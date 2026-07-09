"""RAG-powered investigation engine for security alert analysis.

Uses LangChain with FAISS vector store over MITRE ATT&CK data
to provide context-aware investigation assistance.
"""

import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

VECTORSTORE_DIR = os.path.join(os.path.dirname(__file__), "..", "vectorstore")


class InvestigationEngine:
    """RAG-powered security investigation assistant."""

    def __init__(self):
        self.vectorstore = None
        self.chain = None
        self._initialized = False
        self._init_error = None
        self._try_initialize()

    def _try_initialize(self):
        """Try to load the vector store and build the QA chain."""
        try:
            provider = os.getenv("LLM_PROVIDER", "openai")

            # Load embeddings
            if provider == "google":
                from langchain_google_genai import GoogleGenerativeAIEmbeddings, ChatGoogleGenerativeAI
                embeddings = GoogleGenerativeAIEmbeddings(
                    model="models/gemini-embedding-001",
                    google_api_key=os.getenv("GOOGLE_API_KEY"),
                )
                llm = ChatGoogleGenerativeAI(
                    model="gemini-2.5-flash",
                    google_api_key=os.getenv("GOOGLE_API_KEY"),
                    temperature=0.1,
                )
            else:
                from langchain_openai import OpenAIEmbeddings, ChatOpenAI
                embeddings = OpenAIEmbeddings(
                    model="text-embedding-3-small",
                    openai_api_key=os.getenv("OPENAI_API_KEY"),
                )
                llm = ChatOpenAI(
                    model="gpt-4o-mini",
                    openai_api_key=os.getenv("OPENAI_API_KEY"),
                    temperature=0.1,
                )

            # Load vector store
            if not os.path.exists(VECTORSTORE_DIR):
                self._init_error = "Vector store not found. Run `python -m rag.ingest` first."
                print(f"Warning: {self._init_error}")
                return

            from langchain_community.vectorstores import FAISS
            self.vectorstore = FAISS.load_local(
                VECTORSTORE_DIR, embeddings,
                allow_dangerous_deserialization=True,
            )

            # Build the retrieval chain
            from langchain.chains import RetrievalQA
            from langchain.prompts import PromptTemplate
            from rag.prompts import INVESTIGATION_SYSTEM_PROMPT, INVESTIGATION_PROMPT

            prompt = PromptTemplate(
                template=INVESTIGATION_PROMPT,
                input_variables=["context", "alert_context", "question"],
            )

            self.retriever = self.vectorstore.as_retriever(
                search_type="similarity",
                search_kwargs={"k": 5},
            )

            self.llm = llm
            self._initialized = True
            print("Investigation engine initialized successfully.")

        except Exception as e:
            self._init_error = str(e)
            print(f"Warning: Investigation engine init failed: {e}")

    def investigate(self, question: str, alert_context: str = "") -> dict:
        """Run an investigation query.

        Args:
            question: Analyst's question
            alert_context: Optional alert/case context to include

        Returns:
            Dict with answer, sources, and suggested actions
        """
        if not self._initialized:
            return self._fallback_response(question, alert_context)

        try:
            # Retrieve relevant ATT&CK documents
            docs = self.retriever.invoke(question)

            # Build context from retrieved docs
            context = "\n\n---\n\n".join([
                doc.page_content for doc in docs
            ])

            # Build the prompt
            from rag.prompts import INVESTIGATION_SYSTEM_PROMPT, INVESTIGATION_PROMPT
            from langchain.schema import HumanMessage, SystemMessage

            messages = [
                SystemMessage(content=INVESTIGATION_SYSTEM_PROMPT),
                HumanMessage(content=INVESTIGATION_PROMPT.format(
                    context=context,
                    alert_context=alert_context or "No specific alert context provided.",
                    question=question,
                )),
            ]

            # Get response
            response = self.llm.invoke(messages)
            answer = response.content

            # Extract source technique references
            sources = []
            seen_ids = set()
            for doc in docs:
                tech_id = doc.metadata.get("technique_id", "")
                if tech_id and tech_id not in seen_ids:
                    seen_ids.add(tech_id)
                    sources.append({
                        "technique_id": tech_id,
                        "name": doc.metadata.get("name", ""),
                        "tactics": doc.metadata.get("tactics", ""),
                        "url": doc.metadata.get("url", ""),
                    })

            return {
                "answer": answer,
                "sources": sources,
                "mitre_techniques": sources,
                "suggested_actions": self._extract_actions(answer),
            }

        except Exception as e:
            return {
                "answer": f"Investigation engine error: {str(e)}",
                "sources": [],
                "mitre_techniques": [],
                "suggested_actions": ["Check API key configuration", "Verify vector store exists"],
            }

    def _fallback_response(self, question: str, alert_context: str) -> dict:
        """Provide a useful response when the RAG engine isn't initialized."""
        from utils.mitre_mapper import ATTACK_TO_MITRE, MITIGATIONS

        # Try to extract attack category from context
        attack_cat = None
        for cat in ATTACK_TO_MITRE.keys():
            if cat.lower() in (alert_context or "").lower() or cat.lower() in question.lower():
                attack_cat = cat
                break

        if attack_cat:
            techniques = ATTACK_TO_MITRE.get(attack_cat, [])
            mitigations = MITIGATIONS.get(attack_cat, [])

            answer = f"Based on the {attack_cat} classification, here are the relevant MITRE ATT&CK techniques:\n\n"
            for t in techniques:
                answer += f"- **{t['id']}** ({t['name']}): Tactic - {t['tactic']}\n"
            answer += f"\nRecommended actions:\n"
            for m in mitigations:
                answer += f"- {m}\n"

            if self._init_error:
                answer += f"\n\n*Note: RAG engine not available ({self._init_error}). Using static mappings.*"

            return {
                "answer": answer,
                "sources": [{"technique_id": t["id"], "name": t["name"], "tactics": t["tactic"], "url": ""} for t in techniques],
                "mitre_techniques": techniques,
                "suggested_actions": mitigations,
            }

        return {
            "answer": f"I can help investigate security alerts. {self._init_error or 'Please provide alert context for more specific guidance.'}",
            "sources": [],
            "mitre_techniques": [],
            "suggested_actions": [
                "Provide the alert's attack category for specific MITRE ATT&CK mappings",
                "Run `python -m rag.ingest` to enable full RAG investigation",
            ],
        }

    @staticmethod
    def _extract_actions(answer: str) -> list[str]:
        """Extract action items from the LLM's response."""
        actions = []
        lines = answer.split("\n")
        for line in lines:
            stripped = line.strip()
            # Look for numbered or bulleted action items
            if stripped and (
                stripped[0].isdigit()
                or stripped.startswith("- ")
                or stripped.startswith("* ")
                or stripped.lower().startswith("action")
                or stripped.lower().startswith("recommend")
                or stripped.lower().startswith("investigate")
                or stripped.lower().startswith("check")
                or stripped.lower().startswith("review")
                or stripped.lower().startswith("block")
                or stripped.lower().startswith("isolate")
            ):
                # Clean up the line
                clean = stripped.lstrip("0123456789.-*) ").strip()
                if clean and len(clean) > 10:
                    actions.append(clean)

        return actions[:5]  # Return top 5 actions
