"""Ingest MITRE ATT&CK data into a FAISS vector store.

Fetches technique descriptions from the MITRE ATT&CK STIX data,
chunks them, embeds them, and stores them in a local FAISS index.

Usage:
    python -m rag.ingest
"""

import os
import sys
import json
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
VECTORSTORE_DIR = os.path.join(os.path.dirname(__file__), "..", "vectorstore")

# MITRE ATT&CK STIX data (enterprise techniques)
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def download_attack_data() -> dict:
    """Download MITRE ATT&CK STIX bundle."""
    cache_path = os.path.join(DATA_DIR, "enterprise-attack.json")

    if os.path.exists(cache_path):
        print("Loading cached ATT&CK data...")
        with open(cache_path, "r") as f:
            return json.load(f)

    print("Downloading MITRE ATT&CK Enterprise data (~30MB)...")
    resp = requests.get(ATTACK_STIX_URL, timeout=300)
    resp.raise_for_status()
    data = resp.json()

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(cache_path, "w") as f:
        json.dump(data, f)
    print(f"Cached to {cache_path}")
    return data


def parse_techniques(stix_bundle: dict) -> list[dict]:
    """Extract technique info from the STIX bundle.

    Returns list of dicts with: id, name, description, tactic, url, mitigations
    """
    techniques = []
    objects = stix_bundle.get("objects", [])

    # Build ID -> object lookup
    id_lookup = {obj["id"]: obj for obj in objects}

    # Extract attack patterns (techniques)
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Get technique ID (e.g., T1059)
        external_refs = obj.get("external_references", [])
        technique_id = None
        url = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        # Get tactics (kill chain phases)
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        name = obj.get("name", "")
        description = obj.get("description", "")

        # Get platforms
        platforms = obj.get("x_mitre_platforms", [])

        # Get detection info
        detection = ""
        for ref in obj.get("x_mitre_data_sources", []):
            detection += f"- {ref}\n"

        techniques.append({
            "id": technique_id,
            "name": name,
            "description": description,
            "tactics": tactics,
            "platforms": platforms,
            "detection_sources": detection,
            "url": url or f"https://attack.mitre.org/techniques/{technique_id}/",
        })

    print(f"Extracted {len(techniques)} techniques from ATT&CK data.")
    return techniques


def build_documents(techniques: list[dict]) -> list[str]:
    """Build text documents from techniques for embedding.

    Each technique becomes one document with all its metadata.
    """
    documents = []
    metadatas = []

    for tech in techniques:
        # Build a rich text document for each technique
        text = f"""MITRE ATT&CK Technique: {tech['id']} - {tech['name']}

Tactics: {', '.join(tech['tactics'])}
Platforms: {', '.join(tech['platforms'])}

Description:
{tech['description']}

Data Sources for Detection:
{tech['detection_sources'] if tech['detection_sources'] else 'Not specified'}

Reference: {tech['url']}"""

        documents.append(text)
        metadatas.append({
            "technique_id": tech["id"],
            "name": tech["name"],
            "tactics": ", ".join(tech["tactics"]),
            "url": tech["url"],
        })

    return documents, metadatas


def create_vectorstore(documents: list[str], metadatas: list[dict]):
    """Create FAISS vector store from documents.

    Supports OpenAI or Google embeddings based on .env config.
    """
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

    provider = os.getenv("LLM_PROVIDER", "openai")

    if provider == "google":
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        embeddings = GoogleGenerativeAIEmbeddings(
            model="models/gemini-embedding-001",
            google_api_key=os.getenv("GOOGLE_API_KEY"),
        )
    else:
        from langchain_openai import OpenAIEmbeddings
        embeddings = OpenAIEmbeddings(
            model="text-embedding-3-small",
            openai_api_key=os.getenv("OPENAI_API_KEY"),
        )

    print(f"Creating embeddings with {provider} provider...")
    print(f"Embedding {len(documents)} technique documents...")

    from langchain_community.vectorstores import FAISS
    from langchain.text_splitter import RecursiveCharacterTextSplitter

    # Split longer documents into chunks
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=1500,
        chunk_overlap=200,
        separators=["\n\n", "\n", ". ", " "],
    )

    from langchain.schema import Document
    docs = []
    for text, meta in zip(documents, metadatas):
        chunks = splitter.split_text(text)
        for chunk in chunks:
            docs.append(Document(page_content=chunk, metadata=meta))

    print(f"Split into {len(docs)} chunks. Building FAISS index...")

    vectorstore = FAISS.from_documents(docs, embeddings)

    os.makedirs(VECTORSTORE_DIR, exist_ok=True)
    vectorstore.save_local(VECTORSTORE_DIR)
    print(f"Vector store saved to {VECTORSTORE_DIR}/")

    return vectorstore


def save_techniques_json(techniques: list[dict]):
    """Save techniques as JSON for the API to serve."""
    output_path = os.path.join(DATA_DIR, "mitre_techniques.json")
    with open(output_path, "w") as f:
        json.dump(techniques, f, indent=2)
    print(f"Techniques JSON saved to {output_path}")


def main():
    print("=" * 60)
    print("MITRE ATT&CK Knowledge Base Ingestion")
    print("=" * 60)

    # Step 1: Download STIX data
    print("\n[1/4] Downloading MITRE ATT&CK data...")
    stix_data = download_attack_data()

    # Step 2: Parse techniques
    print("\n[2/4] Parsing techniques...")
    techniques = parse_techniques(stix_data)

    # Step 3: Save JSON for API
    print("\n[3/4] Saving techniques JSON...")
    save_techniques_json(techniques)

    # Step 4: Build vector store
    print("\n[4/4] Building FAISS vector store...")
    try:
        documents, metadatas = build_documents(techniques)
        create_vectorstore(documents, metadatas)
    except Exception as e:
        print(f"\nVector store creation failed: {e}")
        print("This usually means your API key isn't configured.")
        print("1. Copy .env.example to .env")
        print("2. Add your OpenAI or Google API key")
        print("3. Re-run: python -m rag.ingest")
        return

    print("\n" + "=" * 60)
    print("Ingestion complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
