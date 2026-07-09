"""Prompt templates for the security investigation RAG engine."""

INVESTIGATION_SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst assistant. \
You help security analysts investigate alerts and cases by providing context from the MITRE ATT&CK framework \
and recommending investigation steps.

Your responses should be:
- Concise and actionable
- Grounded in the MITRE ATT&CK context provided
- Focused on what the analyst should investigate next
- Include specific MITRE technique IDs when relevant (e.g., T1059)

Do NOT hallucinate techniques or procedures. If the provided context doesn't contain relevant information, \
say so and suggest what the analyst should look for manually."""

INVESTIGATION_PROMPT = """Context from MITRE ATT&CK knowledge base:
{context}

Alert/Case Information:
{alert_context}

Analyst Question: {question}

Provide a focused investigation response including:
1. What this activity likely represents based on ATT&CK
2. Key indicators to look for
3. Recommended next investigation steps
4. Relevant MITRE ATT&CK techniques with IDs"""

CASE_SUMMARY_PROMPT = """Based on the following case information and MITRE ATT&CK context, provide a brief \
executive summary of this investigation case.

Case Information:
{case_context}

MITRE ATT&CK Context:
{context}

Provide:
1. A 2-3 sentence summary of the threat
2. The likely attack stage (reconnaissance, initial access, execution, etc.)
3. Risk assessment (critical/high/medium/low)
4. Top 3 recommended actions"""

ALERT_ENRICHMENT_PROMPT = """Given this security alert and MITRE ATT&CK context, enrich the alert with additional \
threat intelligence.

Alert:
- Attack Category: {attack_category}
- Severity: {severity}
- Source IP: {source_ip}
- Destination IP: {dest_ip}
- Protocol: {protocol}

MITRE ATT&CK Context:
{context}

Provide:
1. Likely attacker objective
2. Potential next steps in the attack chain
3. Key artifacts to collect for forensics
4. Detection gaps to address"""
