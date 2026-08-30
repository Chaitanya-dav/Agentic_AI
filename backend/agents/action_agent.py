import re
import json
from typing import Dict, Any, Tuple
from backend.config import settings
from backend.security.canonicalization import canonicalize_payload
from backend.security.hashing import calculate_payload_hash


def _mock_llm_parse_action(prompt: str, default_creator: str = "alice") -> Dict[str, Any]:
    """
    Deterministic AI Extraction fallback for offline/zero-config operation.
    Parses natural language requests into structured action dictionaries.
    """
    cleaned = prompt.strip()
    
    # 1. Extract amount and currency
    # Matches patterns like ₹50,000, Rs. 50000, 50,000 INR, $1,000 USD, 500 EUR, 50000
    amount = 10000.0
    currency = "INR"
    
    # Currency symbols / codes
    if "₹" in cleaned or "rs" in cleaned.lower() or "inr" in cleaned.lower():
        currency = "INR"
    elif "$" in cleaned or "usd" in cleaned.lower():
        currency = "USD"
    elif "€" in cleaned or "eur" in cleaned.lower():
        currency = "EUR"
    elif "£" in cleaned or "gbp" in cleaned.lower():
        currency = "GBP"

    # Extract numerical amount
    amt_match = re.search(r'(?:[₹$€£]|Rs\.?|INR|USD|EUR)?\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]+)?|[0-9]+(?:\.[0-9]+)?)', cleaned, re.IGNORECASE)
    if amt_match:
        raw_amt_str = amt_match.group(1).replace(",", "")
        try:
            val = float(raw_amt_str)
            if val > 0:
                amount = val
        except ValueError:
            pass

    # 2. Extract recipient
    # Matches "to <Recipient>", "for <Recipient>", "transfer to <Recipient>"
    recipient = "RAVI"
    to_match = re.search(r'\b(?:to|transfer to|pay|send to)\s+([A-Za-z0-9_\-\.]+)', cleaned, re.IGNORECASE)
    if to_match:
        candidate = to_match.group(1).strip().upper()
        # Filter out common stop-words if captured
        if candidate not in ("THE", "A", "AN", "ACCOUNTS", "ACCOUNT"):
            recipient = candidate

    # 3. Extract action type
    action_type = "PAYMENT"
    if any(k in cleaned.lower() for k in ["transfer", "wire"]):
        action_type = "TRANSFER"
    elif any(k in cleaned.lower() for k in ["grant", "access", "permission"]):
        action_type = "ACCESS_GRANT"
    elif any(k in cleaned.lower() for k in ["config", "parameter", "update setting"]):
        action_type = "CONFIG_CHANGE"

    # 4. Extract creator
    creator = default_creator
    creator_match = re.search(r'\b(?:by|from|creator:?)\s+([A-Za-z0-9_\-\.]+)', cleaned, re.IGNORECASE)
    if creator_match:
        creator = creator_match.group(1).strip().lower()

    # 5. Extract description
    description = cleaned
    for_match = re.search(r'\b(?:for|reason:?)\s+(.+)$', cleaned, re.IGNORECASE)
    if for_match:
        description = for_match.group(1).strip()

    return {
        "action_type": action_type,
        "amount": amount,
        "currency": currency,
        "recipient": recipient,
        "creator": creator,
        "description": description,
    }


def _openai_parse_action(prompt: str, default_creator: str = "alice") -> Dict[str, Any]:
    """
    Parses natural language using OpenAI LangChain ChatOpenAI.
    """
    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import SystemMessage, HumanMessage

        llm = ChatOpenAI(
            model=settings.LLM_MODEL,
            openai_api_key=settings.OPENAI_API_KEY,
            temperature=0.0,
        )

        system_prompt = (
            "You are the Action Analysis Agent in a Secure Execution System.\n"
            "Extract structured fields from the user prompt into valid JSON with keys:\n"
            "- action_type (PAYMENT, TRANSFER, ACCESS_GRANT, CONFIG_CHANGE)\n"
            "- amount (float number, default 0.0)\n"
            "- currency (INR, USD, EUR, etc., default INR)\n"
            "- recipient (uppercase entity or username name, e.g. RAVI)\n"
            "- creator (lowercase username, e.g. alice)\n"
            "- description (short context summary)\n"
            "Do NOT calculate or guess SHA-256 hashes. Respond with ONLY the raw JSON object."
        )

        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Prompt: {prompt}\nDefault Creator: {default_creator}")
        ])

        content = response.content.strip()
        if content.startswith("```json"):
            content = content.replace("```json", "").replace("```", "").strip()
        elif content.startswith("```"):
            content = content.replace("```", "").strip()

        parsed = json.loads(content)
        return {
            "action_type": parsed.get("action_type", "PAYMENT").upper(),
            "amount": float(parsed.get("amount", 0.0)),
            "currency": parsed.get("currency", "INR").upper(),
            "recipient": parsed.get("recipient", "UNKNOWN").upper(),
            "creator": parsed.get("creator", default_creator).lower(),
            "description": parsed.get("description", prompt),
        }
    except Exception:
        # Graceful fallback to deterministic mock parser if OpenAI fails or is unconfigured
        return _mock_llm_parse_action(prompt, default_creator)


def assess_action_risk(amount: float, action_type: str, recipient: str) -> Tuple[str, str]:
    """
    Evaluates action risk score and provides human-readable policy justification.
    """
    if amount >= settings.HIGH_RISK_THRESHOLD:
        return "HIGH", f"Amount ₹{amount:,.2f} exceeds high-risk threshold (₹{settings.HIGH_RISK_THRESHOLD:,.2f}). Requires Manager Four-Eyes approval."
    elif amount >= settings.AUTO_APPROVE_THRESHOLD:
        return "MEDIUM", f"Amount ₹{amount:,.2f} requires mandatory dual-authorization checkpointing."
    elif action_type in ("CONFIG_CHANGE", "ACCESS_GRANT"):
        return "HIGH", f"Privileged action type '{action_type}' mandates security orchestrator approval."
    else:
        return "LOW", f"Standard low-value transaction within operational baseline."


class ActionAnalysisAgent:
    """
    1. ACTION ANALYSIS AGENT
    - Accepts natural language action requests or structured parameters.
    - Extracts structured fields (action_type, amount, currency, recipient, creator, description).
    - Normalizes / canonicalizes the action using deterministic canonicalizer.
    - Calculates SHA-256 payload hash through the deterministic hashing tool.
    - Estimates risk and explains why approval is required.
    """

    def process(self, prompt: str, creator: str = "alice") -> Dict[str, Any]:
        # 1. Parse natural language into structured data
        if settings.USE_MOCK_LLM or not settings.OPENAI_API_KEY:
            extracted = _mock_llm_parse_action(prompt, creator)
        else:
            extracted = _openai_parse_action(prompt, creator)

        # 2. Canonicalize via deterministic tool
        canonical_payload = canonicalize_payload(extracted)

        # 3. Calculate SHA-256 payload hash via deterministic tool
        payload_hash = calculate_payload_hash(canonical_payload)

        # 4. Assess risk and explain necessity of approval
        risk_level, risk_explanation = assess_action_risk(
            extracted["amount"], extracted["action_type"], extracted["recipient"]
        )

        return {
            "structured_action": extracted,
            "canonical_payload": canonical_payload,
            "payload_hash": payload_hash,
            "risk_level": risk_level,
            "risk_explanation": risk_explanation,
            "agent_summary": (
                f"Action Analysis Agent parsed action '{extracted['action_type']}' for {extracted['currency']} "
                f"{extracted['amount']:,.2f} to {extracted['recipient']}. "
                f"Canonicalized payload and computed SHA-256 hash [{payload_hash[:16]}...]. Risk: {risk_level}."
            ),
        }
