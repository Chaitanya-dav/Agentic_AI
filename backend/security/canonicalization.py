from typing import Dict, Any, Union


def canonicalize_payload(data: Union[Dict[str, Any], Any]) -> str:
    """
    Transforms action fields into a deterministic, canonical string representation.
    
    Rules:
    1. Key fields: action_type, amount, currency, recipient, creator, description
    2. Normalize:
       - action_type: uppercase trimmed string (e.g. PAYMENT)
       - amount: formatted to 2 decimal places (e.g. 50000.00)
       - currency: uppercase trimmed string (e.g. INR)
       - recipient: uppercase trimmed string (e.g. RAVI)
       - creator: lowercase trimmed string (e.g. alice)
       - description: trimmed string
    3. Keys are sorted alphabetically to guarantee strict byte-level reproducibility.
    4. Delimiter is '|' and key-value separator is '='.
    
    Example output:
    action_type=PAYMENT|amount=50000.00|creator=alice|currency=INR|description=Invoice 104|recipient=RAVI
    """
    if hasattr(data, "__dict__"):
        raw_dict = {
            "action_type": getattr(data, "action_type", "PAYMENT"),
            "amount": getattr(data, "amount", 0.0),
            "currency": getattr(data, "currency", "INR"),
            "recipient": getattr(data, "recipient", ""),
            "creator": getattr(data, "creator", ""),
            "description": getattr(data, "description", "") or "",
        }
    elif isinstance(data, dict):
        raw_dict = {
            "action_type": data.get("action_type", "PAYMENT"),
            "amount": data.get("amount", 0.0),
            "currency": data.get("currency", "INR"),
            "recipient": data.get("recipient", ""),
            "creator": data.get("creator", ""),
            "description": data.get("description", "") or "",
        }
    else:
        raise ValueError(f"Unsupported payload data type: {type(data)}")

    # Normalized fields
    action_type = str(raw_dict.get("action_type", "PAYMENT")).strip().upper()
    try:
        amount_val = float(raw_dict.get("amount", 0.0))
        amount_str = f"{amount_val:.2f}"
    except (ValueError, TypeError):
        amount_str = "0.00"
        
    currency = str(raw_dict.get("currency", "INR")).strip().upper()
    recipient = str(raw_dict.get("recipient", "")).strip().upper()
    creator = str(raw_dict.get("creator", "")).strip().lower()
    description = str(raw_dict.get("description", "") or "").strip()

    normalized_map = {
        "action_type": action_type,
        "amount": amount_str,
        "creator": creator,
        "currency": currency,
        "description": description,
        "recipient": recipient,
    }

    # Deterministic alphabetical sorting of keys
    canonical_parts = [f"{k}={normalized_map[k]}" for k in sorted(normalized_map.keys())]
    return "|".join(canonical_parts)
