import hmac
import hashlib
import json
import base64
import datetime
from typing import Dict, Any, Tuple, Optional
from backend.config import settings


def generate_signature(payload_dict: Dict[str, Any], secret_key: str = settings.SECRET_KEY) -> str:
    """Computes HMAC-SHA256 signature over sorted JSON payload."""
    serialized = json.dumps(payload_dict, sort_keys=True)
    return hmac.new(secret_key.encode("utf-8"), serialized.encode("utf-8"), hashlib.sha256).hexdigest()


def create_approval_token(
    approval_id: str,
    payload_hash: str,
    creator_id: str,
    approver_id: str,
    expires_at: datetime.datetime,
    secret_key: str = settings.SECRET_KEY,
) -> str:
    """
    Generates a tamper-evident, cryptographically signed approval token string.
    
    Contains BOTH approval_id and payload_hash along with expiry and participants.
    """
    token_data = {
        "approval_id": approval_id,
        "payload_hash": payload_hash,
        "creator_id": creator_id.lower().strip(),
        "approver_id": approver_id.lower().strip(),
        "expires_at": expires_at.isoformat(),
    }
    
    signature = generate_signature(token_data, secret_key)
    full_token = {
        **token_data,
        "signature": signature,
    }
    
    json_bytes = json.dumps(full_token, sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(json_bytes).decode("utf-8")


def decode_and_verify_token(
    token_str: str, secret_key: str = settings.SECRET_KEY
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Decodes an approval token and verifies its cryptographic signature.
    Returns (is_valid, token_data_dict, error_message).
    """
    try:
        raw_json = base64.urlsafe_b64decode(token_str.encode("utf-8")).decode("utf-8")
        data = json.loads(raw_json)
    except Exception as e:
        return False, None, f"Invalid token format or encoding: {str(e)}"
        
    signature = data.pop("signature", None)
    if not signature:
        return False, None, "Token missing cryptographic signature"
        
    expected_signature = generate_signature(data, secret_key)
    if not hmac.compare_digest(signature, expected_signature):
        return False, None, "Token signature verification failed: token has been tampered with"
        
    # Put signature back for inspection
    data["signature"] = signature
    return True, data, "Token signature is cryptographically valid"
