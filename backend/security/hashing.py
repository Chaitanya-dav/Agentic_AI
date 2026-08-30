import hashlib
from typing import Union, Dict, Any
from backend.security.canonicalization import canonicalize_payload


def calculate_payload_hash(canonical_payload_or_data: Union[str, Dict[str, Any], Any]) -> str:
    """
    Deterministically computes the SHA-256 hexadecimal digest of a canonical payload.
    
    The AI Agent MUST NOT compute or guess this hash on its own; it must invoke
    this deterministic tool function.
    """
    if isinstance(canonical_payload_or_data, str) and "=" in canonical_payload_or_data:
        canonical_str = canonical_payload_or_data
    else:
        canonical_str = canonicalize_payload(canonical_payload_or_data)
        
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def verify_hash(canonical_payload: str, expected_hash: str) -> bool:
    """
    Recomputes the SHA-256 hash of the canonical payload and performs a constant-time comparison.
    """
    computed = calculate_payload_hash(canonical_payload)
    # Using hmac.compare_digest for timing-attack resistance
    import hmac
    return hmac.compare_digest(computed.lower(), expected_hash.lower())
