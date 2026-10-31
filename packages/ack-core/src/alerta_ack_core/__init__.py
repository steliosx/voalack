"""Provider-neutral primitives for signed Alerta acknowledgement intents.

No Alerta, PostgreSQL, HTTP or provider runtime imports; no credential loading,
threads or database objects.
"""
from .canonical import CanonicalError, canonical_json, strict_loads
from .outcomes import Outcome
from .profiles import INTENT_V2, ZABALACK_V1, KeyUnavailable, Profile, ProofError, mac_hex, verify_mac
from .validate import FieldError, bounded_text, canonical_uuid, parse_utc, utc_timestamp

__version__ = "0.1.0.dev0"
__all__ = ["CanonicalError", "FieldError", "INTENT_V2", "KeyUnavailable", "Outcome", "Profile", "ProofError",
           "ZABALACK_V1", "bounded_text", "canonical_json", "canonical_uuid", "mac_hex", "parse_utc",
           "strict_loads", "utc_timestamp", "verify_mac"]
