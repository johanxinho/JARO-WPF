"""JARO WPF - Security, Secret Redaction, Host-Key Verification & Privilege Policy Module (Phase 5)."""
from core.security.secret_guard import (
    PrivilegePolicyError,
    PrivilegePolicyGate,
    SecretSecurityError,
    audit_json_no_plaintext_secrets,
    audit_sensitive_file,
    compute_ssh_pubkey_fingerprint,
    inspect_ssh_identity_file,
    protect_sensitive_file,
    redact_secrets,
    verify_known_hosts_entry,
)

__all__ = [
    "PrivilegePolicyError",
    "PrivilegePolicyGate",
    "SecretSecurityError",
    "audit_json_no_plaintext_secrets",
    "audit_sensitive_file",
    "compute_ssh_pubkey_fingerprint",
    "inspect_ssh_identity_file",
    "protect_sensitive_file",
    "redact_secrets",
    "verify_known_hosts_entry",
]
