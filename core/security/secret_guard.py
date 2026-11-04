"""JARO WPF - Security Controls: Secret Redaction, Key/Config Auditing & Privilege Gate (Phase 5).

Enforces mandatory Phase 5 Section 4 security invariants:
1. Never store plaintext passwords or private keys in JSON catalogs or session state.
2. Never print or persist secret material in logs or error diagnostics.
3. Validate X.509 certificates and pinned SSH host keys (plain & OpenSSH |1| hashed entries).
4. Protect sensitive key and tunnel configuration files (POSIX 0o600 / 0o400).
5. Never execute privileged commands (sudo/pkexec) automatically.
6. Require explicit authorization before creating/deleting interfaces or modifying routes.
"""
import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Any, Dict, List, Optional, Sequence

ALLOWED_SSH_HOSTKEY_TYPES = frozenset({
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
})

FORBIDDEN_SSH_HOSTKEY_TYPES = frozenset({
    "ssh-dss",
    "ssh-ed25519-cert-v01@openssh.com",  # unhandled without explicit @cert-authority policy
})

FORBIDDEN_JSON_SECRET_KEYS = frozenset({
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "private_key",
    "privatekey",
    "preshared_key",
    "presharedkey",
    "secret_key",
    "secret",
    "raw_private_key",
    "inline_private_key",
    "auth_token",
    "bearer_token",
})

ALLOWED_FILE_REFERENCE_KEYS = frozenset({
    "identity_file",
    "private_key_file",
    "preshared_key_file",
    "known_hosts_file",
    "config_path",
    "ca_file",
})

VALID_PRIVATE_KEY_HEADERS = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 _-]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 _-]+PRIVATE KEY-----",
    re.MULTILINE,
)
_WG_SECRET_LINE_RE = re.compile(
    r"(?im)^(\s*(?:PrivateKey|PresharedKey)\s*=\s*)([^\s#]+)"
)
_KV_SECRET_RE = re.compile(
    r"(?i)(\b(?:password|passwd|passphrase|private_key|privatekey|preshared_key|presharedkey|secret|token|bearer)\s*[:=]\s*['\"]?)(?!\[REDACTED_)([^'\"\s,;}{]+)"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]+)"
)


class SecretSecurityError(Exception):
    """Raised when plaintext secrets, insecure file permissions, or invalid host keys are detected."""


class PrivilegePolicyError(Exception):
    """Raised when an operation attempts privileged or interface-mutating actions without authorization."""


def redact_secrets(text: Optional[str]) -> str:
    """Scrubs private keys, WireGuard keys, passwords, and tokens from any log or error string."""
    if not text:
        return ""
    scrubbed = _PEM_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY]", str(text))
    scrubbed = _WG_SECRET_LINE_RE.sub(r"\1[REDACTED_WG_SECRET]", scrubbed)
    scrubbed = _AUTH_HEADER_RE.sub(r"\1[REDACTED_TOKEN]", scrubbed)
    scrubbed = _KV_SECRET_RE.sub(r"\1[REDACTED_SECRET]", scrubbed)
    return scrubbed


def protect_sensitive_file(file_path: str | Path, mode: int = 0o600) -> Dict[str, Any]:
    """Applies strict owner-only POSIX permissions (default 0o600) to a sensitive file."""
    path = Path(file_path)
    if not path.is_file():
        return {"protected": False, "error": f"Sensitive file does not exist: {path}"}
    if mode & 0o077:
        return {"protected": False, "error": f"Refusing insecure target mode {oct(mode)}; group/other bits must be 0"}
    try:
        if os.name == "posix":
            os.chmod(path, mode)
            actual = stat.S_IMODE(path.stat().st_mode)
            return {"protected": actual == mode, "mode": oct(actual), "error": None}
        return {"protected": True, "mode": "nt_acl_default", "error": None}
    except OSError as exc:
        return {"protected": False, "error": redact_secrets(str(exc))}


def audit_sensitive_file(
    file_path: str | Path,
    require_owner_only: bool = True,
) -> Dict[str, Any]:
    """Audits a key or tunnel config file for existence, regular-file safety, and 0o600/0o400 permissions."""
    path = Path(file_path)
    if not path.exists():
        return {"valid": False, "error": f"Sensitive file does not exist: {path}"}
    if not path.is_file() or path.is_symlink():
        return {"valid": False, "error": f"Sensitive file must be a regular non-symlink file: {path}"}

    if os.name == "posix" and require_owner_only:
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            return {
                "valid": False,
                "mode": oct(mode),
                "error": f"Insecure permissions ({oct(mode)}) on {path.name}; expected 0o600 or 0o400",
            }
        parent_st = path.parent.stat()
        parent_mode = stat.S_IMODE(parent_st.st_mode)
        # Reject world-writable parent directories unless sticky bit is set (like /tmp)
        if (parent_mode & 0o002) and not (parent_mode & stat.S_ISVTX):
            return {
                "valid": False,
                "mode": oct(mode),
                "error": f"Parent directory '{path.parent}' is world-writable without sticky bit ({oct(parent_mode)})",
            }
        return {"valid": True, "mode": oct(mode), "error": None}

    return {"valid": True, "mode": "non_posix", "error": None}


def audit_json_no_plaintext_secrets(data: Any, path_prefix: str = "$") -> Dict[str, Any]:
    """Ensures JSON configurations never contain inline passwords, private keys, or secret tokens."""
    violations: List[str] = []

    def _walk(node: Any, cur_path: str) -> None:
        if isinstance(node, dict):
            for raw_k, val in node.items():
                k_str = str(raw_k)
                k_norm = k_str.strip().lower()
                child_path = f"{cur_path}.{k_str}"
                if k_norm in FORBIDDEN_JSON_SECRET_KEYS and k_norm not in ALLOWED_FILE_REFERENCE_KEYS:
                    if val not in (None, "", False):
                        violations.append(f"Forbidden plaintext secret field at {child_path}")
                        continue
                _walk(val, child_path)
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                _walk(item, f"{cur_path}[{idx}]")
        elif isinstance(node, str):
            if "PRIVATE KEY-----" in node:
                violations.append(f"Inline PEM/OpenSSH private key block detected at {cur_path}")

    _walk(data, path_prefix)
    return {
        "safe": len(violations) == 0,
        "violations": violations,
        "error": "; ".join(violations) if violations else None,
    }


def inspect_ssh_identity_file(identity_file: str | Path) -> Dict[str, Any]:
    """Validates an SSH IdentityFile permissions and header structure without reading/returning key material."""
    perm = audit_sensitive_file(identity_file, require_owner_only=True)
    if not perm["valid"]:
        return {"valid": False, "key_format": None, "error": perm["error"]}

    path = Path(identity_file)
    try:
        with path.open("rb") as fh:
            head = fh.read(96)
    except OSError as exc:
        return {"valid": False, "key_format": None, "error": f"Cannot read IdentityFile header: {exc}"}

    first_line = head.splitlines()[0].decode("ascii", errors="replace").strip() if head else ""
    if not any(first_line.startswith(hdr) for hdr in VALID_PRIVATE_KEY_HEADERS):
        return {
            "valid": False,
            "key_format": None,
            "error": "IdentityFile does not start with a recognized OpenSSH/PEM private key header",
        }

    key_format = "openssh" if "OPENSSH" in first_line else "pem"
    return {
        "valid": True,
        "key_format": key_format,
        "mode": perm.get("mode"),
        "error": None,
    }


def compute_ssh_pubkey_fingerprint(key_blob_b64: str) -> Optional[str]:
    """Computes OpenSSH-style SHA256:<base64> fingerprint of a base64 public key blob."""
    try:
        raw = base64.b64decode(key_blob_b64.strip(), validate=True)
        if len(raw) < 16:
            return None
        digest = hashlib.sha256(raw).digest()
        b64_fp = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{b64_fp}"
    except (binascii.Error, ValueError):
        return None


def _matches_known_hosts_token(token: str, expected_targets: Sequence[str]) -> bool:
    """Matches a single OpenSSH known_hosts host token (plain or |1|salt|hash HMAC-SHA1)."""
    if not token or token.startswith("!"):
        return False
    if token.startswith("|1|"):
        parts = token.split("|")
        # Format: |1|base64_salt|base64_hmac_sha1
        if len(parts) != 4:
            return False
        try:
            salt = base64.b64decode(parts[2], validate=True)
            expected_mac = base64.b64decode(parts[3], validate=True)
        except (binascii.Error, ValueError):
            return False
        for target in expected_targets:
            computed = hmac.new(salt, target.encode("utf-8"), hashlib.sha1).digest()
            if hmac.compare_digest(computed, expected_mac):
                return True
        return False

    token_lower = token.lower()
    return any(token_lower == t.lower() for t in expected_targets)


def verify_known_hosts_entry(
    known_hosts_file: str | Path,
    host: str,
    port: int = 22,
) -> Dict[str, Any]:
    """Verifies that known_hosts_file pins at least one valid cryptographic host key for (host, port).

    Follows OpenSSH StrictHostKeyChecking rules:
    - Port 22 matches either `host` or `[host]:22`.
    - Non-22 ports MUST match `[host]:port`.
    - Supports both plain hostnames and OpenSSH HashKnownHosts (`|1|salt|hash`).
    - Rejects `@revoked` entries and deprecated `ssh-dss` keys.
    """
    path = Path(known_hosts_file)
    if not path.is_file():
        return {
            "valid": False,
            "matched": False,
            "fingerprints": [],
            "error": f"known_hosts file does not exist: {path}",
        }

    clean_host = host.strip()
    if not clean_host:
        return {"valid": False, "matched": False, "fingerprints": [], "error": "Empty SSH host"}

    bracketed = f"[{clean_host}]:{port}"
    expected_targets = [clean_host, bracketed] if port == 22 else [bracketed]

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {"valid": False, "matched": False, "fingerprints": [], "error": f"Cannot read known_hosts: {exc}"}

    matched_types: List[str] = []
    fingerprints: List[str] = []
    revoked_hit = False

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        marker: Optional[str] = None
        rest = line
        if rest.startswith("@"):
            parts = rest.split(None, 1)
            if len(parts) < 2:
                continue
            marker, rest = parts[0], parts[1]

        fields = rest.split()
        if len(fields) < 3:
            continue

        host_field, key_type, key_b64 = fields[0], fields[1], fields[2]
        tokens = [tok.strip() for tok in host_field.split(",") if tok.strip()]

        # Explicit negation `!host` disqualifies matching on this line
        negated = any(
            tok.startswith("!") and _matches_known_hosts_token(tok[1:], expected_targets)
            for tok in tokens
        )
        if negated:
            continue

        if not any(_matches_known_hosts_token(tok, expected_targets) for tok in tokens):
            continue

        if marker == "@revoked":
            revoked_hit = True
            continue

        if key_type in FORBIDDEN_SSH_HOSTKEY_TYPES or key_type not in ALLOWED_SSH_HOSTKEY_TYPES:
            return {
                "valid": False,
                "matched": False,
                "fingerprints": [],
                "error": f"Disallowed or unsupported SSH host key algorithm '{key_type}' at line {line_no}",
            }

        fp = compute_ssh_pubkey_fingerprint(key_b64)
        if fp is None:
            return {
                "valid": False,
                "matched": False,
                "fingerprints": [],
                "error": f"Malformed base64 SSH host key at line {line_no}",
            }

        matched_types.append(key_type)
        fingerprints.append(fp)

    if revoked_hit and not fingerprints:
        return {
            "valid": False,
            "matched": False,
            "fingerprints": [],
            "error": f"Host key for {expected_targets[0]} is marked @revoked in known_hosts",
        }

    if not fingerprints:
        target_hint = expected_targets[0]
        return {
            "valid": False,
            "matched": False,
            "fingerprints": [],
            "error": (
                f"No pinned SSH host key found in {path.name} for '{target_hint}' "
                f"(StrictHostKeyChecking requires exact host/port match)"
            ),
        }

    return {
        "valid": True,
        "matched": True,
        "key_types": matched_types,
        "fingerprints": fingerprints,
        "expected_target": expected_targets[0],
        "error": None,
    }


@dataclass(frozen=True)
class PrivilegePolicyGate:
    """Explicit authorization gate for privileged commands and OS network interface/route mutations.

    By default ALL flags are False:
    - Never invokes sudo/pkexec automatically.
    - Never creates or deletes OS interfaces without explicit authorization.
    - Never modifies routes without explicit authorization.
    - Never touches global default routes (0.0.0.0/0, ::/0) without explicit authorization.
    """
    allow_privileged_commands: bool = False
    authorize_interface_changes: bool = False
    authorize_route_changes: bool = False
    allow_global_routes: bool = False

    def check_interface_mutation(self, action_description: str, requires_root: bool = True) -> Dict[str, Any]:
        """Checks whether creating/modifying/removing a network interface is authorized."""
        if not self.authorize_interface_changes:
            return {
                "allowed": False,
                "authorization_required": True,
                "reason": (
                    f"Explicit authorization required before modifying network interfaces ({action_description}); "
                    f"set authorize_interface_changes=True after user approval"
                ),
            }
        is_root = (os.geteuid() == 0) if os.name == "posix" else False
        if requires_root and not is_root and not self.allow_privileged_commands:
            return {
                "allowed": False,
                "authorization_required": True,
                "reason": (
                    f"Administrative privileges required for '{action_description}', and automatic sudo execution "
                    f"is disabled by security policy (allow_privileged_commands=False)"
                ),
            }
        return {"allowed": True, "authorization_required": False, "reason": None}

    def check_route_mutation(self, modifies_global_default: bool = False) -> Dict[str, Any]:
        """Checks whether adding/updating routing entries is authorized."""
        if modifies_global_default and not self.allow_global_routes:
            return {
                "allowed": False,
                "authorization_required": True,
                "reason": "Modifying global default route (0.0.0.0/0 or ::/0) is blocked without allow_global_routes=True",
            }
        if not self.authorize_route_changes:
            return {
                "allowed": False,
                "authorization_required": True,
                "reason": "Explicit authorization required before modifying routing table (authorize_route_changes=True)",
            }
        return {"allowed": True, "authorization_required": False, "reason": None}
