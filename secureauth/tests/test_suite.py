"""
SecureAuth - Automated Test Suite
Tests real cryptographic functions, policy enforcement, and security controls.
Run with: python tests/test_suite.py
"""

import sys
import os
import time
import json
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Helpers ───────────────────────────────────────────────────────────────────
PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"
WARN = "\033[33m⚠\033[0m"
HEAD = "\033[1;34m"
RST  = "\033[0m"

results = {"pass": 0, "fail": 0, "warn": 0}

def test(name: str, condition: bool, detail: str = ""):
    if condition:
        results["pass"] += 1
        print(f"  {PASS} {name}")
    else:
        results["fail"] += 1
        print(f"  {FAIL} {name}" + (f" — {detail}" if detail else ""))

def section(title: str):
    print(f"\n{HEAD}{'─'*55}{RST}")
    print(f"{HEAD}  {title}{RST}")
    print(f"{HEAD}{'─'*55}{RST}")


# ═══════════════════════════════════════════════════════════════════════════════
section("1. Password Hashing (Argon2id)")
# ═══════════════════════════════════════════════════════════════════════════════
from core.password_manager import hash_password, verify_password, needs_rehash

pwd = "CorrectHorseBatteryStaple99!"
h1  = hash_password(pwd)
h2  = hash_password(pwd)

test("Hash is non-empty string",           isinstance(h1, str) and len(h1) > 50)
test("Two hashes of same password differ", h1 != h2)
test("Hash uses Argon2 identifier",        "$argon2" in h1)
test("Correct password verifies",          verify_password(h1, pwd))
test("Wrong password rejected",            not verify_password(h1, "wrongpassword"))
test("Empty password rejected",            not verify_password(h1, ""))
test("Needs-rehash returns bool",          isinstance(needs_rehash(h1), bool))

# Timing attack test — wrong password must take ≥40ms
t_start = time.monotonic()
verify_password(h1, "wrong")
t_delta = time.monotonic() - t_start
test("Timing-safe: wrong-password path ≥40ms", t_delta >= 0.04,
     f"took {t_delta*1000:.1f}ms")


# ═══════════════════════════════════════════════════════════════════════════════
section("2. Password Policy & Strength Analysis")
# ═══════════════════════════════════════════════════════════════════════════════
from core.password_manager import analyze_password, generate_secure_password, PasswordPolicy

r = analyze_password("abc")
test("Short password fails policy",        not r.passes_policy)
test("Short password has violations",      len(r.violations) > 0)
test("Short password scored ≤30",          r.score <= 30)

r2 = analyze_password("StrongP@ssw0rd#99!")
test("Strong password passes policy",      r2.passes_policy)
test("Strong password scored ≥70",         r2.score >= 70)
test("Entropy computed (>0)",              r2.entropy_bits > 0)

r3 = analyze_password("password123")
test("Common pattern 'password' detected", not r3.passes_policy or len(r3.violations) > 0)

r4 = analyze_password("Alice@Pass1!", username="alice")
test("Username in password flagged",       not r4.passes_policy or
     any("username" in v.lower() for v in r4.violations))

gen = generate_secure_password(20)
rg  = analyze_password(gen)
test("Generated password passes policy",   rg.passes_policy)
test("Generated password is 20 chars",     len(gen) == 20)
test("Generated passwords are unique",
     generate_secure_password(20) != generate_secure_password(20))


# ═══════════════════════════════════════════════════════════════════════════════
section("3. TOTP Multi-Factor Authentication (RFC 6238)")
# ═══════════════════════════════════════════════════════════════════════════════
from core.mfa import (
    generate_totp_setup, verify_totp, get_current_totp,
    generate_backup_codes, hash_backup_code, verify_backup_code,
)

setup = generate_totp_setup("testuser@example.com")
test("TOTP secret generated (base32)",     len(setup.secret) >= 16)
test("Provisioning URI contains secret",   setup.secret in setup.uri)
test("QR code base64 is non-empty",        len(setup.qr_base64) > 100)
test("URI starts with otpauth://",         setup.uri.startswith("otpauth://"))

current = get_current_totp(setup.secret)
test("Current TOTP is 6 digits",           len(current["token"]) == 6)
test("Remaining seconds in [1,30]",        1 <= current["remaining_seconds"] <= 30)
test("Valid TOTP accepted",                verify_totp(setup.secret, current["token"]))
test("Wrong TOTP rejected",                not verify_totp(setup.secret, "000000"))
test("Non-digit TOTP rejected",            not verify_totp(setup.secret, "abcdef"))
test("Short TOTP rejected",                not verify_totp(setup.secret, "12345"))


# ═══════════════════════════════════════════════════════════════════════════════
section("4. Backup Codes")
# ═══════════════════════════════════════════════════════════════════════════════
codes = generate_backup_codes(10)
hashes = [hash_backup_code(c) for c in codes]

test("10 backup codes generated",          len(codes) == 10)
test("Codes are unique",                   len(set(codes)) == 10)
test("Code format XXXXX-XXXXX",            all(len(c) == 11 and c[5] == "-" for c in codes))

ok, matched = verify_backup_code(hashes, codes[0])
test("Valid backup code accepted",         ok and matched is not None)

# Remove used code (simulate single-use)
hashes.remove(matched)
ok2, _ = verify_backup_code(hashes, codes[0])
test("Used backup code rejected (single-use)", not ok2)

ok3, _ = verify_backup_code(hashes, "XXXXX-YYYYY")
test("Invalid backup code rejected",       not ok3)


# ═══════════════════════════════════════════════════════════════════════════════
section("5. JWT Session Tokens")
# ═══════════════════════════════════════════════════════════════════════════════
from core.mfa import issue_tokens, verify_token

tokens = issue_tokens("uid123", "testuser", "ADMIN", mfa_verified=True)
test("Access token is non-empty string",   isinstance(tokens.access_token, str))
test("Refresh token is non-empty string",  isinstance(tokens.refresh_token, str))
test("Tokens are different",               tokens.access_token != tokens.refresh_token)
test("Expires_in is positive int",         tokens.expires_in > 0)

payload = verify_token(tokens.access_token)
test("Access token decodes correctly",     payload["sub"] == "uid123")
test("MFA flag preserved in token",        payload["mfa_verified"] is True)
test("Role preserved in token",            payload["role"] == "ADMIN")

try:
    verify_token(tokens.access_token, "refresh")
    test("Wrong token type rejected",      False, "Should have raised")
except Exception:
    test("Wrong token type rejected",      True)

try:
    verify_token("invalid.token.here")
    test("Tampered token rejected",        False, "Should have raised")
except Exception:
    test("Tampered token rejected",        True)


# ═══════════════════════════════════════════════════════════════════════════════
section("6. Input Validation (Buffer Overflow Protection)")
# ═══════════════════════════════════════════════════════════════════════════════
from core.security import validate_input

test("Normal username accepted",
     validate_input("alice", "username", strict=True).valid)
test("Username with SQL chars rejected",
     not validate_input("alice'; DROP TABLE", "username", strict=True).valid)
test("Oversized username rejected",
     not validate_input("a" * 65, "username").valid)
test("Oversized password rejected",
     not validate_input("p" * 257, "password").valid)
test("Null byte stripped",
     "\x00" not in (validate_input("test\x00user", "generic").sanitized or ""))
test("Control chars stripped",
     "\x01" not in (validate_input("test\x01input", "generic").sanitized or ""))
test("Empty username rejected",
     not validate_input("", "username", strict=True).valid)
test("Valid email accepted",
     validate_input("user@example.com", "email", strict=True).valid)
test("Invalid email rejected",
     not validate_input("notanemail", "email", strict=True).valid)


# ═══════════════════════════════════════════════════════════════════════════════
section("7. RBAC & Privilege Escalation Prevention")
# ═══════════════════════════════════════════════════════════════════════════════
from core.security import check_permission

test("ADMIN can create users",         check_permission("ADMIN", "users:create"))
test("USER cannot create users",       not check_permission("USER", "users:create"))
test("SUPERADMIN can change roles",    check_permission("SUPERADMIN", "users:change_role"))
test("ADMIN cannot change roles",      not check_permission("ADMIN", "users:change_role"))
test("VIEWER can login",               check_permission("VIEWER", "auth:login"))
test("VIEWER cannot read audit",       not check_permission("VIEWER", "audit:read"))
test("ANALYST can read audit",         check_permission("ANALYST", "audit:read"))
test("Unknown role denied",            not check_permission("HACKER", "auth:login"))


# ═══════════════════════════════════════════════════════════════════════════════
section("8. Privilege Escalation Monitoring")
# ═══════════════════════════════════════════════════════════════════════════════
from core.security import privilege_monitor

# Single escalation: allowed
ok = privilege_monitor.record_role_change("u1", "USER", "ANALYST", "admin1")
test("First escalation allowed",       ok)

# Rapid repeated escalations: should trigger alert
privilege_monitor.record_role_change("u1", "ANALYST",   "DEVELOPER", "admin1")
blocked = not privilege_monitor.record_role_change("u1", "DEVELOPER", "ADMIN", "admin1")
test("Rapid escalation pattern detected/blocked", blocked)


# ═══════════════════════════════════════════════════════════════════════════════
section("9. Backdoor / Trapdoor Scanner")
# ═══════════════════════════════════════════════════════════════════════════════
from core.security import scan_for_trapdoors
import tempfile

# Write a test file with known backdoor patterns
with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                  delete=False, dir="/tmp") as f:
    f.write('password = "supersecret123"\n')
    f.write('api_key  = "sk-abcdef123456789"\n')
    f.write('debug    = True\n')
    f.write('# backdoor left here for testing\n')
    fname = f.name

findings = scan_for_trapdoors("/tmp")
matched = [fi for fi in findings if fi.file == fname]

test("Hardcoded password detected",    any("password" in fi.description.lower()
                                           or "hardcoded" in fi.description.lower()
                                           for fi in matched))
test("Debug=True detected",            any("debug" in fi.description.lower()
                                           for fi in matched))
test("All findings have severity",     all(fi.severity in ("CRITICAL","HIGH","MEDIUM","LOW")
                                           for fi in findings))
os.unlink(fname)


# ═══════════════════════════════════════════════════════════════════════════════
section("10. Tamper-Evident Audit Log")
# ═══════════════════════════════════════════════════════════════════════════════
from core.security import AuditLogger, AuditLevel

log = AuditLogger()
log.log(AuditLevel.INFO, "AUTH", "Login", user_id="u1", ip="1.2.3.4")
log.log(AuditLevel.WARN, "MFA",  "Challenge", user_id="u1", ip="1.2.3.4")
log.log(AuditLevel.CRIT, "PRIV", "Escalation attempt")

test("Log has 3 entries",              log.count == 3)
test("Chain verifies (unmodified)",    log.verify_chain())

# Tamper with an entry
log._events[1].message = "TAMPERED"
test("Tampered chain detected",        not log.verify_chain())

# Restore and re-check
log2 = AuditLogger()
for _ in range(5):
    log2.log(AuditLevel.INFO, "AUTH", "Test event")
test("Clean log chain verifies",       log2.verify_chain())


# ═══════════════════════════════════════════════════════════════════════════════
section("11. OS Integration")
# ═══════════════════════════════════════════════════════════════════════════════
from core.os_integration import (
    os_authenticate, check_system_security, get_privilege_info,
    list_system_users, PLATFORM, PAM_AVAILABLE,
)

test("Platform detected",              PLATFORM in ("Linux", "Darwin", "Windows"))

priv = get_privilege_info()
test("Privilege info returns object",  priv is not None)
test("Effective UID is int",           isinstance(priv.effective_uid, int))
test("SUID list is list",              isinstance(priv.suid_files, list))

checks = check_system_security()
test("OS checks return dict",          isinstance(checks, dict))
test("At least one check returned",   len(checks) > 0)

if PLATFORM == "Linux":
    test("ASLR check present",         "aslr" in checks)
    aslr_val = checks.get("aslr", {}).get("value", "0")
    test("ASLR is enabled (value≥1)",  aslr_val in ("1", "2"),
         f"ASLR value={aslr_val}")

# PAM test (graceful degradation)
result = os_authenticate("testuser", "testpass")
test("PAM returns OSAuthResult",       result is not None)
test("PAM method field populated",     bool(result.method))
if not PAM_AVAILABLE:
    test("PAM graceful degradation message", "unavailable" in result.message.lower()
         or "pam" in result.method.lower())


# ═══════════════════════════════════════════════════════════════════════════════
section("12. MFA Rate Limiter")
# ═══════════════════════════════════════════════════════════════════════════════
from core.mfa import MFARateLimit

rl = MFARateLimit()
rl.MAX_ATTEMPTS = 3

for i in range(3):
    rl.record_attempt("user99", "totp", False)

test("Rate limiter locks after max attempts", rl.is_locked("user99", "totp"))

status = rl.get_status("user99", "totp")
test("Status shows locked=True",       status["locked"])
test("Remaining attempts is 0",        status["remaining_attempts"] == 0)

rl2 = MFARateLimit()
rl2.record_attempt("user100", "totp", True)
test("Success clears rate limit",      not rl2.is_locked("user100", "totp"))


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
total = results["pass"] + results["fail"]
pct   = int(results["pass"] / total * 100) if total else 0
print(f"\n{'═'*55}")
print(f"  Results: {results['pass']}/{total} passed  ({pct}%)")
if results["fail"]:
    print(f"  \033[31mFailed:  {results['fail']}\033[0m")
print(f"{'═'*55}\n")

sys.exit(0 if results["fail"] == 0 else 1)
