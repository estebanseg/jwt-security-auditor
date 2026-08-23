"""
tests/test_auditor.py
-----------------------
Suite de pruebas automatizadas para JWT Security Auditor.

Ejecutar con:
    python3 -m unittest discover -s tests -v
"""

import hashlib
import hmac
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jwt_auditor.core import (
    audit_token,
    b64url_encode,
    check_algorithm_confusion_risk,
    check_claims,
    check_weak_secret,
    decode_token,
)


def make_token(header: dict, payload: dict, secret: str | None = None) -> str:
    """Construye un JWT válido (o sin firma si secret es None) para tests."""
    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    if secret is None or header.get("alg") == "none":
        return f"{header_b64}.{payload_b64}."

    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[header["alg"]]
    sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


class TestDecodeToken(unittest.TestCase):
    def test_decode_valid_token(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "role": "user"}, "s3cr3t")
        header, payload, sig = decode_token(token)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(payload["sub"], "alice")
        self.assertTrue(sig)

    def test_decode_malformed_token_raises(self):
        with self.assertRaises(ValueError):
            decode_token("no-es-un-jwt")

    def test_decode_alg_none_token_empty_signature(self):
        token = make_token({"alg": "none", "typ": "JWT"}, {"sub": "alice", "role": "admin"})
        header, payload, sig = decode_token(token)
        self.assertEqual(header["alg"], "none")
        self.assertEqual(sig, "")


class TestWeakSecret(unittest.TestCase):
    def test_detects_secret_in_wordlist(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"}, "secret")
        header, _, _ = decode_token(token)
        finding = check_weak_secret(token, header, wordlist=["secret", "otra_cosa"])
        self.assertFalse(finding.passed)
        self.assertEqual(finding.severity, "critical")
        self.assertIn("secret", finding.detail)

    def test_strong_secret_not_in_wordlist(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"}, "una-clave-muy-larga-y-aleatoria-9f8a7b")
        header, _, _ = decode_token(token)
        finding = check_weak_secret(token, header, wordlist=["secret", "123456"])
        self.assertTrue(finding.passed)

    def test_non_hmac_algorithm_skips_check(self):
        token = make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "alice"})
        header, _, _ = decode_token(token)
        finding = check_weak_secret(token, header)
        self.assertTrue(finding.passed)
        self.assertIn("no es HMAC", finding.detail)


class TestAlgorithmConfusionRisk(unittest.TestCase):
    def test_flags_rs256_as_risk(self):
        finding = check_algorithm_confusion_risk({"alg": "RS256"})
        self.assertFalse(finding.passed)
        self.assertEqual(finding.severity, "medium")

    def test_hs256_no_risk_flagged(self):
        finding = check_algorithm_confusion_risk({"alg": "HS256"})
        self.assertTrue(finding.passed)


class TestClaims(unittest.TestCase):
    def test_missing_exp_flagged_high(self):
        findings = check_claims({"sub": "alice"})
        exp_finding = next(f for f in findings if f.check == "claim_exp_missing")
        self.assertFalse(exp_finding.passed)
        self.assertEqual(exp_finding.severity, "high")

    def test_valid_future_exp_passes(self):
        findings = check_claims({"exp": int(time.time()) + 3600, "iss": "x", "aud": "y"})
        exp_finding = next(f for f in findings if f.check == "claim_exp_valid")
        self.assertTrue(exp_finding.passed)

    def test_missing_iss_and_aud_flagged(self):
        findings = check_claims({"exp": int(time.time()) + 3600})
        checks = {f.check: f for f in findings}
        self.assertFalse(checks["claim_iss_missing"].passed)
        self.assertFalse(checks["claim_aud_missing"].passed)

    def test_iat_in_future_flagged(self):
        findings = check_claims({"exp": int(time.time()) + 3600, "iat": int(time.time()) + 9999})
        iat_finding = next(f for f in findings if f.check == "claim_iat_future")
        self.assertFalse(iat_finding.passed)


class TestAuditTokenOrchestration(unittest.TestCase):
    def test_full_audit_offline_detects_weak_secret_and_missing_claims(self):
        token = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "role": "user"}, "secret")
        report = audit_token(token, wordlist=["secret"])
        self.assertGreaterEqual(report.vulnerable_count, 1)
        self.assertIn(report.highest_severity, ("high", "critical"))

    def test_full_audit_secure_token_has_no_critical_findings(self):
        strong_secret = "clave-robusta-generada-aleatoriamente-abc123xyz"
        payload = {
            "sub": "alice",
            "role": "user",
            "exp": int(time.time()) + 900,
            "iat": int(time.time()),
            "iss": "jwt-auditor-lab",
            "aud": "jwt-auditor-clients",
        }
        token = make_token({"alg": "HS256", "typ": "JWT"}, payload, strong_secret)
        report = audit_token(token, wordlist=["secret", "123456"])
        self.assertNotEqual(report.highest_severity, "critical")


if __name__ == "__main__":
    unittest.main()
