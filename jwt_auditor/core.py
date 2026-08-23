"""
jwt_auditor/core.py
--------------------
Motor de análisis de JWT Security Auditor.

Contiene toda la lógica de detección, independiente de la CLI, para poder
importarla también desde los tests automatizados.

Comprobaciones implementadas:
  1. Algoritmo `none` aceptado por el servidor (si se indica --target)
  2. Secreto HMAC débil / de diccionario (fuerza bruta offline sobre el
     propio token, sin tocar ningún servidor)
  3. Confusión de algoritmo RS256 -> HS256 (aviso si el token usa RS256,
     ya que puede ser vulnerable si el servidor reutiliza la clave pública
     como secreto HMAC)
  4. Validación de claims: exp ausente o ya caducado, iat en el futuro,
     ausencia de iss/aud
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------
# Utilidades de codificación
# ---------------------------------------------------------------------
def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------
# Estructuras de resultado
# ---------------------------------------------------------------------
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    check: str
    severity: str  # info | low | medium | high | critical
    passed: bool  # True = no hay problema, False = vulnerabilidad detectada
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "severity": self.severity,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass
class AuditReport:
    token: str
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    @property
    def highest_severity(self) -> str:
        vulnerable = [f for f in self.findings if not f.passed]
        if not vulnerable:
            return "info"
        return max(vulnerable, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if not f.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "header": self.header,
            "payload": self.payload,
            "highest_severity": self.highest_severity,
            "vulnerable_findings": self.vulnerable_count,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------
# Decodificación (sin verificar firma; solo lectura estructural)
# ---------------------------------------------------------------------
def decode_token(token: str) -> tuple[dict, dict, str]:
    """Devuelve (header, payload, signature_b64). Lanza ValueError si el
    formato del token no es válido."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("El token no tiene el formato header.payload[.signature]")

    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    signature = parts[2] if len(parts) > 2 else ""
    return header, payload, signature


# ---------------------------------------------------------------------
# Comprobación 1: alg=none contra un servidor real (opcional)
# ---------------------------------------------------------------------
def _try_alg_none_request(payload: dict, target_url: str) -> tuple[int | None, str]:
    import urllib.request
    import urllib.error

    forged_header = {"alg": "none", "typ": "JWT"}
    forged_token = f"{b64url_encode(json.dumps(forged_header).encode())}." \
                   f"{b64url_encode(json.dumps(payload).encode())}."

    req = urllib.request.Request(
        target_url,
        headers={"Authorization": f"Bearer {forged_token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, forged_token
    except urllib.error.HTTPError as e:
        return e.code, forged_token
    except Exception:
        return None, forged_token


def check_alg_none_live(payload: dict, target_url: str) -> Finding:
    """Prueba el ataque alg=none dos veces: una con el payload tal cual, y
    otra escalando el claim 'role' a 'admin' (si existe), ya que un
    servidor puede rechazar por falta de permisos y no por rechazar
    alg=none correctamente — que es justo lo que hay que distinguir."""

    attempts: list[dict] = [dict(payload)]
    if "role" in payload and payload.get("role") != "admin":
        escalated = dict(payload)
        escalated["role"] = "admin"
        attempts.append(escalated)

    last_status = None
    for attempt_payload in attempts:
        status, forged_token = _try_alg_none_request(attempt_payload, target_url)
        last_status = status
        if status is None:
            continue
        if status < 400:
            return Finding(
                check="alg_none_live",
                severity="critical",
                passed=False,
                detail=f"El servidor aceptó un token alg=none sin firma (HTTP {status}) "
                       f"con payload {attempt_payload}. Token forjado: {forged_token}",
            )

    if last_status is None:
        return Finding(
            check="alg_none_live",
            severity="info",
            passed=True,
            detail="No se pudo contactar con el servidor objetivo.",
        )
    return Finding(
        check="alg_none_live",
        severity="info",
        passed=True,
        detail=f"El servidor rechazó todos los intentos con alg=none (último HTTP {last_status}).",
    )


# ---------------------------------------------------------------------
# Comprobación 2: fuerza bruta offline del secreto HMAC
# ---------------------------------------------------------------------
DEFAULT_WORDLIST = [
    "secret", "s3cr3t", "password", "123456", "changeme", "jwt_secret",
    "your-256-bit-secret", "supersecret", "admin", "qwerty", "s3cr3t-del-servidor-2026",
]

_ALG_TO_HASH = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def check_weak_secret(token: str, header: dict, wordlist: list[str] | None = None) -> Finding:
    alg = header.get("alg", "")
    if alg not in _ALG_TO_HASH:
        return Finding(
            check="weak_secret",
            severity="info",
            passed=True,
            detail=f"Algoritmo '{alg}' no es HMAC, no aplica fuerza bruta de secreto.",
        )

    wordlist = wordlist or DEFAULT_WORDLIST
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return Finding(
            check="weak_secret",
            severity="info",
            passed=True,
            detail="El token no tiene firma que comprobar.",
        )

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target_sig = parts[2]
    hash_fn = _ALG_TO_HASH[alg]

    for candidate in wordlist:
        computed = hmac.new(candidate.encode(), signing_input, hash_fn).digest()
        computed_b64 = b64url_encode(computed)
        if hmac.compare_digest(computed_b64, target_sig):
            return Finding(
                check="weak_secret",
                severity="critical",
                passed=False,
                detail=f"Secreto HMAC encontrado por diccionario: '{candidate}'",
            )

    return Finding(
        check="weak_secret",
        severity="info",
        passed=True,
        detail=f"Ninguno de los {len(wordlist)} secretos del diccionario coincide con la firma.",
    )


# ---------------------------------------------------------------------
# Comprobación 3: riesgo de confusión de algoritmo (RS256 -> HS256)
# ---------------------------------------------------------------------
def check_algorithm_confusion_risk(header: dict) -> Finding:
    alg = header.get("alg", "")
    if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        return Finding(
            check="algorithm_confusion_risk",
            severity="medium",
            passed=False,
            detail=f"El token usa un algoritmo asimétrico ({alg}). Si el servidor no "
                   f"fuerza explícitamente el algoritmo esperado al verificar, podría "
                   f"ser vulnerable a un ataque de confusión de algoritmo (usar la "
                   f"clave pública como secreto HMAC).",
        )
    return Finding(
        check="algorithm_confusion_risk",
        severity="info",
        passed=True,
        detail=f"Algoritmo '{alg}' no es asimétrico; no aplica este riesgo.",
    )


# ---------------------------------------------------------------------
# Comprobación 4: validación de claims estándar
# ---------------------------------------------------------------------
def check_claims(payload: dict) -> list[Finding]:
    findings: list[Finding] = []
    now = int(time.time())

    if "exp" not in payload:
        findings.append(Finding(
            check="claim_exp_missing",
            severity="high",
            passed=False,
            detail="El token no incluye claim 'exp': no caduca nunca.",
        ))
    else:
        exp = payload["exp"]
        if exp < now:
            findings.append(Finding(
                check="claim_exp_expired",
                severity="low",
                passed=True,
                detail=f"El token ya está caducado (exp={exp}).",
            ))
        else:
            findings.append(Finding(
                check="claim_exp_valid",
                severity="info",
                passed=True,
                detail=f"El token tiene fecha de expiración válida (exp={exp}).",
            ))

    if "iat" in payload and payload["iat"] > now + 60:
        findings.append(Finding(
            check="claim_iat_future",
            severity="medium",
            passed=False,
            detail=f"El claim 'iat' está en el futuro ({payload['iat']}), lo cual es anómalo.",
        ))

    for claim in ("iss", "aud"):
        if claim not in payload:
            findings.append(Finding(
                check=f"claim_{claim}_missing",
                severity="low",
                passed=False,
                detail=f"El token no incluye el claim '{claim}'; el servidor no puede "
                       f"restringir de qué emisor/audiencia acepta tokens.",
            ))

    return findings


# ---------------------------------------------------------------------
# Orquestador principal
# ---------------------------------------------------------------------
def audit_token(token: str, target_url: str | None = None,
                 wordlist: list[str] | None = None) -> AuditReport:
    header, payload, _sig = decode_token(token)
    report = AuditReport(token=token, header=header, payload=payload)

    report.findings.append(check_weak_secret(token, header, wordlist))
    report.findings.append(check_algorithm_confusion_risk(header))
    report.findings.extend(check_claims(payload))

    if target_url:
        report.findings.append(check_alg_none_live(payload, target_url))
    else:
        report.findings.append(Finding(
            check="alg_none_live",
            severity="info",
            passed=True,
            detail="No se especificó --target: comprobación alg=none contra "
                   "servidor real omitida (solo análisis offline del token).",
        ))

    return report
