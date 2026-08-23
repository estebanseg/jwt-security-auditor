#!/usr/bin/env python3
"""
jwt_auditor_cli.py
-------------------
Herramienta de línea de comandos: JWT Security Auditor.

Analiza un JWT en busca de vulnerabilidades comunes (alg=none, secretos
HMAC débiles, riesgo de confusión de algoritmo, claims mal configurados)
y exporta un informe en JSON y/o CSV.

Uso básico:
    python3 jwt_auditor_cli.py --token "eyJhbGciOi..."

Con comprobación en vivo de alg=none contra un servidor:
    python3 jwt_auditor_cli.py --token "eyJhbGciOi..." --target http://localhost:3000/admin

Con diccionario de secretos personalizado:
    python3 jwt_auditor_cli.py --token "eyJhbGciOi..." --wordlist mis_secretos.txt

Exportando resultados:
    python3 jwt_auditor_cli.py --token "..." --json informe.json --csv informe.csv
"""

import argparse
import csv
import json
import sys

from jwt_auditor.core import audit_token, AuditReport


def load_wordlist(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def print_report(report: AuditReport) -> None:
    print("\n=== JWT Security Auditor ===\n")
    print(f"Header:  {json.dumps(report.header, ensure_ascii=False)}")
    print(f"Payload: {json.dumps(report.payload, ensure_ascii=False)}\n")

    print(f"{'CHECK':<28} {'SEVERIDAD':<10} {'RESULTADO':<12} DETALLE")
    print("-" * 100)
    for f in report.findings:
        resultado = "OK" if f.passed else "VULNERABLE"
        print(f"{f.check:<28} {f.severity:<10} {resultado:<12} {f.detail}")

    print("\n" + "-" * 100)
    if report.vulnerable_count == 0:
        print("Resultado global: sin hallazgos de riesgo.")
    else:
        print(
            f"Resultado global: {report.vulnerable_count} hallazgo(s) de riesgo. "
            f"Severidad máxima: {report.highest_severity.upper()}"
        )
    print()


def export_json(report: AuditReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)


def export_csv(report: AuditReport, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["check", "severity", "passed", "detail"])
        for finding in report.findings:
            writer.writerow([finding.check, finding.severity, finding.passed, finding.detail])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="JWT Security Auditor — análisis defensivo de tokens JWT."
    )
    parser.add_argument("--token", required=True, help="JWT a analizar")
    parser.add_argument(
        "--target",
        help="URL de un endpoint protegido para probar en vivo si acepta alg=none "
             "(opcional; si no se indica, solo se hace análisis offline)",
    )
    parser.add_argument("--wordlist", help="Ruta a un diccionario de secretos personalizado")
    parser.add_argument("--json", help="Ruta de salida para el informe en JSON")
    parser.add_argument("--csv", help="Ruta de salida para el informe en CSV")

    args = parser.parse_args()

    wordlist = load_wordlist(args.wordlist) if args.wordlist else None

    try:
        report = audit_token(args.token, target_url=args.target, wordlist=wordlist)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print_report(report)

    if args.json:
        export_json(report, args.json)
        print(f"Informe JSON guardado en: {args.json}")
    if args.csv:
        export_csv(report, args.csv)
        print(f"Informe CSV guardado en: {args.csv}")

    return 1 if report.vulnerable_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
