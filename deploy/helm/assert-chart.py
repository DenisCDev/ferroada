"""Fail-closed snapshot for the Helm chart (PR 21). Needs helm on PATH."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy" / "helm" / "ferroada"
PORT_9000 = re.compile(r"\b9000\b")
HELM_TIMEOUT_SECS = 60


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def helm_bin() -> str:
    found = shutil.which("helm")
    if found:
        return found
    temp = Path(os.environ.get("TEMP", os.environ.get("TMP", "/tmp")))
    extras = [
        temp / "helm-bin" / "windows-amd64" / "helm.exe",
        Path.home() / "bin" / "helm",
        Path("/usr/local/bin/helm"),
    ]
    for path in extras:
        if path.is_file():
            return str(path)
    fail("helm não está no PATH (preciso de helm lint / helm template)")


def run_helm(helm: str, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [helm, *args],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=HELM_TIMEOUT_SECS,
        )
    except subprocess.TimeoutExpired:
        fail(f"helm {' '.join(args)} excedeu {HELM_TIMEOUT_SECS}s")
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        fail(f"helm {' '.join(args)} falhou:\n{detail}")
    return result


def documents(rendered: str) -> list[tuple[str, str]]:
    docs: list[tuple[str, str]] = []
    for raw in re.split(r"\n---\s*\n", "\n" + rendered):
        body = raw.strip()
        if not body or body == "---":
            continue
        kind = ""
        for line in body.splitlines():
            if line.startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                break
        docs.append((kind, body))
    return docs


def check_default(rendered: str, errors: list[str]) -> None:
    docs = documents(rendered)
    kinds = [kind for kind, _ in docs]
    if "Ingress" in kinds:
        errors.append("values default emitiu Ingress (ingress.enabled deve ser false)")
    if "PodDisruptionBudget" not in kinds:
        errors.append("values default não emitiu PodDisruptionBudget")
    if "NetworkPolicy" not in kinds:
        errors.append("values default não emitiu NetworkPolicy")

    for kind, body in docs:
        if kind in {"Service", "Ingress"} and PORT_9000.search(body):
            errors.append(f"{kind}: contém 9000 (dashboard não é público)")

        if kind == "Service":
            if re.search(r"port:\s*9000\b", body):
                errors.append("Service publica a porta 9000")
            if not re.search(r"port:\s*3000\b", body):
                errors.append("Service default não publica a porta 3000")

        if kind == "NetworkPolicy":
            if PORT_9000.search(body):
                errors.append("NetworkPolicy menciona 9000 (não listar; omitir a porta)")
            if not re.search(r"port:\s*3000\b", body):
                errors.append("NetworkPolicy default não admite só a porta 3000")

        if kind == "Deployment":
            if "runAsNonRoot: true" not in body:
                errors.append("Deployment sem securityContext.runAsNonRoot: true")
            if "readOnlyRootFilesystem: true" not in body:
                errors.append("Deployment sem readOnlyRootFilesystem: true")
            if not re.search(r"drop:\s*\n\s*- ALL", body):
                errors.append("Deployment sem capabilities.drop ALL")
            if "RuntimeDefault" not in body:
                errors.append("Deployment sem seccomp RuntimeDefault")
            if "curl" in body:
                errors.append("Deployment menciona curl (distroless não tem curl)")
            if "httpGet:" in body:
                errors.append("Deployment usa httpGet na probe (deve ser ferroada healthcheck)")
            if "/ferroada" not in body or "healthcheck" not in body:
                errors.append("liveness/readiness não apontam /ferroada healthcheck")
            if not re.search(
                r'name:\s*DASHBOARD_BIND\s*\n\s*value:\s*"127\.0\.0\.1"',
                body,
            ):
                errors.append("DASHBOARD_BIND default não é 127.0.0.1")
            if not re.search(r'name:\s*WAF_ENGINE\s*\n\s*value:\s*"native"', body):
                errors.append("WAF_ENGINE default não é native")
            if not re.search(
                r'name:\s*TARGET_URL\s*\n\s*value:\s*"http://substitua-origin\.invalid:8080"',
                body,
            ):
                errors.append("TARGET_URL default não é o placeholder .invalid")
            if "OTEL_EXPORTER_OTLP_ENDPOINT" in body or "FERROADA_OTLP_ENDPOINT" in body:
                errors.append("values default ligou OTel (endpoint tem de nascer vazio)")


def check_ingress(rendered: str, errors: list[str]) -> None:
    docs = documents(rendered)
    ingress = [body for kind, body in docs if kind == "Ingress"]
    if not ingress:
        errors.append("ingress.enabled=true não emitiu Ingress")
        return
    for body in ingress:
        if PORT_9000.search(body):
            errors.append("Ingress habilitado contém 9000")
        if not re.search(r"number:\s*3000\b", body):
            errors.append("Ingress habilitado não aponta a porta 3000 do Service")


def main() -> None:
    if not (CHART / "Chart.yaml").is_file():
        fail(f"chart em falta: {CHART}")
    helm = helm_bin()
    errors: list[str] = []

    lint = run_helm(helm, ["lint", str(CHART)], check=False)
    if lint.returncode != 0:
        errors.append(f"helm lint falhou:\n{(lint.stderr or lint.stdout).strip()}")
    elif "ERROR" in (lint.stdout + lint.stderr):
        errors.append(f"helm lint reportou ERROR:\n{lint.stdout.strip()}")

    default = run_helm(helm, ["template", "ferroada", str(CHART)])
    check_default(default.stdout, errors)

    empty = run_helm(
        helm,
        ["template", "ferroada", str(CHART), "--set", "ferroada.dashboardToken="],
        check=False,
    )
    if empty.returncode == 0:
        errors.append("helm template com token vazio deveria falhar (token obrigatório)")

    collide = run_helm(
        helm,
        ["template", "ferroada", str(CHART), "--set", "service.port=9000"],
        check=False,
    )
    if collide.returncode == 0:
        errors.append("helm template com service.port=9000 deveria falhar (dashboard não é Service)")

    remap = run_helm(
        helm,
        [
            "template",
            "ferroada",
            str(CHART),
            "--set",
            "service.port=9000",
            "--set",
            "ferroada.dashboardPort=9001",
        ],
        check=False,
    )
    if remap.returncode == 0:
        errors.append("service.port=9000 tem de falhar mesmo com dashboardPort noutro sítio")

    bind = run_helm(
        helm,
        [
            "template",
            "ferroada",
            str(CHART),
            "--set",
            "ferroada.dashboardBind=0.0.0.0",
        ],
        check=False,
    )
    if bind.returncode == 0:
        errors.append("dashboardBind=0.0.0.0 deveria falhar (só loopback)")

    ingress = run_helm(
        helm,
        [
            "template",
            "ferroada",
            str(CHART),
            "--set",
            "ingress.enabled=true",
            "--set",
            "ingress.hosts[0].host=api.exemplo.com",
            "--set",
            "ingress.hosts[0].paths[0].path=/",
            "--set",
            "ingress.hosts[0].paths[0].pathType=Prefix",
        ],
    )
    check_ingress(ingress.stdout, errors)

    if errors:
        fail("chart Helm não está fail-closed:\n- " + "\n- ".join(errors))
    print("chart Helm fail-closed: ok")


if __name__ == "__main__":
    main()
