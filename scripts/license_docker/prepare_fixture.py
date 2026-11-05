#!/usr/bin/env python3
"""Prepare private fixture material and build two explicitly test-only images."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", required=True)
    p.add_argument("--cadence",choices=("slow","fast","both"),default="both")
    p.add_argument("--image-prefix", default="arc-license-fixture")
    p.add_argument("--authority-image", default="arc-license-authority:local")
    p.add_argument("--runtime-image", default="arc-license-tests:dde0bbeb")
    p.add_argument("--extra-tls-ip", action="append", default=[])
    args = p.parse_args()
    root = Path(args.state).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.umask(0o077)
    private = root / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    if not (private / "signing.pem").exists():
        command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private / "signing.pem"))
        command("openssl", "pkey", "-in", str(private / "signing.pem"), "-pubout", "-out", str(private / "public.pem"))
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
                "-subj", "/CN=enterprise.basekick.net", "-addext", "subjectAltName=DNS:enterprise.basekick.net,IP:127.0.0.1",
                "-keyout", str(private / "tls.key"), "-out", str(private / "tls.crt"))
    token = private / "control.token"
    if args.extra_tls_ip:
        # Host access to an internal Docker network uses its container IP;
        # retain certificate verification instead of disabling hostname checks.
        import ipaddress
        addresses = [str(ipaddress.ip_address(value)) for value in args.extra_tls_ip]
        command("openssl", "req", "-x509", "-new", "-key", str(private / "tls.key"), "-days", "3",
                "-subj", "/CN=enterprise.basekick.net", "-addext",
                "subjectAltName=DNS:enterprise.basekick.net,IP:127.0.0.1,"+','.join('IP:'+value for value in addresses),
                "-out", str(private / "tls.crt"))
    if not token.exists():
        token.write_text(secrets.token_hex(32))
    (private / "server.env").write_text("FIXTURE_CONTROL_TOKEN="+token.read_text()+"\n")
    context = root / "image-context"
    context.mkdir(mode=0o700, exist_ok=True)
    public = (private / "public.pem").read_text()
    pub_source = (ROOT / "internal/license/pubkey.go").read_text()
    pub_source = re.sub(r"const enterprisePublicKeyPEM = `[^`]+`", lambda _: "const enterprisePublicKeyPEM = `"+public+"`", pub_source)
    (context / "pubkey.go").write_text(pub_source)
    client = (ROOT / "internal/license/client.go").read_text()
    fast = client.replace("ValidationInterval = 4 * time.Hour", "ValidationInterval = 2 * time.Second")
    if fast == client:
        raise RuntimeError("validation cadence constant changed; review fixture overlay")
    (context / "client.go").write_text(fast)
    # Copy only tracked build inputs from this checkout. Never send private
    # fixture state, real keys or local credentials to the Docker build context.
    source = context / "source"
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(mode=0o700)
    for raw_path in subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split('\0'):
        if not raw_path or not (raw_path.startswith(('cmd/', 'internal/', 'scripts/license_docker/iceberg_audit/')) or raw_path in ('go.mod', 'go.sum')):
            continue
        src = ROOT / raw_path
        if src.is_file():
            dst = source / raw_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
    for name, extra in [("slow", {}), ("fast", {"/build/internal/license/client.go": "/overlay/client.go"})]:
        overlay = {"Replace": {"/build/internal/license/pubkey.go": "/overlay/pubkey.go", **extra}}
        (context / (name+".json")).write_text(json.dumps(overlay))
    (context / "Dockerfile").write_text('''ARG RUNTIME_IMAGE=arc-license-tests:dde0bbeb
FROM arc-license-builder:dde0bbeb AS build
ARG CADENCE=slow
RUN rm -rf /build/internal /build/cmd
COPY source/ /build/
COPY pubkey.go client.go slow.json fast.json /overlay/
RUN go build -overlay=/overlay/${CADENCE}.json -tags=duckdb_arrow -ldflags="-X main.Version=license-authority-fixture" -o /build/arc-fixture ./cmd/arc
RUN go build -o /build/iceberg-audit ./scripts/license_docker/iceberg_audit
FROM ${RUNTIME_IMAGE}
COPY --from=build --chown=arc:arc /build/arc-fixture /app/arc
COPY --from=build --chown=arc:arc /build/iceberg-audit /app/iceberg-audit
LABEL arc.license-test-only="true"
''')
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    (root / "build-provenance.json").write_text(json.dumps({"revision": revision,
        "source_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)).hexdigest(),
        "runtime_image": args.runtime_image, "test_trust_root": True}, indent=2))
    server = root / "server-context"
    server.mkdir(mode=0o700, exist_ok=True)
    shutil.copyfile(ROOT / "scripts/license_docker/fixture_server.py", server / "fixture_server.py")
    (server / "Dockerfile").write_text('''FROM python:3.13-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY --chmod=0444 fixture_server.py /fixture_server.py
ENTRYPOINT ["python3", "/fixture_server.py"]
''')
    for cadence in (("slow","fast") if args.cadence=="both" else (args.cadence,)):
        subprocess.run(["docker", "build", "--progress=plain", "--build-arg", "CADENCE="+cadence,
                        "--build-arg", "RUNTIME_IMAGE="+args.runtime_image,
                        "-t", args.image_prefix+":"+cadence, str(context)], check=True)
    subprocess.run(["docker", "build", "--progress=plain", "-t", args.authority_image, str(server)], check=True)
    print("Prepared fixture images; private signing material remains outside all build contexts.")


if __name__ == "__main__":
    main()
