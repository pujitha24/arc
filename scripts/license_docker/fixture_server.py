#!/usr/bin/env python3
"""Local synthetic license authority; never receives the user's real keys.

This server and the fixture trust-root overlay exist only for controlled
Docker tests. They are not substitutes for real-license issuance evidence.
"""
import base64
import collections
import datetime as dt
import http.server
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse

LOCK = threading.Lock()
STATE = {"mode": "valid", "activation_mode": "valid", "tier": "enterprise",
         "successful_verdict_total": 0,
         "activation_epochs": {},
         "request_totals": {},
         "max_cores": 32, "max_machines": 10,
         "expires_at": (dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=3)).isoformat(),
         "issued_at": dt.datetime.now(dt.timezone.utc).isoformat(),
         "features": ["rbac", "audit_logging", "clustering", "tiering", "writer_failover",
                      "query_governance", "query_management", "shared_storage_multi_writer"]}
EVENTS = collections.deque(maxlen=10000)
SEQUENCES = {}
PROOFS = {}

# Retained test authorities may be refreshed without rewinding their virtual
# clock. Docker uses this host's monotonic clock; retain time_origin unchanged.
if os.environ.get("FIXTURE_INITIAL_STATE"):
    initial = json.loads(Path(os.environ["FIXTURE_INITIAL_STATE"]).read_text())
    if any(not key.startswith("LOCAL-FIXTURE-") for key in initial.get("profiles", {})):
        raise ValueError("initial state contains a non-synthetic profile")
    STATE.update(initial)


def effective_time(cfg):
    if cfg.get("server_time"):
        return dt.datetime.fromisoformat(cfg["server_time"].replace("Z", "+00:00"))+dt.timedelta(seconds=time.monotonic()-cfg["time_origin"])
    return dt.datetime.now(dt.timezone.utc)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if path == "/control":
            if self.headers.get("Authorization") != "Bearer "+os.environ["FIXTURE_CONTROL_TOKEN"]:
                return self.reply(403, {"error": "control authentication required"})
            with LOCK:
                STATE.update(body)
                if "server_time" in body:
                    STATE["time_origin"] = time.monotonic()
                if body.get("reset_events"):
                    EVENTS.clear()
                    SEQUENCES.clear()
                    PROOFS.clear()
            return self.reply(200, {"ok": True})
        if path == "/api/v1/activate":
            return self.license_response(body, activate=True)
        return self.reply(404, {"error": "unknown fixture route"})

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/stats":
            if self.headers.get("Authorization") != "Bearer "+os.environ["FIXTURE_CONTROL_TOKEN"]:
                return self.reply(403, {"error": "control authentication required"})
            with LOCK:
                return self.reply(200, {"events": list(EVENTS), "state": dict(STATE),
                                        "effective_server_time": effective_time(STATE).isoformat(),
                                        "successful_verdict_total": STATE["successful_verdict_total"],
                                        "event_history_limit": EVENTS.maxlen})
        if parsed.path == "/api/v1/verify":
            body = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
            return self.license_response(body, activate=False)
        return self.reply(404, {"error": "unknown fixture route"})

    def license_response(self, request, activate):
        key, fingerprint = request.get("license_key", ""), request.get("machine_fingerprint", "")
        # Keep the local trust-root fixture isolated from real customer secrets.
        if not key.startswith("LOCAL-FIXTURE-"):
            return self.reply(400, {"error": "fixture accepts synthetic keys only"})
        with LOCK:
            cfg = dict(STATE)
            if cfg.get("strict_profiles") and key not in cfg.get("profiles", {}):
                return self.reply(400, {"error": "unknown synthetic profile"})
            # Test-only per-key capabilities let the two paid installations
            # share one authority clock without sharing their entitlements.
            cfg.update(cfg.get("profiles", {}).get(key, {}))
            totals = STATE["request_totals"].setdefault(key, {}).setdefault(fingerprint, {"verify": 0, "activate": 0})
            totals["activate" if activate else "verify"] += 1
            identity = (key, fingerprint, activate)
            sequence = SEQUENCES.get(identity, 0)+1
            SEQUENCES[identity] = sequence
            mode = cfg["activation_mode"] if activate else cfg["mode"]
            epoch = int(cfg.get("reactivation_epoch", 0))
            activated = STATE["activation_epochs"].get(key, {}).get(fingerprint, 0)
            if not activate and mode == "valid" and activated < epoch:
                mode = cfg.get("reactivation_reason", "missing_activation")
            if cfg.get("success_limit") and sequence > cfg["success_limit"]:
                mode = "503"
            event = {"time": time.time(), "activate": activate, "sequence": sequence,
                     "fingerprint": fingerprint, "profile": cfg.get("profile_id"),
                     "license_key_sha256": hashlib.sha256(key.encode()).hexdigest(),
                     "protocol": request.get("license_protocol"),
                     "test_phase": cfg.get("test_phase"), "reactivation_epoch": epoch,
                     "effective_server_time": effective_time(cfg).isoformat(),
                     "mode": mode, "successful_verdict": False}
            EVENTS.append(event)
        if mode == "drop":
            self.connection.close()
            return
        if mode in ("503", "429"):
            return self.reply(int(mode), {"error": "temporary fixture fault"})
        if mode == "html404":
            return self.reply(404, b"<html>proxy default</html>")
        if mode == "malformed":
            return self.reply(200, {})
        if mode == "null":
            return self.reply(200, b"null")
        errors = {"expired": "license has expired", "suspended": "license is suspended",
                  "notfound": "license not found", "revoked": "license is not active",
                  "missing_activation": "machine not activated for this license",
                  "revoked_activation": "activation has been revoked"}
        verdict = "success" if activate else "valid"
        if mode in errors:
            with LOCK:
                event["rejection_reason"] = errors[mode]
            return self.reply(200, {verdict: False, "error": errors[mode]})
        server_time = effective_time(cfg)
        with LOCK:
            event["effective_server_time"] = server_time.isoformat()
        if cfg.get("enforce_expiry"):
            term = dt.datetime.fromisoformat(cfg["term_ends_at"].replace("Z", "+00:00"))
            cutoff = term if cfg["license_kind"] == "trial" else term.astimezone(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)+dt.timedelta(days=15)
            if server_time >= cutoff:
                with LOCK:
                    event["rejection_reason"] = "license has expired"
                return self.reply(200, {verdict: False, "error": "license has expired"})
        payload = {"version": 1, "license_key": key, "tier": cfg["tier"],
                   "customer_id": "local-fixture", "customer_name": "Local fixture",
                   "features": cfg["features"], "max_cores": cfg["max_cores"],
                   "max_machines": cfg["max_machines"], "machine_fingerprint": fingerprint,
                   "issued_at": cfg["issued_at"], "expires_at": cfg["expires_at"]}
        if str(request.get("license_protocol", "0")) == "2":
            term = dt.datetime.fromisoformat(cfg.get("term_ends_at", cfg["expires_at"]).replace("Z", "+00:00"))
            trial = cfg.get("license_kind", "paid") == "trial"
            cutoff = term if trial else term.astimezone(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)+dt.timedelta(days=15)
            payload["expires_at"] = cutoff.isoformat()
            payload["expiry_policy"] = {"version": 1, "kind": "trial" if trial else "paid",
                                        "term_ends_at": term.isoformat(), "grace_days": 0 if trial else 14}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", "/fixture/signing.pem"],
                                input=raw, capture_output=True, check=True)
        signature = result.stdout
        if mode == "bad_signature":
            signature = b"x"*len(signature)
        with LOCK:
            event["successful_verdict"] = mode != "bad_signature"
            if event["successful_verdict"]:
                STATE["successful_verdict_total"] += 1
            event["signed_expires_at"] = payload["expires_at"]
        response = {verdict: True, "license_file": base64.b64encode(raw).decode(),
                    "license_signature": base64.b64encode(signature).decode()}
        if request.get("time_nonce") and mode != "omit_time":
            proof = {"version": 1, "purpose": "arc-license-time", "nonce": request["time_nonce"],
                     "license_key_sha256": hashlib.sha256(key.encode()).hexdigest(),
                     "machine_fingerprint": fingerprint, "license_sha256": hashlib.sha256(raw).hexdigest(),
                     "server_time": server_time.isoformat()}
            proof_raw = json.dumps(proof, separators=(",", ":")).encode()
            proof_sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", "/fixture/signing.pem"],
                                       input=proof_raw, capture_output=True, check=True).stdout
            if mode == "bad_time_signature":
                proof_sig = b"x"*len(proof_sig)
            pair = {"time_file": base64.b64encode(proof_raw).decode(), "time_signature": base64.b64encode(proof_sig).decode()}
            with LOCK:
                if mode == "replay_time" and identity in PROOFS:
                    pair = PROOFS[identity]
                else:
                    PROOFS[identity] = pair
            response.update(pair)
        if activate and mode == "valid" and epoch:
            with LOCK:
                current = {**STATE, **STATE.get("profiles", {}).get(key, {})}
                # A request admitted before a control change must not consume
                # a newer activation epoch or undo a concurrent suspension.
                consumed = (current.get("reactivation_epoch", 0) == epoch and
                            current.get("test_phase") == cfg.get("test_phase") and
                            current.get("mode") == "valid" and current.get("activation_mode") == "valid")
                if consumed:
                    STATE["activation_epochs"].setdefault(key, {})[fingerprint] = epoch
                event["activation_epoch_consumed"] = consumed
        return self.reply(200, response)


server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/fixture/tls.crt", "/fixture/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
