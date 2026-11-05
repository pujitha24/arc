#!/usr/bin/env python3
"""Opt-in Docker license behavior checks. Never writes production source.

Real keys stay in private env files outside the checkout. Stable hostnames,
MAC addresses and CPU visibility preserve activation identity across reruns.
Reports contain redacted HTTP observations, not license/cache/database bytes.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
UTC = dt.timezone.utc


class Suite:
    def __init__(self, args):
        self.args = args
        self.harness_revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        self.state = Path(args.state).resolve()
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        self.redactions = []
        self.results = []
        self.nodes = {}
        self.installations = []
        self.run_id = args.run_id
        self.label = "arc-license-tests=" + self.run_id
        self.current = None
        self.case_id = secrets.token_hex(4)
        if (self.state / "nodes.private.json").exists():
            self.nodes = json.loads((self.state / "nodes.private.json").read_text())
            for info in self.nodes.values():
                self.secret(info["token"])

    def secret(self, value):
        if value and value not in self.redactions:
            self.redactions.append(value)
        return value

    def redact(self, value):
        if isinstance(value, dict):
            return {k: self.redact(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact(v) for v in value]
        if isinstance(value, str):
            for secret in sorted(self.redactions, key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
            # Arc logs key prefixes; redact those even when the full key is absent.
            return re.sub(r"ARC-(?:ENT-)?[A-Za-z0-9-]{4,}(?:\.\.\.)?", "[REDACTED-LICENSE]", value)
        return value

    def private(self, path, text):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(text)

    def require_owned(self, kind, name):
        result = subprocess.run(["docker", kind, "inspect", name], capture_output=True, text=True)
        if result.returncode:
            return False
        info = json.loads(result.stdout)[0]
        labels = info.get("Config", {}).get("Labels", {}) if kind == "container" else info.get("Labels", {})
        if (labels or {}).get("arc-license-tests") != self.run_id:
            raise RuntimeError("refusing to reuse or mutate unowned "+kind+": "+name)
        return True

    def verify_container(self, name, env, image):
        if not self.require_owned("container", name):
            return None
        info = json.loads(subprocess.check_output(["docker", "container", "inspect", name], text=True))[0]
        image_info = json.loads(subprocess.check_output(["docker", "image", "inspect", image], text=True))[0]
        wanted_image = image_info["Id"]
        expected_env = dict(item.split("=", 1) for item in image_info["Config"].get("Env", []) if "=" in item)
        expected_env.update(env)
        actual_env = dict(item.split("=", 1) for item in info["Config"]["Env"] if "=" in item)
        managed = {key for key in set(expected_env) | set(actual_env)
                   if key.startswith("ARC_") or key in ("GOMAXPROCS", "SSL_CERT_FILE") or key in env}
        drift = sorted(key for key in managed if actual_env.get(key) != expected_env.get(key))
        if info["Image"] != wanted_image or drift:
            raise RuntimeError("existing container image/environment drift: "+name+"; keys="+",".join(drift))
        return info["Image"]

    def docker(self, *args, check=True, timeout=180):
        if args[0] == "run" and "--network" in args:
            network = str(args[args.index("--network")+1])
            if not self.require_owned("network", network):
                raise RuntimeError("test network is missing: "+network)
        if args[0] in ("start", "stop", "rm", "restart", "kill"):
            skip = False
            for value in args[1:]:
                value = str(value)
                if skip:
                    skip = False
                    continue
                if value in ("-t", "--time", "--signal", "-s"):
                    skip = True
                elif not value.startswith("-"):
                    self.require_owned("container", value)
        if args[:2] == ("network", "create"):
            self.require_owned("network", str(args[-1]))
        if args[:2] == ("network", "connect"):
            self.require_owned("network", str(args[-2]))
            self.require_owned("container", str(args[-1]))
        result = subprocess.run(["docker", *map(str, args)], capture_output=True,
                                text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(self.redact("docker " + str(args[0]) + ": " + result.stderr))
        return result

    def record(self, name, passed=None, observed=None, expected=None, note=""):
        status = "PASS" if passed is True else "FAIL" if passed is False else "OBSERVED"
        item = self.redact(dict(installation=self.current, name=name, result=status,
                               observed=observed, expected=expected, note=note))
        self.results.append(item)
        print(json.dumps(item), flush=True)
        self.write_report()

    def provenance(self):
        return dict(harness_revision=self.harness_revision,
                    requested_image=self.args.image,
                    actual_images={name: info.get("image_id", "historical-unrecorded") for name, info in self.nodes.items()})

    def write_report(self):
        data = dict(run_id=self.run_id, image=self.args.image,
                    harness_revision=self.harness_revision,
                    generated_at=dt.datetime.now(UTC).isoformat(),
                    installations=self.installations, results=self.results,
                    actual_images={name: info.get("image_id", "historical-unrecorded") for name, info in self.nodes.items()})
        self.private(self.state / "report.json", json.dumps(self.redact(data), indent=2))
        lines = ["# Docker license behavior report", "", f"Image: `{self.args.image}`",
                 f"Harness: `{data['harness_revision']}`", "",
                 "Real-license observations and fixture results are separate evidence classes.", "",
                 "| Installation | Check | Result |", "|---|---|---|"]
        for row in self.results:
            lines.append(f"| {row['installation']} | {row['name']} | {row['result']} |")
        lines += ["", "See report.json for redacted HTTP observations and expectations.",
                  "Raw license files, env files and databases are private and excluded from this report."]
        self.private(self.state / "report.md", "\n".join(lines) + "\n")

    def api(self, node, path, payload=None, method=None, token=True, timeout=30):
        info = self.nodes[node]
        headers = {"x-arc-database": "license_test"}
        if token:
            headers["Authorization"] = "Bearer " + (info["token"] if token is True else token)
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        elif isinstance(payload, str):
            payload = payload.encode()
            headers["Content-Type"] = "text/plain"
        req = urllib.request.Request(info["url"] + path, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                code, body = response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            code, body = error.code, error.read().decode()
        except (urllib.error.URLError, OSError) as error:
            return 0, {"network_error": str(error)}
        try:
            return code, json.loads(body)
        except ValueError:
            return code, body

    def refresh_port(self, node):
        self.nodes[node]["url"] = self.node_url(node, self.nodes[node]['install'])
        self.private(self.state / "nodes.private.json", json.dumps(self.nodes, indent=2))

    def node_url(self, node, install):
        published = self.docker('port', node, '8000/tcp', check=False)
        if published.returncode == 0 and published.stdout.strip():
            return 'http://127.0.0.1:'+published.stdout.strip().split(':')[-1]
        network = self.run_id+'-'+install
        self.require_owned('container', node)
        if not self.require_owned('network', network):
            raise RuntimeError('missing owned internal test network')
        net = json.loads(self.docker('network','inspect',network).stdout)[0]
        if not net.get('Internal'):
            raise RuntimeError('container has no published API port')
        info = json.loads(self.docker('inspect',node).stdout)[0]
        address = info['NetworkSettings']['Networks'][network]['IPAddress']
        if not address or not info['State']['Running']:
            raise RuntimeError('internal fixture has not started')
        return 'http://'+address+':8000'

    def wait(self, node, path="/ready", timeout=100, predicate=None):
        deadline = time.monotonic() + timeout
        result = None
        while time.monotonic() < deadline:
            result = self.api(node, path, timeout=3)
            if result[0] == 200 and (predicate is None or predicate(result[1])):
                return result
            time.sleep(.5)
        raise RuntimeError(self.redact(f"{node} {path} not ready: {result}"))

    def base_env(self, key, admin, shared, cluster_name):
        return {
            "ARC_LICENSE_KEY": key, "ARC_LOG_FORMAT": "json", "ARC_LOG_LEVEL": "info",
            "ARC_AUTH_ENABLED": "true", "ARC_AUTH_BOOTSTRAP_TOKEN": admin,
            "ARC_AUTH_DB_PATH": "/app/data/arc.db", "ARC_TELEMETRY_ENABLED": "false",
            "ARC_DATABASE_MEMORY_LIMIT": "256MB", "ARC_DATABASE_MAX_CONNECTIONS": "4",
            # Intentionally larger than ordinary license limits: observe startup clamping.
            "ARC_DATABASE_THREAD_COUNT": "256", "ARC_INGEST_FLUSH_WORKERS": "2",
            "ARC_INGEST_SHARD_COUNT": "2", "ARC_INGEST_MAX_BUFFER_AGE_MS": "200",
            "ARC_STORAGE_LOCAL_PATH": "/app/data/storage", "ARC_COMPACTION_ENABLED": "true",
            "ARC_COMPACTION_MEMORY_LIMIT": "128MB", "ARC_WAL_ENABLED": "true",
            "ARC_CLUSTER_ENABLED": "true", "ARC_CLUSTER_CLUSTER_NAME": cluster_name,
            "ARC_CLUSTER_SHARED_SECRET": shared, "ARC_CLUSTER_COORDINATOR_ADDR": ":9100",
            "ARC_CLUSTER_RAFT_BIND_ADDR": ":9200", "ARC_CLUSTER_REPLICATION_ENABLED": "true",
            "ARC_CLUSTER_FAILOVER_ENABLED": "true", "ARC_CLUSTER_HEALTH_CHECK_INTERVAL": "1",
            "ARC_CLUSTER_UNHEALTHY_THRESHOLD": "3", "ARC_CLUSTER_REPLICATION_PULL_WORKERS": "1",
            "ARC_AUDIT_LOG_ENABLED": "true", "ARC_AUDIT_LOG_INCLUDE_READS": "true",
            "ARC_GOVERNANCE_ENABLED": "true", "ARC_QUERY_MANAGEMENT_ENABLED": "true",
            "ARC_TIERED_STORAGE_ENABLED": "true", "ARC_TIERED_STORAGE_DEFAULT_HOT_MAX_AGE_DAYS": "1",
            "ARC_CONTINUOUS_QUERY_ENABLED": "true", "ARC_RETENTION_ENABLED": "true",
            "ARC_SERVER_SHUTDOWN_TIMEOUT": "40", "GOMAXPROCS": "2",
        }

    def start_node(self, install, role, env, image=None, extra=(), cluster_role=None, node_id=None):
        hostname = f"arc-license-{install}-{role}"
        name = f"{self.run_id}-{install}-{role}"
        directory = self.state / install / role
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = directory / "data"
        data.mkdir(mode=0o700, exist_ok=True)
        node_env = dict(env, ARC_CLUSTER_NODE_ID=hostname if node_id is None else node_id,
                        ARC_CLUSTER_ROLE=cluster_role or ("reader" if role == "r1" else "writer"),
                        ARC_CLUSTER_ADVERTISE_ADDR=hostname+":9100",
                        ARC_CLUSTER_RAFT_ADVERTISE_ADDR=hostname+":9200",
                        ARC_CLUSTER_API_ADDR=hostname+":8000",
                        ARC_CLUSTER_RAFT_BOOTSTRAP="true" if role == "w1" else "false")
        selected_image = image or self.args.image
        self.verify_container(name, node_env, selected_image)
        self.private(directory / "node.env", "".join(f"{k}={v}\n" for k, v in node_env.items()))
        mac = "02:" + ":".join(hashlib.sha256(hostname.encode()).hexdigest()[i:i+2] for i in range(0, 10, 2))
        if self.docker("container", "inspect", "-f", "{{.State.Status}}", name, check=False).returncode == 0:
            self.docker("start", name)
        else:
            self.docker("run", "-d", "--name", name, "--hostname", hostname,
                        "--network", f"{self.run_id}-{install}", "--network-alias", hostname,
                        "--mac-address", mac, "--label", self.label, "--cpus", "1", "--memory", "1g",
                        "--pids-limit", "512", "--stop-timeout", "45",
                        "--env-file", directory / "node.env", "-p", "127.0.0.1::8000",
                        "-v", str(data)+":/app/data", *extra, image or self.args.image)
        self.nodes[name] = dict(url=self.node_url(name,install), token=env["ARC_AUTH_BOOTSTRAP_TOKEN"],
                                data=str(data), install=install, role=role, hostname=hostname,
                                image_id=self.verify_container(name, node_env, selected_image))
        self.private(self.state / "nodes.private.json", json.dumps(self.nodes, indent=2))
        return name

    def signed_metadata(self, node):
        path = Path(self.nodes[node]["data"]) / "license_cache.json"
        if not path.exists():
            return None
        pair = json.loads(path.read_text())
        raw = base64.b64decode(pair["license_file"])
        payload = json.loads(raw)
        public = re.search(r"const enterprisePublicKeyPEM = `([^`]+)`", (ROOT / "internal/license/pubkey.go").read_text()).group(1)
        folder = self.state / self.nodes[node]["install"] / "signature-check"
        folder.mkdir(mode=0o700, exist_ok=True)
        for name, content in [("payload", raw), ("signature", base64.b64decode(pair["license_signature"])), ("public.pem", public.encode())]:
            fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(content)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(folder / "public.pem"),
                                 "-signature", str(folder / "signature"), str(folder / "payload")], capture_output=True)
        self.record("cache_signature_verifies_against_production_key", result.returncode == 0)
        return {k: payload.get(k) for k in ["tier", "features", "max_cores", "max_machines", "expires_at", "issued_at"]} | {
            "trial": payload.get("customer_id", "").startswith("trial-"),
            "bound_to_machine": bool(payload.get("machine_fingerprint")),
        }

    @staticmethod
    def count(body):
        if not isinstance(body, dict) or body.get("columns") != ["n"] or len(body.get("data", [])) != 1:
            raise ValueError("unexpected count response: " + str(body))
        row = body["data"][0]
        value = row[0] if isinstance(row, list) else row.get("n")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("count is not a nonnegative integer")
        return value

    def query_count(self, node, measurement="events"):
        return self.api(node, "/api/v1/query", {"sql": f"SELECT count(*) AS n FROM {measurement}"})

    def probe_features(self, node, metadata):
        features = set(metadata.get("features", [])) if metadata else set()
        valid = bool(metadata) and dt.datetime.fromisoformat(metadata["expires_at"].replace("Z", "+00:00")) > dt.datetime.now(UTC)
        for label, path, flag in [
            ("rbac", "/api/v1/rbac/organizations", "rbac"),
            ("audit", "/api/v1/audit/logs?limit=5", "audit_logging"),
            ("governance", "/api/v1/governance/policies", "query_governance"),
            ("query_management", "/api/v1/queries/active", "query_management"),
            ("tiering", "/api/v1/tiering/status", "tiering"),
        ]:
            code, body = self.api(node, path)
            entitled = valid and flag in features
            self.record(label+"_entitlement_http", code == 200 if entitled else code in (403, 404),
                        {"http": code, "body": body}, "200" if entitled else "403/404")
            if label == "audit" and entitled and code == 200:
                kinds = {row.get("event_type") for row in body.get("data", [])}
                self.record("audit_records_real_query_or_write", bool(kinds & {"data.query", "data.write"}), sorted(kinds))
        if valid:
            code, body = self.api(node, "/api/v1/schedulers/")
            self.record("licensed_schedulers_running", code == 200 and all(body.get(name, {}).get("running") for name in ("cq_scheduler", "retention_scheduler")), body)
        if valid and "query_management" in features:
            code, body = self.api(node, "/api/v1/queries/history")
            self.record("query_management_history_observed", code == 200, {"http": code, "body": body})
        for path in ("/api/v1/schedulers/", "/api/v1/cluster", "/ready", "/ready/write"):
            self.record("state:"+path, observed=self.api(node, path))
        self.record("no_auth_query_refused", self.api(node, "/api/v1/query", {"sql": "SELECT 1"}, token=False)[0] == 401)
        self.record("arcx_sql_execution", observed="not exercised", note="The standard Docker image does not contain the proprietary extension artifact; entitlement is not proof of execution.")

    def rbac(self, node):
        ids = {}
        code, body = self.api(node, "/api/v1/rbac/organizations", {"name": "license-test-"+self.case_id})
        self.record("rbac_create_organization", code == 201, {"http": code, "body": body})
        if code != 201:
            return
        org = body["organization"]["id"]
        code, body = self.api(node, f"/api/v1/rbac/organizations/{org}/teams", {"name": "restricted"})
        self.record("rbac_create_team", code == 201, {"http": code, "body": body})
        if code != 201:
            return
        team = body["team"]["id"]
        code, body = self.api(node, f"/api/v1/rbac/teams/{team}/roles",
                              {"database_pattern": "license_test", "permissions": ["read"]})
        self.record("rbac_create_role", code == 201, {"http": code, "body": body})
        if code != 201:
            return
        role = body["role"]["id"]
        code, body = self.api(node, f"/api/v1/rbac/roles/{role}/measurements",
                              {"measurement_pattern": "events", "permissions": ["read"]})
        self.record("rbac_create_measurement_grant", code == 201, {"http": code, "body": body})
        code, body = self.api(node, "/api/v1/auth/tokens", {"name": "restricted-license-test-"+self.case_id, "permissions": ["read"]})
        if code != 201:
            self.record("rbac_create_token", False, {"http": code, "body": body})
            return
        data = body.get("data", body)
        token = self.secret(data.get("token", body.get("token")))
        token_id = data.get("id", body.get("id"))
        if token_id is None and isinstance(data.get("token_info"), dict):
            token_id = data["token_info"].get("id")
        if token and token_id is None:
            verify_code, verified = self.api(node, "/api/v1/auth/verify", token=token)
            if verify_code == 200:
                token_id = verified.get("token_info", {}).get("id")
        if not token or token_id is None:
            self.record("rbac_token_response_contract", False, self.redact(body))
            return
        code, body = self.api(node, f"/api/v1/auth/tokens/{token_id}/teams", {"team_id": team})
        self.record("rbac_assign_token", code in (200, 201), {"http": code, "body": body})
        allowed = self.api(node, "/api/v1/query", {"sql": "SELECT count(*) AS n FROM events"}, token=token)
        denied = self.api(node, "/api/v1/query", {"sql": "SELECT count(*) AS n FROM private_events"}, token=token)
        self.record("rbac_allowed_measurement", allowed[0] == 200, allowed)
        self.record("rbac_denial_is_final", denied[0] == 403, denied)
        ids.update(org=org, team=team, role=role, token_id=token_id)
        self.private(self.state / self.current / "rbac.private.json", json.dumps(dict(ids, token=token)))
        if "query_governance" in getattr(self, "current_features", set()):
            code, body = self.api(node, "/api/v1/governance/policies", {"token_id": token_id, "max_rows_per_query": 1})
            self.record("governance_create_row_cap", code == 201, (code, body))
            result = self.api(node, "/api/v1/query", {"sql": "SELECT record_id,value FROM events ORDER BY value LIMIT 10"}, token=token)
            self.record("governance_enforces_row_cap", result[0] == 200 and result[1].get("row_count") == 1, result, 1)

    def snapshot(self, install):
        evidence = {}
        for node, info in self.nodes.items():
            if info["install"] != install:
                continue
            tables = {}
            for path in Path(info["data"]).rglob("*.db"):
                try:
                    with sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True) as db:
                        names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                        for name in names:
                            quoted = '"'+name.replace('"', '""')+'"'
                            rows = db.execute("SELECT * FROM "+quoted).fetchall()
                            encoded = json.dumps(sorted(map(repr, rows))).encode()
                            tables[str(path.relative_to(info["data"]))+":"+name] = {"rows": len(rows), "sha256": hashlib.sha256(encoded).hexdigest()}
                except sqlite3.Error as error:
                    tables[str(path.name)] = {"error": str(error)}
            files = {str(p.relative_to(info["data"])): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in Path(info["data"]).rglob("*.parquet")}
            evidence[info["role"]] = {"tables": tables, "parquet": files}
        self.private(self.state / install / "inventory.json", json.dumps(evidence, indent=2))
        self.record("data_metadata_inventory", observed=evidence)

    def collect(self, install):
        for node, info in self.nodes.items():
            if info["install"] == install:
                # Docker may send stderr separately; include both without leaking secrets.
                result = self.docker("logs", node, check=False)
                self.private(self.state / install / (info["role"]+".redacted.log"), self.redact(result.stdout+result.stderr))

    def stop_install(self, install):
        names = [n for n, info in self.nodes.items() if info["install"] == install]
        if names:
            self.docker("stop", "-t", "45", *names, timeout=120, check=False)
        self.collect(install)

    def run_install(self, index, key_path):
        install = "license"+str(index)
        self.current = install
        key = self.secret(Path(key_path).read_text().strip())
        if not key or "\n" in key:
            raise ValueError("empty or multiline license file")
        self.secret(key[:12])
        folder = self.state / install
        folder.mkdir(mode=0o700, exist_ok=True)
        # Preserve credentials on a rerun of this state directory.
        secret_path = folder / "installation.private.json"
        if secret_path.exists():
            credentials = json.loads(secret_path.read_text())
        else:
            credentials = dict(admin=secrets.token_hex(32), shared=secrets.token_hex(32))
            self.private(secret_path, json.dumps(credentials))
        admin, shared = self.secret(credentials["admin"]), self.secret(credentials["shared"])
        network = f"{self.run_id}-{install}"
        if self.docker("network", "inspect", "-f", "{{.Name}}", network, check=False).returncode:
            self.docker("network", "create", "--label", self.label, network)
        self.require_owned("network", network)
        # A persisted Raft group needs its original voters during a rerun.
        for name, info in self.nodes.items():
            if info["install"] == install and info["role"] != "w1":
                self.docker("start", name)
                self.refresh_port(name)
        env = self.base_env(key, admin, shared, install)
        env["ARC_CLUSTER_SEEDS"] = ",".join(f"arc-license-{install}-w{n}:9100" for n in (1, 2, 3))
        leader = self.start_node(install, "w1", env)
        self.wait(leader)
        health = self.api(leader, "/health")
        self.record("startup_health", health[0] == 200, health)
        metadata = self.signed_metadata(leader)
        self.installations.append(dict(id=install, key_file=Path(key_path).name, signed_license=metadata))
        self.record("signed_entitlement_and_expiration", observed=metadata)
        features = set(metadata.get("features", [])) if metadata else set()
        self.current_features = features
        status, cluster = self.api(leader, "/api/v1/cluster")
        cluster_allowed = bool(metadata) and "clustering" in features
        self.record("cluster_requested_and_license_gate", bool(cluster.get("enabled")) == cluster_allowed,
                    {"http": status, "cluster": cluster}, {"enabled": cluster_allowed})
        peers = []
        if cluster_allowed:
            capacity = metadata.get("max_machines", 0)
            for role in ["w2", "w3", "r1"][:max(0, min(3, capacity-1 if capacity > 0 else 3))]:
                peer = self.start_node(install, role, env)
                try:
                    self.wait(peer)
                except Exception as error:
                    self.record("peer_start:"+role, False, str(error))
                    break
                peer_health = self.api(peer, "/health")
                self.record("peer_license:"+role, peer_health[1].get("license", {}).get("status") == "active", peer_health)
                peers.append(peer)
            expected_nodes = 1+len(peers)
            _, cluster = self.wait(leader, "/api/v1/cluster", timeout=90,
                                   predicate=lambda b: b.get("node_count", 0) >= expected_nodes)
            self.record("cluster_members_converged", cluster.get("node_count") == expected_nodes, cluster)
            candidates = [leader]+peers
            for _ in range(60):
                writable = [node for node in candidates if self.api(node, "/ready/write")[0] == 200]
                if writable:
                    leader = writable[0]
                    break
                time.sleep(.5)
            self.record("writable_primary_exists", bool(writable), observed=writable)
        old_code, old_count = self.query_count(leader)
        baseline = self.count(old_count) if old_code == 200 else 0
        old_code, old_unique = self.api(leader, "/api/v1/query", {"sql": "SELECT count(DISTINCT record_id) AS n FROM events"})
        unique_baseline = self.count(old_unique) if old_code == 200 else 0
        expected_count = baseline + 50
        stamp = time.time_ns()
        body = "".join(f"events,record_id=r{self.case_id}_{i} value={i}i {stamp+i}\n" for i in range(50))
        code, result = self.api(leader, "/api/v1/write/line-protocol", body)
        self.record("ingest_50_acknowledged_rows", code in (200, 204), {"http": code, "body": result})
        self.api(leader, "/api/v1/write/line-protocol", f"private_events value=1i {stamp}\n")
        time.sleep(2)
        code, count = self.query_count(leader)
        self.record("query_exact_acknowledged_count", code == 200 and self.count(count) == expected_count, {"http": code, "body": count}, expected_count)
        code, unique = self.api(leader, "/api/v1/query", {"sql": "SELECT count(DISTINCT record_id) AS n FROM events"})
        self.record("query_unique_acknowledged_ids", code == 200 and self.count(unique) == unique_baseline+50, unique, unique_baseline+50)
        for peer in peers:
            if self.nodes[peer]["role"] != "r1":
                continue
            try:
                _, result = self.wait(peer, "/api/v1/cluster", timeout=20)
                deadline = time.monotonic()+60
                observed = None
                while time.monotonic() < deadline:
                    code, observed = self.query_count(peer)
                    if code == 200 and self.count(observed) == expected_count:
                        break
                    time.sleep(.5)
                self.record("reader_replication_exact_count", code == 200 and self.count(observed) == expected_count, observed)
            except Exception as error:
                self.record("reader_replication_exact_count", False, str(error))
        self.probe_features(leader, metadata)
        if "rbac" in features:
            self.rbac(leader)
        code, threads = self.api(leader, "/api/v1/query", {"sql": "SELECT current_setting('threads') AS configured_threads"})
        self.record("effective_duckdb_thread_cap", observed={"requested": 256, "signed_limit": metadata.get("max_cores") if metadata else None,
                                                          "http": code, "body": threads})
        log = self.docker("logs", leader, check=False)
        settings = []
        for line in (log.stdout+log.stderr).splitlines():
            try:
                event = json.loads(line)
                if event.get("message", "").startswith("DuckDB effective resource settings"):
                    settings.append(event)
            except ValueError:
                pass
        if settings and metadata:
            actual = int(settings[-1]["threads"])
            limit = metadata["max_cores"]
            self.record("signed_core_limit_enforced_in_runtime", actual == (min(256, limit) if limit > 0 else 256),
                        {"requested_threads": 256, "effective_threads": actual, "signed_max_cores": limit})
        else:
            self.record("signed_core_limit_enforced_in_runtime", False, "No effective-settings observation")
        before = self.query_count(leader)
        self.docker("restart", "-t", "45", leader, timeout=120)
        self.refresh_port(leader)
        self.wait(leader)
        after = self.query_count(leader)
        self.record("restart_preserves_acknowledged_rows",
                    before[0] == after[0] == 200 and self.count(before[1]) == self.count(after[1]),
                    after, self.count(before[1]) if before[0] == 200 else before)
        self.record("restart_license_source_status", observed=self.api(leader, "/health"))
        self.snapshot(install)
        self.record("staged_day8_day9_day10_day15_policy", observed="not implemented in target branch",
                    note="Behavioral tests of those proposed phases cannot pass against a branch that only implements core runtime expiry.")
        self.stop_install(install)

    def run(self):
        for index, key_path in enumerate(self.args.key_files):
            try:
                self.run_install(index, key_path)
            except Exception as error:
                self.record("installation_exception", False, str(error))
                self.stop_install("license"+str(index))
        self.current = None
        self.write_report()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="arc-license-tests:dde0bbeb")
    parser.add_argument("--state", required=True)
    parser.add_argument("--run-id", default="arc-license-"+dt.datetime.now(UTC).strftime("%Y%m%d%H%M%S"))
    parser.add_argument("key_files", nargs="+")
    args = parser.parse_args()
    suite = Suite(args)
    suite.run()
    print("Report: "+str(suite.state / "report.md"), flush=True)
    return int(any(row["result"] == "FAIL" for row in suite.results))


if __name__ == "__main__":
    raise SystemExit(main())
