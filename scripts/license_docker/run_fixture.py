#!/usr/bin/env python3
"""Controlled Docker expiry/failure evidence, explicitly using synthetic keys."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import secrets
import ssl
import time
import urllib.request

from run import Suite, UTC


class Fixtures(Suite):
    def __init__(self, args):
        super().__init__(args)
        self.material = Path(args.material).resolve() / "private"
        self.control_token = self.secret((self.material / "control.token").read_text().strip())
        self.ssl = ssl.create_default_context(cafile=str(self.material / "tls.crt"))
        self.server_name = args.run_id+"-authority"
        self.network = None
        self.control_url = None

    def control(self, **changes):
        return self.authority("/control", changes)

    def authority(self, path, data=None):
        request = urllib.request.Request(self.control_url+path,
                    data=json.dumps(data).encode() if data is not None else None,
                    headers={"Authorization": "Bearer "+self.control_token, "Content-Type": "application/json"})
        with urllib.request.urlopen(request, context=self.ssl, timeout=10) as response:
            return json.load(response)

    def setup_authority(self):
        self.docker("network", "create", "--label", self.label, self.args.run_id+"-authority")
        self.docker("run", "-d", "--name", self.server_name, "--label", self.label,
                    "--network", self.args.run_id+"-authority", "--network-alias", "enterprise.basekick.net",
                    "--env-file", self.material / "server.env", "-v", str(self.material)+":/fixture:ro",
                    "-p", "127.0.0.1::443", "--memory", "192m", "--cpus", ".5",
                    getattr(self.args, "authority_image", "arc-license-authority:local"))
        port = self.docker("port", self.server_name, "443/tcp").stdout.strip().split(":")[-1]
        self.control_url = "https://127.0.0.1:"+port
        for _ in range(30):
            try:
                self.authority("/stats")
                return
            except Exception:
                time.sleep(.2)
        raise RuntimeError("local fixture authority did not start")

    def prepare(self, install, image, expires):
        self.current = install
        self.docker("network", "create", "--label", self.label, f"{self.args.run_id}-{install}")
        self.docker("network", "connect", "--alias", "enterprise.basekick.net",
                    f"{self.args.run_id}-{install}", self.server_name)
        self.control(mode="valid", activation_mode="valid", tier="enterprise", max_cores=32,
                     max_machines=10, success_limit=0, expires_at=expires.isoformat(), reset_events=True)
        admin, shared = self.secret(secrets.token_hex(32)), self.secret(secrets.token_hex(32))
        env = self.base_env("LOCAL-FIXTURE-"+install.upper(), admin, shared, install)
        env["SSL_CERT_FILE"] = "/run/fixture-ca.crt"
        env["ARC_CLUSTER_SEEDS"] = ",".join(f"arc-license-{install}-w{n}:9100" for n in (1, 2, 3))
        nodes = []
        for role in ["w1", "w2", "w3", "r1"]:
            node = self.start_node(install, role, env, image=image,
                                  extra=("-v", str(self.material / "tls.crt")+":/run/fixture-ca.crt:ro"))
            self.wait(node)
            nodes.append(node)
        leader = nodes[0]
        self.wait(leader, "/api/v1/cluster", predicate=lambda b: b.get("node_count") == 4)
        self.wait(leader, "/ready/write")
        stamp = time.time_ns()
        code, body = self.api(leader, "/api/v1/write/line-protocol",
                              "".join(f"events,record_id=f{i} value={i}i {stamp+i}\n" for i in range(20)))
        self.record("fixture_ingest_baseline", code == 204, (code, body))
        self.api(leader, "/api/v1/write/line-protocol", f"private_events value=9i {stamp}\n")
        time.sleep(1)
        code, body = self.query_count(leader)
        self.record("fixture_query_baseline", code == 200 and self.count(body) == 20, (code, body))
        code, body = self.api(leader, "/api/v1/queries/active")
        self.record("fixture_licensed_feature_positive", code == 200, (code, body))
        return leader, nodes

    def caches(self, nodes):
        result = {}
        for node in nodes:
            path = Path(self.nodes[node]["data"]) / "license_cache.json"
            result[node] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        return result

    def until(self, predicate, timeout=15):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(.25)
        return False

    def all_status(self, nodes, status):
        return all(self.api(node, "/health")[1].get("license", {}).get("status") == status for node in nodes)

    def expiry(self):
        install = "clock"
        expires = dt.datetime.now(UTC)+dt.timedelta(seconds=45)
        leader, nodes = self.prepare(install, "arc-license-fixture:slow", expires)
        self.rbac(leader)
        stats_before = self.authority("/stats")
        self.record("clock_baseline_active_before_boundary", self.all_status(nodes, "active"))
        wait = expires.timestamp()-time.time()+.5
        if wait > 0:
            time.sleep(wait)
        stats_after = self.authority("/stats")
        self.record("clock_expiry_without_additional_authority_request",
                    len(stats_before["events"]) == len(stats_after["events"]),
                    {"before": len(stats_before["events"]), "after": len(stats_after["events"]),
                     "signed_expires_at": expires.isoformat(), "cadence": "unmodified 4 hours"})
        self.record("signed_expiry_health_changes_on_every_node", self.all_status(nodes, "expired"),
                    [self.api(node, "/health") for node in nodes])
        code, body = self.api(leader, "/api/v1/queries/active")
        self.record("expired_query_management_refused", code == 403, (code, body))
        code, body = self.api(leader, "/api/v1/rbac/organizations")
        self.record("expired_rbac_management_refused", code == 403, (code, body))
        saved = json.loads((self.state / install / "rbac.private.json").read_text())
        scoped = self.secret(saved["token"])
        allowed = self.api(leader, "/api/v1/query", {"sql": "SELECT count(*) AS n FROM events"}, token=scoped)
        denied = self.api(leader, "/api/v1/query", {"sql": "SELECT count(*) AS n FROM private_events"}, token=scoped)
        self.record("expiry_preserves_existing_rbac_grants_and_denials", allowed[0] == 200 and denied[0] == 403,
                    {"allowed": allowed, "denied": denied})
        _, cluster = self.api(leader, "/api/v1/cluster")
        readiness = {self.nodes[n]["role"]: self.api(n, "/ready/write")[0] for n in nodes}
        self.record("expiry_actual_cluster_roles_raft_and_readiness", observed={"cluster": cluster, "write_readiness": readiness},
                    note="Observation of running services, not inference from license health.")
        self.record("required_automatic_cluster_to_oss_handoff", not cluster.get("running", True) and not cluster.get("raft", {}).get("enabled", True),
                    {"cluster_running": cluster.get("running"), "raft_enabled": cluster.get("raft", {}).get("enabled")},
                    note="Expected policy gap: the tested PR implements runtime gates, not the proposed handoff.")
        write = self.api(leader, "/api/v1/write/line-protocol", f"events,record_id=afterexpiry value=99i {time.time_ns()}\n")
        self.record("expiry_actual_ingest_behavior", observed=write)
        self.snapshot(install)
        self.stop_install(install)

    def preservation_window(self, nodes, baseline, start, mode, activate=False):
        # Repeated attempts prove prior responses returned; polling detects a
        # temporary clear/recovery that a single final-state assertion misses.
        deadline = time.monotonic()+12
        intact = True
        samples = 0
        attempts = {}
        window_start = time.monotonic()
        while time.monotonic() < deadline:
            intact = intact and self.all_status(nodes, "active") and self.caches(nodes) == baseline
            intact = intact and all(self.api(n, "/api/v1/queries/active")[0] == 200 for n in nodes)
            samples += 1
            attempts = {}
            for event in self.authority("/stats")["events"]:
                if event["time"] >= start and event["mode"] == mode and event["activate"] == activate:
                    identity = event["fingerprint"]
                    attempts[identity] = attempts.get(identity, 0)+1
            if time.monotonic()-window_start >= 6 and len(attempts) == len(nodes) and min(attempts.values()) >= 2:
                break
            time.sleep(.15)
        observed = len(attempts) == len(nodes) and min(attempts.values(), default=0) >= 2
        return intact and observed, {"samples": samples, "seconds": round(time.monotonic()-window_start, 1),
                                      "distinct_machines": len(attempts), "minimum_attempts": min(attempts.values(), default=0),
                                      "license_cache_and_api_intact_throughout": intact}

    def cache_expiries(self, nodes):
        import base64
        values = {}
        for node in nodes:
            path = Path(self.nodes[node]["data"])/"license_cache.json"
            if not path.exists():
                values[node] = None
                continue
            pair = json.loads(path.read_text())
            values[node] = json.loads(base64.b64decode(pair["license_file"]))["expires_at"]
        return values

    def faults(self):
        install = "faults"
        leader, nodes = self.prepare(install, "arc-license-fixture:fast", dt.datetime.now(UTC)+dt.timedelta(hours=2))
        self.rbac(leader)
        baseline = self.caches(nodes)
        for mode in ("503", "429", "malformed", "null", "html404", "bad_signature", "drop"):
            start = time.time()
            self.control(mode=mode, activation_mode="valid", success_limit=0)
            preserved, evidence = self.preservation_window(nodes, baseline, start, mode)
            self.record("transient_"+mode+"_preserves_license_and_cache", preserved, evidence)
        for reason in ("missing_activation", "revoked_activation"):
            for activation in ("503", "malformed", "valid"):
                start = time.time()
                if activation == "valid":
                    renewed_expiry = (dt.datetime.now(UTC)+dt.timedelta(hours=3)).isoformat()
                    self.control(mode=reason, activation_mode=activation, expires_at=renewed_expiry)
                    installed = self.until(lambda: all(dt.datetime.fromisoformat(self.api(n, "/health")[1].get("license", {}).get("expires_at", "1970-01-01T00:00:00Z").replace("Z", "+00:00")) == dt.datetime.fromisoformat(renewed_expiry) for n in nodes)
                        and all(value == renewed_expiry for value in self.cache_expiries(nodes).values()))
                    self.record("reactivation_"+reason+"_valid_installs_renewed_entitlement",
                                installed and all(self.caches(nodes)[n] != baseline[n] for n in nodes),
                                {"new_signed_expires_at": renewed_expiry, "runtime_and_cache_updated": installed})
                    baseline = self.caches(nodes)
                else:
                    self.control(mode=reason, activation_mode=activation)
                    preserved, evidence = self.preservation_window(nodes, baseline, start, activation, activate=True)
                    self.record("reactivation_"+reason+"_"+activation, preserved, evidence)
        for mode in ("expired", "suspended", "notfound", "revoked"):
            self.control(mode=mode, activation_mode="valid")
            observed = self.until(lambda: self.all_status(nodes, "unlicensed") and all(x is None for x in self.caches(nodes).values()))
            code, body = self.api(leader, "/api/v1/queries/active")
            self.record("definitive_"+mode+"_closes_gate_and_removes_cache", observed and code == 403,
                        {"all_unlicensed_and_cache_absent": observed, "feature_response": (code, body)})
            self.control(mode="valid", activation_mode="valid")
            recovered = self.until(lambda: self.all_status(nodes, "active") and all(self.caches(nodes).values()))
            self.record("recovery_after_"+mode, recovered)
        # Signed lower-capacity entitlement and restoration, without deleting config.
        import sqlite3
        def rbac_digest():
            with sqlite3.connect("file:"+str(Path(self.nodes[leader]["data"])/"arc.db")+"?mode=ro", uri=True) as db:
                rows = []
                for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'rbac_%' ORDER BY name"):
                    quoted = '"'+name.replace('"', '""')+'"'
                    rows.append((name, sorted(map(repr, db.execute("SELECT * FROM "+quoted).fetchall()))))
                return hashlib.sha256(repr(rows).encode()).hexdigest()
        before_rbac = rbac_digest()
        original_features = self.authority("/stats")["state"]["features"]
        self.control(mode="valid", tier="starter", features=[], max_cores=8, max_machines=1)
        restricted = self.until(lambda: all(self.api(n, "/api/v1/queries/active")[0] == 403 for n in nodes))
        self.record("synthetic_restricted_entitlement_closes_feature_gates", restricted,
                    {path: self.api(leader, path) for path in ["/api/v1/rbac/organizations", "/api/v1/tiering/status", "/api/v1/queries/active"]},
                    note="Synthetic restrictive feature vector; not evidence of official Starter issuance terms.")
        self.record("synthetic_downgrade_preserves_rbac_metadata", rbac_digest() == before_rbac)
        self.control(mode="valid", tier="enterprise", features=original_features, max_cores=32, max_machines=10)
        restored = self.until(lambda: all(self.api(n, "/api/v1/queries/active")[0] == 200 for n in nodes))
        self.record("synthetic_renewal_restores_existing_feature_configuration", restored and rbac_digest() == before_rbac)
        saved = json.loads((self.state / install / "rbac.private.json").read_text())
        scoped = self.secret(saved["token"])
        allowed = self.api(leader, "/api/v1/query", {"sql": "SELECT count(*) AS n FROM events"}, token=scoped)
        denied = self.api(leader, "/api/v1/query", {"sql": "SELECT count(*) AS n FROM private_events"}, token=scoped)
        self.record("renewal_preserves_rbac_access_and_denials", allowed[0] == 200 and denied[0] == 403, {"allowed": allowed, "denied": denied})
        self.control(mode="suspended")
        self.until(lambda: self.all_status(nodes, "unlicensed") and all(x is None for x in self.caches(nodes).values()))
        self.control(mode="503")
        self.docker("restart", "-t", "45", leader, timeout=120)
        self.refresh_port(leader)
        self.wait(leader, timeout=110)
        health = self.api(leader, "/health")
        cluster = self.api(leader, "/api/v1/cluster")
        self.record("outage_restart_cannot_resurrect_rejected_cache",
                    health[1].get("license", {}).get("status") == "unlicensed" and not cluster[1].get("enabled"),
                    {"health": health, "cluster": cluster})
        code, body = self.query_count(leader)
        self.record("oss_restart_retains_existing_hot_data", code == 200 and self.count(body) == 20, (code, body))
        self.record("mixed_running_cluster_and_oss_after_rejection", observed={
            self.nodes[n]["role"]: {"cluster": self.api(n, "/api/v1/cluster"), "ready_write": self.api(n, "/ready/write")[0]} for n in nodes},
            note="Current runtime behavior; does not satisfy the planned coordinated ownership transition.")
        self.snapshot(install)
        self.stop_install(install)

    def run(self):
        self.setup_authority()
        for case in (self.expiry, self.faults):
            try:
                case()
            except Exception as error:
                self.record("fixture_exception", False, str(error))
                if self.current:
                    self.stop_install(self.current)
        self.current = "fixture-authority"
        self.record("authority_request_history", observed=self.authority("/stats"))
        self.docker("stop", self.server_name)
        self.write_report()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--material", required=True)
    parser.add_argument("--run-id", default="arc-license-fixtures")
    parser.add_argument("--image", default="arc-license-fixture:fast")
    args = parser.parse_args()
    suite = Fixtures(args)
    suite.run()
    return int(any(row["result"] == "FAIL" for row in suite.results))


if __name__ == "__main__":
    raise SystemExit(main())
