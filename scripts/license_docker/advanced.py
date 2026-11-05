#!/usr/bin/env python3
"""Cold-storage, capacity and persistence checks on the real installations."""
import argparse
import datetime as dt
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from run import Suite, UTC


class Advanced(Suite):
    def __init__(self, args):
        super().__init__(args)
        self.base_report = json.loads((self.state / "report.json").read_text())
        self.installations = self.base_report["installations"]
        self.results = []
        self.s3_name = self.run_id+"-cold-store"
        self.s3_port = None
        for key_file in args.key_files:
            value = Path(key_file).read_text().strip()
            self.secret(value)
            self.secret(value[:12])

    def write_report(self):
        # Keep baseline evidence intact; the advanced run is a separate artifact.
        if not hasattr(self, "base_report"):
            return
        data = self.redact(dict(**self.provenance(), evidence_class="real licenses / advanced Docker", results=self.results,
                                installations=self.installations, generated_at=dt.datetime.now(UTC).isoformat()))
        self.private(self.state / (getattr(self.args, "report_name", "advanced-report")+".json"), json.dumps(data, indent=2))

    def storage(self):
        network = self.run_id+"-cold"
        self.docker("network", "create", "--label", self.label, network, check=False)
        self.docker("stop", self.s3_name, check=False)
        self.docker("rm", self.s3_name, check=False)
        folder = self.state / "cold-store"
        folder.mkdir(mode=0o700, exist_ok=True)
        self.docker("run", "-d", "--name", self.s3_name, "--label", self.label,
                    "--hostname", self.s3_name, "--network", network,
                    "--memory", "512m", "--cpus", ".5", "-p", "127.0.0.1::8333",
                    "-v", str(folder)+":/data", "chrislusf/seaweedfs:4.47",
                    "server", "-dir=/data", "-s3", "-s3.port=8333", "-ip="+self.s3_name,
                    "-ip.bind=0.0.0.0", "-master.volumeSizeLimitMB=64")
        self.s3_port = self.docker("port", self.s3_name, "8333/tcp").stdout.strip().split(":")[-1]
        for _ in range(240):
            try:
                self.s3("/", "GET")
                return
            except Exception:
                time.sleep(.25)
        raise RuntimeError("local S3 fixture did not start")

    def s3(self, path, method):
        request = urllib.request.Request("http://127.0.0.1:"+self.s3_port+path, method=method)
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()

    def reopen_with_cold(self, install):
        self.current = install
        bucket = install+"-cold"
        try:
            self.s3("/"+bucket, "PUT")
        except urllib.error.HTTPError as error:
            if error.code != 409:
                raise
        self.docker("network", "connect", "--alias", "cold-store", self.run_id+"-"+install, self.s3_name, check=False)
        names = [name for name, info in self.nodes.items() if info["install"] == install
                 and not (install == "license1" and info["role"] == "r1")]
        for name in names:
            info = self.nodes[name]
            env_path = self.state / install / info["role"] / "node.env"
            env = dict(line.split("=", 1) for line in env_path.read_text().splitlines() if line)
            old_env = dict(env)
            cluster_role = "compactor" if "writer_failover" not in self.current_features and info["role"] == "w3" else ("reader" if info["role"] == "r1" else "writer")
            env["ARC_CLUSTER_ROLE"] = cluster_role
            env.update(ARC_COMPACTION_DAILY_MIN_FILES="1", ARC_COMPACTION_DAILY_SKIP_FILE_AGE_CHECK_DAYS="1",
                       ARC_TIERED_STORAGE_COLD_ENABLED="true", ARC_TIERED_STORAGE_COLD_BACKEND="s3",
                       ARC_TIERED_STORAGE_COLD_S3_BUCKET=bucket, ARC_TIERED_STORAGE_COLD_S3_REGION="us-east-1",
                       ARC_TIERED_STORAGE_COLD_S3_ENDPOINT="http://cold-store:8333",
                       ARC_TIERED_STORAGE_COLD_S3_ACCESS_KEY="local-test", ARC_TIERED_STORAGE_COLD_S3_SECRET_KEY="local-test",
                       ARC_TIERED_STORAGE_COLD_S3_USE_SSL="false", ARC_TIERED_STORAGE_COLD_S3_PATH_STYLE="true")
            if env != old_env:
                self.docker("stop", "-t", "45", name, check=False)
                self.docker("rm", name)
            self.start_node(install, info["role"], env, cluster_role=cluster_role)
        for name in names:
            self.wait(name)
        self.wait(names[0], "/api/v1/cluster", predicate=lambda b: b.get("node_count", 0) >= len(names))
        for _ in range(40):
            ready = [name for name in names if self.api(name, "/ready/write")[0] == 200]
            if ready:
                return ready[0], names, bucket
            time.sleep(.5)
        raise RuntimeError("no primary after cold-tier configuration restart")

    def protected_metadata(self, node):
        import sqlite3
        path = Path(self.nodes[node]["data"]) / "arc.db"
        result = {}
        with sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True) as db:
            for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'rbac_%' ORDER BY name"):
                quoted = '"'+name.replace('"', '""')+'"'
                columns = [row[1] for row in db.execute("PRAGMA table_info("+quoted+")")]
                result[name] = dict(columns=columns, rows=sorted(map(repr, db.execute("SELECT * FROM "+quoted).fetchall())))
        return result

    def run_case(self, installation):
        install = installation["id"]
        metadata = installation["signed_license"]
        self.current_features = set(metadata["features"])
        leader, names, bucket = self.reopen_with_cold(install)
        self.rbac(leader)
        baseline = self.query_count(leader)
        before_metadata = self.protected_metadata(leader)
        stamp = time.time_ns()-3*24*3600*10**9
        measurement = "cold_events_"+self.case_id
        writes = []
        # The compactor needs at least two source files. Separate flushes create them
        # through ingestion instead of altering files or metadata behind Arc.
        for first in (0, 15):
            writes.append(self.api(leader, "/api/v1/write/line-protocol",
                          "".join(f"{measurement},record_id=c{i} value={i}i {stamp+i}\n" for i in range(first, first+15))))
            time.sleep(1)
        self.record("old_data_ingested_for_real_cold_migration", all(code == 204 for code, _ in writes), writes)
        time.sleep(2)
        deadline = time.monotonic()+30
        compactor = None
        while time.monotonic() < deadline:
            cluster_status = self.api(leader, "/api/v1/cluster")
            holder = cluster_status[1].get("active_compactor", {}).get("node_id")
            source = "lease" if holder else "static_compactor_role"
            if not holder:
                holder = next((n["id"] for n in cluster_status[1].get("nodes", [])
                               if n.get("role") == "compactor" and n.get("state") == "healthy"), None)
            compactor = next((n for n in names if self.nodes[n]["hostname"] == holder), None)
            if compactor is not None:
                break
            time.sleep(.5)
        if compactor is None:
            raise RuntimeError("no observed active compactor in the installation after settling")
        self.record("observed_compactor_selection", observed={"node_id": holder, "container": compactor, "source": source})
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            replicated = self.query_count(compactor, measurement)
            if replicated[0] == 200 and self.count(replicated[1]) == 30:
                break
            time.sleep(.5)
        compact = self.api(compactor, "/api/v1/compaction/trigger?tier=daily&database=license_test&measurement="+measurement, {})
        self.record("daily_compaction_requested", compact[0] in (200, 202), compact)
        # Tier migration requires daily-compacted files, not raw hourly ingest.
        deadline = time.monotonic()+60
        while time.monotonic() < deadline:
            daily = [p for p in Path(self.nodes[leader]["data"]).rglob("*.parquet")
                     if measurement in str(p) and "_daily" in p.name and "_compaction_staged" not in str(p)]
            cycle = self.api(compactor, "/api/v1/compaction/cycles/"+str(compact[1].get("cycle_id")))
            if daily and cycle[0] == 200 and cycle[1].get("status") == "completed":
                break
            time.sleep(.5)
        self.record("compaction_cycle_terminal_state", cycle[0] == 200 and cycle[1].get("status") == "completed", cycle)
        self.record("rows_immediately_after_compaction_before_scan", observed=self.query_count(leader, measurement))
        self.record("daily_compacted_file_exists", bool(daily), [str(p.relative_to(self.nodes[leader]["data"])) for p in daily])
        self.record("cold_backend_initialized", observed=self.api(leader, "/api/v1/tiering/status"))
        code, body = self.api(leader, "/api/v1/tiering/scan", {})
        self.record("tier_scan_runs", code == 200, (code, body))
        self.record("rows_after_tier_scan_before_migration", observed=self.query_count(leader, measurement))
        payload = dict(from_tier="hot", to_tier="cold", database="license_test", measurement=measurement)
        preview = self.api(leader, "/api/v1/tiering/migrate", dict(payload, dry_run=True))
        self.record("cold_migration_has_real_candidate", preview[0] == 200 and preview[1].get("would_migrate", 0) > 0, preview)
        migrated = self.api(leader, "/api/v1/tiering/migrate", payload, timeout=120)
        self.record("cold_migration_moves_file", migrated[0] == 200 and migrated[1].get("migrated", 0) > 0 and migrated[1].get("errors") == 0, migrated)
        objects = self.s3("/"+bucket+"?list-type=2", "GET")
        document = ET.fromstring(objects[1])
        keys = [element.text for element in document.iter() if element.tag.split("}")[-1] == "Key"]
        self.record("cold_objects_exist_in_s3", any(measurement in key for key in keys), keys)
        cold_query = self.query_count(leader, measurement)
        self.record("cold_rows_queryable_after_migration", cold_query[0] == 200 and self.count(cold_query[1]) == 30, cold_query)
        hot_paths = [str(path.relative_to(self.nodes[leader]["data"])) for path in Path(self.nodes[leader]["data"]).rglob("*.parquet") if "/"+measurement+"/" in str(path)]
        self.record("post_migration_hot_copy_observation", observed=hot_paths)
        time.sleep(3)
        settled = self.query_count(leader, measurement)
        self.record("cold_rows_after_three_seconds", settled[0] == 200 and self.count(settled[1]) == 30, settled)
        self.docker("restart", "-t", "45", leader, timeout=120)
        self.refresh_port(leader)
        self.wait(leader)
        cold_after = self.query_count(leader, measurement)
        self.record("cold_rows_queryable_after_restart", cold_after[0] == 200 and self.count(cold_after[1]) == 30, cold_after)
        hot_after = self.query_count(leader)
        self.record("hot_rows_preserved_with_cold_configuration", hot_after[0] == 200 and baseline[0] == 200 and self.count(hot_after[1]) == self.count(baseline[1]), hot_after)
        self.record("rbac_metadata_unchanged_by_restart", self.protected_metadata(leader) == before_metadata,
                    {"before_tables": {k: len(v["rows"]) for k, v in before_metadata.items()},
                     "after_tables": {k: len(v["rows"]) for k, v in self.protected_metadata(leader).items()}})
        self.snapshot(install)
        # Test a real capacity refusal once, without allocating arbitrary identities.
        if metadata["max_machines"] == 3:
            extra_name = self.run_id+"-"+install+"-r1"
            path = self.state / install / ("r1" if extra_name in self.nodes else "w1") / "node.env"
            env = dict(line.split("=", 1) for line in path.read_text().splitlines() if line)
            extra = self.start_node(install, "r1", env)
            self.wait(extra)
            health = self.api(extra, "/health")
            cluster = self.api(extra, "/api/v1/cluster")
            self.record("real_fourth_activation_refused",
                        health[1].get("license", {}).get("status") == "unlicensed" and not cluster[1].get("enabled"),
                        {"health": health, "cluster": cluster}, "one deliberate excess-machine attempt; stop after refusal")
            self.record("capacity_refusal_attribution", observed="inconclusive: the client redacts the authority HTTP 403 response body; refusal alone cannot prove the capacity reason")
        self.stop_install(install)

    def run(self):
        self.storage()
        for installation in self.installations:
            if getattr(self.args, "only", None) and installation["id"] not in self.args.only:
                continue
            try:
                self.run_case(installation)
            except Exception as error:
                self.record("advanced_exception", False, str(error))
                self.stop_install(installation["id"])
        self.docker("stop", self.s3_name)
        self.write_report()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--image", default="arc-license-tests:dde0bbeb")
    parser.add_argument("--run-id", default="arc-license-live")
    parser.add_argument("--only", nargs="+", help="recheck selected installation IDs")
    parser.add_argument("--report-name", default="advanced-report", help="JSON report basename inside state directory")
    parser.add_argument("key_files", nargs="+")
    args = parser.parse_args()
    suite = Advanced(args)
    suite.run()
    return int(any(row["result"] == "FAIL" for row in suite.results))


if __name__ == "__main__":
    raise SystemExit(main())
