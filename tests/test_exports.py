import contextlib
import copy
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import all_in_one
import s3_upload


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.sec = self.root / "sec"
        self.sec.mkdir()
        self.blocked = [f"blockedcluster{i:06d}" for i in range(10)]
        (self.sec / "org_cids.csv").write_text("\n".join(self.blocked))
        self.exports = self.root / "exports"
        self.exports.mkdir()
        for module, name, value in ((s3_upload, "SEC", str(self.sec)),
                                    (all_in_one, "SEC", self.sec),
                                    (all_in_one, "EXPORTS", self.exports)):
            context = patch.object(module, name, value)
            context.start()
            self.addCleanup(context.stop)
        script = (Path(__file__).parent / "fixtures/fake_tools.py").read_text()
        executable = self.bin / "fake_tool"
        executable.write_text(f"#!{sys.executable}\n" + script.split("\n", 1)[1])
        executable.chmod(0o700)
        for name in ["rclone", *s3_upload.WALG_BINARIES.values()]:
            (self.bin / name).symlink_to(executable.name)
        self.config = {
            "cid": "cluster-one", "cluster_type": "postgresql",
            "source": {"endpoint": "https://storage.yandexcloud.net", "prefix": "s3://src/",
                       "access_key": "test-source-access", "secret_key": "test-source-secret", "region": "ru-central1"},
            "destination": {"endpoint": "https://destination.example", "prefix": "s3://dst/restored/",
                            "access_key": "test-destination-access", "secret_key": "test-destination-secret"},
            "gpg": {"key": "test-private-gpg-key", "key_id": "test-gpg-id"},
        }
        self.config_path = self.root / "config.json"
        self.state = self.root / "state"
        self.control = {"selected_objects": [
            "basebackups_005/base_new_backup_stop_sentinel.json",
            "basebackups_005/base_new/part.tar", "wal_005/history"]}
        self.write_control()
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def write_control(self):
        (self.root / "control.json").write_text(json.dumps(self.control))

    def seed_root(self, relative="wal-e/cluster-one/1400/"):
        root = self.root / "storage/src" / relative
        for name in [*self.control["selected_objects"],
                     "basebackups_005/base_old_backup_stop_sentinel.json", "basebackups_005/base_old/part.tar"]:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("fixture bytes for " + name).encode())
        return root

    def run_export(self, extra=(), engine="walg", write_config=True):
        self.write_control()
        if write_config:
            self.config_path.write_text(json.dumps(self.config))
        args = [str(self.config_path), "--rclone", str(self.bin / "rclone"), "--state-dir", str(self.state), *extra]
        if engine:
            args.extend(["--engine", engine])
        environment = {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
                       "AWS_ACCESS_KEY_ID": "inherited-secret", "WALG_S3_PREFIX": "s3://wrong/"}
        with patch.dict(os.environ, environment), contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return s3_upload.main(args)

    def calls(self, tool=None):
        path = self.root / "calls.jsonl"
        calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [call for call in calls if call["tool"] == tool] if tool else calls

    def report(self):
        return json.loads(next(self.state.glob("run-*/walg-result.json")).read_text())

    def test_all_walg_flavors_and_raw_destination_layout(self):
        for kind, binary in s3_upload.WALG_BINARIES.items():
            with self.subTest(kind=kind):
                self.config["cluster_type"] = kind
                if kind == "mongodb":
                    self.config["mongodb"] = {"admin_password": "test-mongo-password"}
                else:
                    self.config.pop("mongodb", None)
                self.seed_root()
                self.assertEqual(self.run_export(["-p", "3"]), 0, self.stderr.getvalue())
                calls = self.calls("walg")
                command = [call for call in calls if call["command"] == "copy"][-1]
                self.assertEqual(command["binary"], binary)
                self.assertEqual(command["args"][command["args"].index("--backup-name") + 1], "LATEST")
                self.assertEqual("--with-history" in command["args"], kind != "redis")
                self.assertEqual(command["destination_config"]["WALG_S3_PREFIX"],
                                 "s3://dst/restored/cluster-one/wal-e/cluster-one/1400/")
                for side in ("source_config", "destination_config"):
                    cfg = command[side]
                    self.assertEqual(cfg["AWS_S3_FORCE_PATH_STYLE"], "true")
                    self.assertEqual(cfg["WALG_UPLOAD_CONCURRENCY"], "3")
                    self.assertEqual(cfg["WALG_DOWNLOAD_CONCURRENCY"], "3")
                    self.assertFalse(any("PGP" in key for key in cfg))
                    self.assertEqual("MONGODB_URI" in cfg, kind == "mongodb")
                self.assertEqual(command["source_config"]["AWS_REGION"], "ru-central1")
                self.assertEqual(command["destination_config"]["AWS_REGION"], "us-east-1")
                self.assertEqual(command["config_mode"], 0o600)
                self.assertNotIn("AWS_ACCESS_KEY_ID", command["environment"])
                self.assertNotIn("WALG_S3_PREFIX", command["environment"])
                target = self.root / "storage/dst/restored/cluster-one/wal-e/cluster-one/1400"
                for name in self.control["selected_objects"]:
                    self.assertEqual((target / name).read_bytes(), (self.root / "storage/src/wal-e/cluster-one/1400" / name).read_bytes())
                self.assertFalse((target / "basebackups_005/base_old/part.tar").exists())
                metadata_path = next((self.root / "storage/dst/restored/cluster-one/__migration__").glob("config-*.json"))
                metadata = json.loads(metadata_path.read_text())
                self.assertEqual(metadata["gpg"], self.config["gpg"])
                self.assertNotIn("source", metadata)
                self.assertNotIn("destination", metadata)
                self.assertFalse(self.config_path.exists())
                self.assertEqual(self.report()["status"], "complete")
                self.assertFalse(list(self.state.glob("run-*/walg-*-source.json")))
                self.assertFalse(list(self.state.glob("run-*/rclone.conf")))
                shutil.rmtree(self.state)
                shutil.rmtree(self.root / "storage/dst")

    def test_discovery_multiple_roots_and_greenplum_pruning(self):
        self.config["cluster_type"] = "greenplum"
        first = self.seed_root("wal-e/cluster-one/6/")
        self.seed_root("wal-e/cluster-one/7/")
        self.seed_root("wal-e/cluster-one/6/segments_005/seg0/")
        self.seed_root("__migration__/ignored/")
        self.seed_root("orphan/segments_005/seg1/")
        self.assertEqual(self.run_export(), 0, self.stderr.getvalue())
        self.assertEqual([r["root"] for r in self.report()["roots"]],
                         ["wal-e/cluster-one/6/", "wal-e/cluster-one/7/"])
        self.assertEqual(len([c for c in self.calls("walg") if c["command"] == "copy"]), 2)
        self.assertTrue(first.exists())

    def test_exact_source_root_and_binary_override(self):
        self.seed_root()
        self.config["source"]["prefix"] += "wal-e/cluster-one/1400"
        self.config["destination"]["region"] = None
        self.assertEqual(self.run_export(["--walg", str(self.bin / "wal-g")]), 0, self.stderr.getvalue())
        self.assertEqual(self.calls("walg")[0]["destination_config"]["AWS_REGION"], "us-east-1")
        self.assertEqual(self.report()["roots"][0]["root"], "")
        self.assertTrue((self.root / "storage/dst/restored/cluster-one/basebackups_005/base_new/part.tar").exists())

    def test_copy_failure_redacts_and_retains_secrets_for_retry(self):
        self.seed_root()
        self.config["gpg"]["key"] = "private-key-header\nprivate-key-material\nprivate-key-footer"
        self.control.update(fail_copy=True, leak=[self.config["source"]["secret_key"], self.config["gpg"]["key"]])
        self.assertEqual(self.run_export(), 2)
        self.assertEqual(self.report()["roots"][0]["status"], "failed")
        self.assertTrue(self.config_path.exists())
        self.assertTrue(list(self.state.glob("run-*/walg-*-source.json")))
        self.assertFalse(list((self.root / "storage/dst").rglob("config-*.json")))
        logs = self.stdout.getvalue() + self.stderr.getvalue() + next(self.state.glob("run-*/run.log")).read_text()
        self.assertNotIn(self.config["source"]["secret_key"], logs)
        for line in self.config["gpg"]["key"].splitlines():
            self.assertNotIn(line, logs)
        self.control.pop("fail_copy")
        self.assertEqual(self.run_export(write_config=False), 0, self.stderr.getvalue())

    def test_bad_readback_never_publishes_metadata(self):
        self.seed_root()
        for output in ("[]", "null", "not json", "{}", "[null]", "[{}]"):
            with self.subTest(output=output):
                self.control["list_output"] = output
                self.assertEqual(self.run_export(), 2)
                self.assertEqual(self.report()["status"], "failed")
                self.assertTrue(self.config_path.exists())
                self.assertFalse(list((self.root / "storage/dst").rglob("config-*.json")))
                shutil.rmtree(self.state)
        self.control.pop("list_output")
        self.control["list_exit"] = True
        self.assertEqual(self.run_export(), 2)

    def test_metadata_failure_keeps_credentials(self):
        self.seed_root()
        for option in ("fail_metadata", "bad_metadata"):
            with self.subTest(option=option):
                self.control[option] = True
                self.assertEqual(self.run_export(), 2)
                self.assertEqual(self.report()["status"], "failed")
                self.assertEqual(self.report()["roots"][0]["status"], "complete")
                self.assertTrue(self.config_path.exists())
                self.control.pop(option)
                shutil.rmtree(self.state)

    def test_multiple_shards_stop_on_failure_and_leave_remaining_pending(self):
        self.config["cluster_type"] = "mongodb"
        self.config["mongodb"] = {"admin_password": "test-mongo-password"}
        for shard in ("shard-a", "shard-b", "shard-c"):
            self.seed_root(f"mongodb-backup/cluster-one/{shard}/")
        self.control["fail_root"] = "shard-b"
        self.assertEqual(self.run_export(), 2)
        self.assertEqual([root["status"] for root in self.report()["roots"]],
                         ["complete", "failed", "pending"])
        self.assertFalse(list((self.root / "storage/dst").rglob("config-*.json")))

    def test_no_roots_and_source_listing_failure(self):
        (self.root / "storage/src").mkdir(parents=True)
        self.assertEqual(self.run_export(), 2)
        self.assertIn("no WAL-G backup roots", self.report()["error"])
        self.assertFalse(self.calls("walg"))
        self.control["source_list_fail"] = True
        self.assertEqual(self.run_export(), 2)
        self.assertFalse(self.calls("walg"))

    def test_walg_cli_rejects_inapplicable_options_before_io(self):
        for args in (["--verify"], ["0", "2"], ["--fast-list"], ["--no-traverse"],
                     ["--max-errors", "100"], ["--stall-timeout", "28800"]):
            with self.subTest(args=args), self.assertRaises(SystemExit) as caught:
                self.run_export(args)
            self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.calls())
        self.assertFalse(self.state.exists())

    def test_blocklists_and_overlap_fail_before_subprocesses(self):
        self.config["source"]["prefix"] = f"s3://yandexcloud-dbaas-pg-{self.blocked[0].upper()}/"
        self.assertEqual(self.run_export(), 2)
        self.config["source"] = copy.deepcopy(self.config["destination"])
        self.assertEqual(self.run_export(), 2)
        self.assertFalse(self.calls())
        self.assertFalse(self.state.exists())

    def test_unsupported_type_and_missing_binary(self):
        self.config["cluster_type"] = "clickhouse"
        self.config["clickhouse"] = {"encryption_key": "clickhouse-secret"}
        self.assertEqual(self.run_export(), 2)
        self.config["cluster_type"] = "postgresql"
        self.assertEqual(self.run_export(["--walg", str(self.bin / "missing")]), 2)
        self.assertFalse(self.calls())
        self.assertFalse(self.state.exists())

    def test_default_rclone_still_copies_and_verifies_all_objects(self):
        self.seed_root()
        self.assertEqual(self.run_export(engine=None), 0, self.stderr.getvalue())
        self.assertFalse(self.calls("walg"))
        self.assertTrue((self.root / "storage/dst/restored/cluster-one/wal-e/cluster-one/1400/basebackups_005/base_old/part.tar").exists())
        report = json.loads(next(self.state.glob("run-*/verification.json")).read_text())
        self.assertEqual(report["missing_files"], [])
        self.assertEqual(report["size_mismatches"], [])

    def prepare_ticket(self, kind="postgresql"):
        all_in_one.prepare_export_dir("123")
        self.ticket = {"cluster_id": "cluster-one", "cluster_type": "managed-" + kind,
                       "s3_endpoint": "destination.example", "s3_bucket": "customer-bucket/prefix",
                       "s3_access_key_id": "ticket-access", "s3_secret_key": "ticket-secret"}
        (self.exports / "123/ticket.json").write_text(json.dumps(self.ticket))
        (self.sec / "all_in_one_config.json").write_text(json.dumps({
            "copernic_access_key": "copernic-access", "copernic_secret_key": "copernic-secret"}))

    def test_cli_config_cloud_and_mds_merge_preserve_original(self):
        for kind in ("postgresql", "clickhouse", "mongodb", "greenplum"):
            with self.subTest(kind=kind):
                self.prepare_ticket(kind)
                self.config["cluster_type"] = kind + "_cluster"
                self.config["destination"] = {"endpoint": "https://foo", "prefix": "s3://target-bucket/",
                                              "access_key": "...", "secret_key": "...", "region": "US"}
                if kind == "clickhouse":
                    self.config[kind] = {"encryption_key": "test-ch-key"}
                if kind == "mongodb":
                    self.config[kind] = {"admin_password": "test-mongo-password"}
                self.config_path.write_text(json.dumps(self.config))
                original = self.config_path.read_bytes()
                for source in ("mds", "yandexcloud"):
                    output = all_in_one.prepare_upload_config("123", source, self.config_path)
                    config = json.loads(output.read_text())
                    self.assertEqual(config["destination"]["secret_key"], "ticket-secret")
                    self.assertEqual(config["gpg"], self.config["gpg"])
                    self.assertEqual(config["cluster_type"], kind)
                    if kind in ("clickhouse", "mongodb"):
                        self.assertEqual(config[kind], self.config[kind])
                    if source == "yandexcloud":
                        self.assertEqual(config["source"], self.config["source"])
                    else:
                        self.assertEqual(config["source"]["prefix"], "s3://copernic-cp-cluster-one-backups/")
                        self.assertEqual(config["source"]["secret_key"], "copernic-secret")
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.config_path.read_bytes(), original)
                self.assertEqual((self.exports / "123").stat().st_mode & 0o777, 0o700)

    def test_ticket_identity_blocklist_and_original_file_checks(self):
        self.prepare_ticket()
        for change in ({"cid": "other"}, {"cluster_type": "mysql"}):
            self.config_path.write_text(json.dumps({**self.config, **change}))
            with self.assertRaisesRegex(ValueError, "must match"):
                all_in_one.prepare_upload_config("123", "yandexcloud", self.config_path)
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, "BLACKLISTED"):
            all_in_one.prepare_upload_config("123", "yandexcloud", self.config_path, {"cluster-one"})
        output = self.exports / "123/config.json"
        output.write_text(json.dumps(self.config))
        original = output.read_bytes()
        with self.assertRaisesRegex(ValueError, "separate"):
            all_in_one.prepare_upload_config("123", "yandexcloud", output)
        self.assertEqual(output.read_bytes(), original)

    def test_legacy_mds_and_missing_restore_fields(self):
        self.prepare_ticket()
        (self.sec / "gpg_keys.json").write_text(json.dumps({"cluster-one": {"gpg_key_id": "id", "data": "key"}}))
        output = all_in_one.prepare_upload_config("123")
        self.assertEqual(json.loads(output.read_text())["gpg"], {"key_id": "id", "key": "key"})
        self.prepare_ticket("mongodb")
        with self.assertRaisesRegex(ValueError, "supply restore fields using --source-config"):
            all_in_one.prepare_upload_config("123")

    def test_manual_cloud_flow_needs_no_copernic_or_gpg_file_and_passes_engine(self):
        self.config_path.write_text(json.dumps(self.config))
        answers = ["managed-postgresql", "destination.example", "customer-bucket",
                   "ticket-access", "ticket-secret", "cluster-one"]
        with patch("builtins.input", side_effect=answers), patch.object(all_in_one.subprocess, "check_call") as call:
            with contextlib.redirect_stdout(self.stdout):
                result = all_in_one.main(["123", "--manual", "--source", "yandexcloud",
                                          "--source-config", str(self.config_path), "--engine", "walg",
                                          "--walg", str(self.bin / "wal-g")])
        self.assertEqual(result, 0)
        call.assert_called_once_with(
            [sys.executable, str(all_in_one.REPO / "s3_upload.py"),
             str(self.exports / "123/config.json"), "--engine", "walg", "--walg", str(self.bin / "wal-g")],
            cwd=self.exports / "123")
        self.assertNotIn("ticket-secret", self.stdout.getvalue())
        self.assertEqual((self.exports / "123/ticket.json").stat().st_mode & 0o777, 0o600)

    def test_cloud_source_config_is_required_before_fetching_ticket(self):
        with patch.object(all_in_one, "get_ticket_info") as fetch:
            with contextlib.redirect_stderr(self.stderr), self.assertRaises(SystemExit) as caught:
                all_in_one.main(["123", "--source", "yandexcloud"])
        self.assertEqual(caught.exception.code, 2)
        fetch.assert_not_called()

    def test_missing_or_short_blocklist_refuses_run_before_dependencies(self):
        path = self.sec / "org_cids.csv"
        for content in (None, self.blocked[0] + "\n", (self.blocked[0] + "\n") * 10):
            if content is None:
                path.unlink()
            else:
                path.write_text(content)
            self.assertEqual(self.run_export(), 2)
        self.assertFalse(self.calls())
        self.assertFalse(self.state.exists())

    def test_blocklist_updater_can_embed_list_in_standalone_copy(self):
        source = self.root / "clusters.csv"
        source.write_text("cluster_id\n" + "\n".join(self.blocked))
        target = self.root / "standalone.py"
        shutil.copyfile(s3_upload.__file__, target)
        result = subprocess.run([sys.executable, "-B", str(all_in_one.REPO / "tools/update_blocked_cids.py"),
                                 str(source), str(target)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.config["destination"]["prefix"] = f"s3://dbaas-{self.blocked[0]}/"
        self.config_path.write_text(json.dumps(self.config))
        result = subprocess.run([sys.executable, "-B", str(target), str(self.config_path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("do-not-copy list", result.stderr)

    def test_help_and_import_do_not_read_local_secrets(self):
        repo = str(Path(s3_upload.__file__).parent)
        for command in ([sys.executable, "-B", "-c", "import all_in_one, s3_upload"],
                        [sys.executable, "-B", "all_in_one.py", "--help"],
                        [sys.executable, "-B", "s3_upload.py", "--help"]):
            result = subprocess.run(command, cwd=repo, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_interrupt_kills_walg_process_group_and_records_failure(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum):
                self.check_interruption(signum)
                shutil.rmtree(self.state)
                (self.root / "ready.json").unlink()
                (self.root / "heartbeat").unlink()

    def check_interruption(self, signum):
        self.seed_root()
        self.control["slow_copy"] = True
        self.write_control()
        self.config_path.write_text(json.dumps(self.config))
        wrapper = "import sys, s3_upload; s3_upload.SEC = sys.argv[1]; sys.exit(s3_upload.main(sys.argv[2:]))"
        command = [sys.executable, "-B", "-c", wrapper, str(self.sec), str(self.config_path),
                   "--engine", "walg", "--walg", str(self.bin / "wal-g"),
                   "--rclone", str(self.bin / "rclone"), "--state-dir", str(self.state)]
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(command, stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 15
                while not (self.root / "heartbeat").exists() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                self.assertTrue((self.root / "ready.json").exists(), "stub did not start")
                self.assertTrue((self.root / "heartbeat").exists(), "stub child did not start")
                pids = json.loads((self.root / "ready.json").read_text())
                process.send_signal(signum)
                self.assertEqual(process.wait(timeout=10), 130)
                self.assertEqual(self.report()["status"], "interrupted")
                self.assertTrue(self.config_path.exists())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pids["parent"], 0)
                heartbeat = (self.root / "heartbeat").read_bytes()
                time.sleep(0.2)
                self.assertEqual((self.root / "heartbeat").read_bytes(), heartbeat,
                                 "the WAL-G child is still running after interruption")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if (self.root / "ready.json").exists():
                    for pid in json.loads((self.root / "ready.json").read_text()).values():
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
