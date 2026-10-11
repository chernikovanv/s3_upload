#!/usr/bin/env python3
"""Copy S3 objects: python3 copy_s3_shard.py config.json [A B] [-p 10].

S3 provides LastModified, not the original creation time of an object.
"""

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


def now():
    return datetime.now(timezone.utc)


def required(obj, key, parent):
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{parent}.{key} must be a non-empty string")
    return value


def prefix(value, name):
    parsed = urlsplit(value)
    if parsed.scheme != "s3" or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError(f"{name} must be s3://bucket/optional/prefix/")
    return value.rstrip("/") + "/"


def endpoint(value, name):
    if "\n" in value or "\r" in value:
        raise ValueError(f"{name} must not contain newlines")
    parsed = urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or parsed.username or parsed.password):
        raise ValueError(f"{name} must be http(s)://host[:port] without a path")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} has an invalid port") from exc
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    if port and port != (443 if parsed.scheme == "https" else 80):
        host += f":{port}"
    return parsed.scheme, host


def read_config(path):
    with path.open(encoding="utf-8") as stream:
        config = json.load(stream)
    if not isinstance(config, dict):
        raise ValueError("JSON root must be an object")
    cid = required(config, "cid", "config")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", cid):
        raise ValueError("config.cid must be one folder name using letters, digits, '.', '_' or '-'")
    for side in ("source", "destination"):
        item = config.get(side)
        if not isinstance(item, dict):
            raise ValueError(f"{side} must be an object")
        for key in ("endpoint", "prefix", "access_key", "secret_key"):
            required(item, key, side)
        endpoint(item["endpoint"], f"{side}.endpoint")
        prefix(item["prefix"], f"{side}.prefix")
        region = item.get("region")
        if region is not None and (not isinstance(region, str) or not region
                                   or any(c.isspace() for c in region)):
            raise ValueError(f"{side}.region must be a non-empty string if present")
        if "path_style" in item:
            raise ValueError(f"{side}.path_style is unsupported; path style is always used")
        if any("\n" in item[key] or "\r" in item[key]
               for key in ("access_key", "secret_key")):
            raise ValueError(f"{side} credentials must not contain newlines")

    kind = required(config, "cluster_type", "config")
    gpg = config.get("gpg")
    if not isinstance(gpg, dict):
        raise ValueError("gpg must be an object")
    if "key_base64" in gpg:
        required(gpg, "key_base64", "gpg")
    else:
        required(gpg, "key", "gpg")
        required(gpg, "key_id", "gpg")
    if "passphrase" in gpg:
        required(gpg, "passphrase", "gpg")
    if kind in ("clickhouse", "mongodb"):
        item = config.get(kind)
        if not isinstance(item, dict):
            raise ValueError(f"{kind} must be an object")
        required(item, "encryption_key" if kind == "clickhouse" else "admin_password", kind)

    src = prefix(config["source"]["prefix"], "source.prefix")
    dst = prefix(config["destination"]["prefix"], "destination.prefix") + cid + "/"
    if endpoint(config["source"]["endpoint"], "source.endpoint") == endpoint(
            config["destination"]["endpoint"], "destination.endpoint"):
        if src.startswith(dst) or dst.startswith(src):
            raise ValueError("source and destination prefixes overlap on the same endpoint")

    return config


def atomic_write(path, data):
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def make_rclone_config(path, config):
    lines = []
    for name in ("source", "destination"):
        item = config[name]
        lines.extend([f"[{name}]", "type = s3", "provider = Other",
                      "env_auth = false", f"access_key_id = {item['access_key']}",
                      f"secret_access_key = {item['secret_key']}",
                      f"endpoint = {item['endpoint']}", "force_path_style = true",
                      "no_check_bucket = true"])
        if name == "destination":
            # rclone otherwise copies the source S3 storage class (e.g. ICE)
            # into PutObject, which another provider may reject.
            lines.append("storage_class = STANDARD")
        if item.get("region"):
            lines.append(f"region = {item['region']}")
        lines.append("")
    atomic_write(path, ("\n".join(lines) + "\n").encode("utf-8"))


def remote_path(uri, remote):
    if not uri.startswith("s3://"):
        raise ValueError(f"expected S3 URI: {uri}")
    return f"{remote}:{uri[5:]}"


class HumanLog:
    def __init__(self, console, stream, level):
        self.console = console
        self.stream = stream
        self.level = level
        self.pending = ""

    def record(self, message):
        for line in message.splitlines():
            self.stream.write(f"{now().isoformat()} [{self.level}] {line}\n")
        self.stream.flush()

    def write(self, text):
        self.console.write(text)
        self.pending += text
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            self.record(line)
        return len(text)

    def flush(self):
        self.console.flush()
        self.stream.flush()

    def finish(self):
        if self.pending:
            self.record(self.pending)
            self.pending = ""
        self.flush()


def attach_run_log(stack, run_dir):
    path = run_dir / "run.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    stream = stack.enter_context(os.fdopen(fd, "a", encoding="utf-8"))
    stdout = HumanLog(sys.stdout, stream, "INFO")
    stderr = HumanLog(sys.stderr, stream, "ERROR")
    stack.enter_context(redirect_stdout(stdout))
    stack.enter_context(redirect_stderr(stderr))
    stack.callback(stdout.finish)
    stack.callback(stderr.finish)
    print(f"Log: {path.resolve()}", flush=True)
    print("State files: operations.log — operation attempts; "
          "pass-N-rclone.jsonl — raw copy logs; progress.txt — latest progress; "
          "skipped_500.jsonl — skipped source GET errors; "
          "failed.jsonl and verification.json — final reports", flush=True)


def operation_log(cfg, message):
    line = f"{now().isoformat()} {message}"
    print(line, flush=True)
    path = cfg.parent / "operations.log"
    with path.open("a", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(line + "\n")


def retry_operation(cfg, label, action):
    for attempt in range(1, 4):
        started = time.monotonic()
        operation_log(cfg, f"START [{attempt}/3] {label}")
        try:
            result = action()
        except RuntimeError as exc:
            operation_log(cfg, f"ERROR [{attempt}/3] {label}; "
                          f"elapsed={time.monotonic() - started:.1f}s\n{exc}")
            transient = re.search(
                r"StatusCode: (?:429|500|502|503|504)\b|InternalError|"
                r"ServiceUnavailable|SlowDown|TooManyRequests|"
                r"connection reset|connection timed out|i/o timeout|unexpected EOF",
                str(exc), re.IGNORECASE)
            if not transient or attempt == 3:
                raise RuntimeError(f"{label}: {exc}; log: {cfg.parent / 'operations.log'}") from exc
            delay = 5 * 2 ** (attempt - 1)
            operation_log(cfg, f"RETRY {label} in {delay}s")
            time.sleep(delay)
        else:
            operation_log(cfg, f"OK {label}; elapsed={time.monotonic() - started:.1f}s")
            return result


def rclone(binary, cfg, *args, output_path=None):
    return retry_operation(cfg, " ".join(map(str, args)),
                           lambda: rclone_once(binary, cfg, *args, output_path=output_path))


def rclone_once(binary, cfg, *args, output_path=None):
    command = [binary, "--config", str(cfg), *args]
    with tempfile.TemporaryFile() as stderr:
        if output_path is None:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=stderr)
            output = result.stdout.decode("utf-8", "replace")
        else:
            with output_path.open("wb") as stdout:
                result = subprocess.run(command, stdout=stdout, stderr=stderr)
            output = ""
        if result.returncode:
            stderr.seek(0)
            error = stderr.read().decode("utf-8", "replace").strip()
            raise RuntimeError((error or output.strip() or
                                f"rclone exited {result.returncode}")[-8000:])
    return output


def rclone_cat_size(binary, cfg, uri):
    return retry_operation(cfg, f"source GET {uri}",
                           lambda: rclone_cat_size_once(binary, cfg, uri))


def rclone_cat_size_once(binary, cfg, uri):
    command = [binary, "--config", str(cfg), "cat", remote_path(uri, "source")]
    size = 0
    with tempfile.TemporaryFile() as stderr:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr) as process:
            while chunk := process.stdout.read(1024 * 1024):
                size += len(chunk)
            returncode = process.wait()
        if returncode:
            stderr.seek(0)
            error = stderr.read().decode("utf-8", "replace").strip()
            raise RuntimeError((error or f"rclone cat exited {returncode}")[-8000:])
    return size


def lsjson_items(stream, name):
    """Read rclone's array one item at a time, including pretty-printed items."""
    pending = ""
    first_line = 0
    opened = False
    closed = False
    for line_number, line in enumerate(stream, 1):
        stripped = line.strip()
        if not stripped:
            continue
        if closed:
            raise ValueError(f"{name} listing has data after the JSON array")
        if not opened:
            if not stripped.startswith("["):
                raise ValueError(f"{name} listing must be a JSON array")
            opened = True
            if stripped == "[":
                continue
        elif not pending and stripped == "]":
            closed = True
            continue
        if not pending:
            first_line = line_number
        pending += line
        candidate = pending.strip()
        if candidate.endswith(","):
            candidate = candidate[:-1].rstrip()
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            yield from ((first_line, item) for item in parsed)
            closed = True
        else:
            yield first_line, parsed
        pending = ""
    if pending.strip() or not opened or not closed:
        raise ValueError(f"{name} listing has invalid JSON starting at line {first_line}")


def parse_rclone_time(value):
    # Go's RFC3339Nano permits nine fractional digits; older Python versions
    # accept fewer. Round sub-microsecond values up so the cutoff stays strict.
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
        value)
    if not match:
        raise ValueError("not an RFC3339 timestamp")
    base, fraction, zone = match.groups()
    fraction = fraction or ""
    micros = fraction[:6].ljust(6, "0")
    offset = "+00:00" if zone == "Z" else zone
    result = datetime.fromisoformat(f"{base}.{micros}{offset}")
    if any(digit != "0" for digit in fraction[6:]):
        result += timedelta(microseconds=1)
    return result.astimezone(timezone.utc)


def list_shard(binary, cfg, base, a, b, run_dir, name, snapshot=False,
               unfiltered=False):
    fd, filename = tempfile.mkstemp(prefix=f".{name}-", dir=run_dir)
    os.close(fd)
    listing = Path(filename)
    found = {}
    try:
        flags = ("--use-server-modtime",) if name == "source" else ("--no-modtime",)
        hash_filter = () if unfiltered else ("--hash-filter", f"{a}/{b}")
        rclone(binary, cfg, "lsjson", remote_path(base, name), "--recursive",
               "--files-only", "--no-mimetype", *flags, *hash_filter,
               output_path=listing)
        with listing.open(encoding="utf-8") as stream:
            for line_number, item in lsjson_items(stream, name):
                if not isinstance(item, dict) or not isinstance(item.get("Path"), str):
                    raise ValueError(f"{name} listing line {line_number} has no Path")
                key = item["Path"]
                if not key or key.endswith("/"):
                    continue
                size = item.get("Size")
                if type(size) is not int or size < 0:
                    raise ValueError(f"{name} listing line {line_number} has no valid Size")
                record = {"key": key, "uri": base + key, "size": size}
                if name == "source":
                    timestamp = item.get("ModTime")
                    if not isinstance(timestamp, str) or not timestamp:
                        raise ValueError(f"{name} listing line {line_number} has no ModTime")
                    try:
                        modified = parse_rclone_time(timestamp)
                    except ValueError as exc:
                        shown = json.dumps(timestamp[:120], ensure_ascii=False)
                        raise ValueError(f"{name} listing line {line_number} has invalid "
                                         f"ModTime {shown}: {exc}") from exc
                    record["modified_minute"] = modified
                found[key] = record
        if snapshot:
            shutil.copyfile(listing, run_dir / "initial_source_listing.json")
        return found
    finally:
        listing.unlink(missing_ok=True)


def eligible(record, cutoff):
    return record["modified_minute"] <= cutoff


def source_get_500(error):
    return bool(re.search(r"StatusCode:\s*500\b", str(error))
                and "GetObject" in str(error))


def skip_source_object(run_dir, skipped, record, error, stage):
    key = record["key"]
    if key in skipped:
        return
    item = {"source": record["uri"], "key": key, "stage": stage,
            "error": str(error), "time": now().isoformat()}
    skipped[key] = item
    path = run_dir / "skipped_500.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"SKIPPED source GET 500: {record['uri']}; details: {path}",
          file=sys.stderr, flush=True)


def copy_batch(binary, cfg, src_prefix, dst_prefix, records, parallel, run_dir, attempt,
               completed=0, total=None, skipped=None):
    # files-from0 overrides hash-filter. Its input comes only from a shard-filtered
    # listing, so rclone's native hash function defines the shard for every pass.
    file_list = run_dir / f"pass-{attempt}-files.bin"
    atomic_write(file_list, b"".join(record["key"].encode("utf-8") + b"\0"
                                      for record in records))
    command = [binary, "--config", str(cfg), "copy",
               remote_path(src_prefix, "source"), remote_path(dst_prefix, "destination"),
               "--files-from0", str(file_list), "--size-only",
               "--transfers", str(parallel), "--checkers", str(max(4, parallel)),
               "--retries", "1", "--use-json-log", "--stats", "10s",
               "--stats-log-level", "NOTICE"]
    log = run_dir / f"pass-{attempt}-rclone.jsonl"
    errors = []
    skipped = {} if skipped is None else skipped
    records_by_key = {record["key"]: record for record in records}
    total = len(records) + completed if total is None else total
    last_transferred = 0
    with log.open("w", encoding="utf-8") as saved:
        os.chmod(log, 0o600)
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              text=True, encoding="utf-8", errors="replace") as process:
            for line in process.stderr:
                saved.write(line)
                saved.flush()
                try:
                    event = json.loads(line)
                except ValueError:
                    event = {"level": "error", "msg": line.strip()}
                stats = event.get("stats") or {}
                transferred = stats.get("transfers")
                if type(transferred) is int:
                    last_transferred = max(last_transferred, transferred)
                    done = min(total, completed + last_transferred)
                    speed = stats.get("speed", 0) / (1024 * 1024)
                    progress = (f"Pass {attempt}/3 | Present by size: {done}/{total} | "
                                f"Remaining: {total - done} | "
                                f"Speed: {speed:.2f} MiB/s | Errors: {stats.get('errors', 0)}")
                    print(progress, flush=True)
                    atomic_write(run_dir / "progress.txt", (progress + "\n").encode())
                if str(event.get("level", "")).lower() in ("error", "fatal"):
                    message = event.get("msg", line.strip())
                    errors.append(str(message))
                    key = event.get("object")
                    if source_get_500(message) and key in records_by_key:
                        skip_source_object(run_dir, skipped, records_by_key[key],
                                           message, f"copy pass {attempt}")
                    print(f"ERROR [{attempt}/3] {message}", file=sys.stderr, flush=True)
            returncode = process.wait()
    if returncode:
        raise RuntimeError(f"rclone copy exited {returncode}; "
                           f"details: {log}; last error: {(errors[-1] if errors else 'unknown')[-1000:]}")
    return last_transferred


def missing_ranges(records):
    """Merge discrepant objects when successive LastModified minutes are < 1 hour apart."""
    ordered = sorted(records, key=lambda record: record["modified_minute"])
    ranges = []
    for record in ordered:
        moment = record["modified_minute"]
        if ranges and moment - ranges[-1]["end"] < timedelta(hours=1):
            ranges[-1]["end"] = moment
            ranges[-1]["count"] += 1
        else:
            ranges.append({"start": moment, "end": moment, "count": 1})
    return ranges


def format_range(item):
    start, end = item["start"], item["end"]
    if start.date() == end.date():
        return f"{start:%Y-%m-%d %H:%M}-{end:%H:%M}"
    return f"{start:%Y-%m-%d %H:%M}-{end:%Y-%m-%d %H:%M}"


def validate_source(binary, cfg, records, run_dir, skipped=None):
    """Stream the smallest object in this shard to test GET without staging it."""
    if not records:
        print("Source LS: OK; shard is empty, so GET cannot be checked", flush=True)
        return
    record = min(records.values(), key=lambda item: item["size"])
    operation_log(cfg, f"Source GET probe: {record['uri']}; expected size={record['size']} bytes")
    try:
        size = rclone_cat_size(binary, cfg, record["uri"])
    except RuntimeError as exc:
        if not source_get_500(exc):
            raise
        skip_source_object(run_dir, {} if skipped is None else skipped,
                           record, exc, "source GET probe")
        return False
    if size != record["size"]:
        raise RuntimeError(f"source GET returned {size} bytes for {record['uri']}; "
                           f"listing reported {record['size']}")
    return True


def validate_destination(binary, cfg, dest_prefix, run_dir):
    """Test PUT, GET and exact-key LS, then delete the remote probe."""
    probe_uri = dest_prefix + "__migration__/credential-check-" + secrets.token_hex(16)
    payload = secrets.token_bytes(32)
    fd, filename = tempfile.mkstemp(prefix=".credential-check-upload-", dir=run_dir)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
    upload = Path(filename)
    fd, filename = tempfile.mkstemp(prefix=".credential-check-download-", dir=run_dir)
    os.close(fd)
    download = Path(filename)
    put_attempted = False
    check_error = None
    cleanup_error = None
    try:
        put_attempted = True
        rclone(binary, cfg, "copyto", str(upload),
               remote_path(probe_uri, "destination"), "--ignore-times")
        rclone(binary, cfg, "copyto", remote_path(probe_uri, "destination"),
               str(download), "--ignore-times")
        if download.read_bytes() != payload:
            raise RuntimeError("destination GET returned different content")
        folder, name = probe_uri.rsplit("/", 1)
        listing = rclone(binary, cfg, "lsjson", remote_path(folder + "/", "destination"),
                         "--files-only", "--no-modtime", "--no-mimetype")
        if not any(item.get("Path") == name for item in json.loads(listing)):
            raise RuntimeError(f"destination LS did not show {probe_uri}")
    except (OSError, RuntimeError, ValueError) as exc:
        check_error = exc
    finally:
        if put_attempted:
            try:
                rclone(binary, cfg, "deletefile", remote_path(probe_uri, "destination"))
            except (OSError, RuntimeError, ValueError) as exc:
                cleanup_error = exc
        upload.unlink(missing_ok=True)
        download.unlink(missing_ok=True)
    if check_error and cleanup_error:
        raise RuntimeError(f"{check_error}; probe deletion failed: {cleanup_error}")
    if check_error:
        raise check_error
    if cleanup_error:
        raise RuntimeError(f"probe deletion failed: {cleanup_error}")


def upload_metadata(binary, cfg, local, remote, run_dir):
    rclone(binary, cfg, "copyto", str(local), remote_path(remote, "destination"),
           "--ignore-times")
    fd, filename = tempfile.mkstemp(prefix=".metadata-check-", dir=run_dir)
    os.close(fd)
    download = Path(filename)
    try:
        rclone(binary, cfg, "copyto", remote_path(remote, "destination"),
               str(download), "--ignore-times")
        if download.read_bytes() != local.read_bytes():
            raise RuntimeError(f"uploaded metadata differs from {local}")
    finally:
        download.unlink(missing_ok=True)


def verify(args, run_dir, cfg, dst_prefix, source, destination=None):
    if destination is None:
        destination = list_shard(args.rclone, cfg, dst_prefix, args.a, args.b,
                                 run_dir, "destination")
    missing = [source[key] for key in source.keys() - destination.keys()]
    wrong_size = [(source[key], destination[key])
                  for key in source.keys() & destination.keys()
                  if source[key]["size"] != destination[key]["size"]]
    ranges = missing_ranges(missing + [record for record, _ in wrong_size])
    report = run_dir / "verification.json"
    data = {
        "shard": {"a": args.a, "b": args.b},
        "source_files": len(source),
        "missing_files": [
            {"source": record["uri"], "destination": dst_prefix + record["key"],
             "last_modified": record["modified_minute"].isoformat()}
            for record in sorted(missing, key=lambda item: item["modified_minute"])
        ],
        "size_mismatches": [
            {"source": record["uri"], "destination": target["uri"],
             "source_size": record["size"], "destination_size": target["size"],
             "last_modified": record["modified_minute"].isoformat()}
            for record, target in sorted(wrong_size,
                                         key=lambda pair: pair[0]["modified_minute"])
        ],
        "ranges": [
            {"start": item["start"].isoformat(), "end": item["end"].isoformat(),
             "count": item["count"]}
            for item in ranges
        ],
    }
    atomic_write(report, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode())
    print(f"Checked shard {args.a}/{args.b}: {len(source)} source files, "
          f"{len(missing)} missing, {len(wrong_size)} with different size. "
          f"Report: {report}", flush=True)
    if ranges:
        print("Discrepancy time ranges (UTC):", flush=True)
    for item in ranges:
        print(format_range(item), flush=True)
    return 1 if missing or wrong_size else 0


def cleanup_local_secrets(*paths):
    errors = []
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise RuntimeError("verification passed, but credential cleanup failed: " +
                           "; ".join(errors))


def run(args, started):
    with ExitStack() as stack:
        try:
            result = run_impl(args, started, stack)
        except (OSError, ValueError, RuntimeError) as exc:
            if isinstance(sys.stderr, HumanLog):
                sys.stderr.record(f"FATAL: {exc}")
            raise
        except KeyboardInterrupt:
            print("Interrupted by user", file=sys.stderr, flush=True)
            raise
        else:
            print(f"Run finished: exit={result}; "
                  f"{'verification passed' if result == 0 else 'verification found discrepancies'}",
                  flush=True)
            return result


def run_impl(args, started, stack):
    config = read_config(args.config)
    src_prefix = prefix(config["source"]["prefix"], "source.prefix")
    dst_prefix = prefix(config["destination"]["prefix"], "destination.prefix") + config["cid"] + "/"
    cutoff = started + timedelta(minutes=10)
    state_dir = args.state_dir or Path(f"copy_s3_state_{config['cid']}")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    stamp = started.strftime("%Y%m%dT%H%M%S%fZ")
    run_dir = state_dir / f"run-{stamp}-{args.a}-of-{args.b}-{os.getpid()}"
    run_dir.mkdir(mode=0o700)
    attach_run_log(stack, run_dir)
    print(f"Run directory: {run_dir.resolve()}", flush=True)
    cfg = run_dir / "rclone.conf"
    make_rclone_config(cfg, config)
    metadata = {key: value for key, value in config.items()
                if key not in ("source", "destination")}
    metadata_file = run_dir / "destination_config.json"
    atomic_write(metadata_file,
                 (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    metadata_uri = dst_prefix + f"__migration__/config-{stamp}-{args.a}-of-{args.b}.json"
    print(f"Checking source LS under {src_prefix}", flush=True)
    rclone(args.rclone, cfg, "lsjson", remote_path(src_prefix, "source"),
           "--files-only", "--no-modtime", "--no-mimetype",
           output_path=Path(os.devnull))
    print("Source LS: OK", flush=True)
    print(f"Checking destination PUT, GET, LS and cleanup under {dst_prefix}", flush=True)
    validate_destination(args.rclone, cfg, dst_prefix, run_dir)
    print("Destination PUT, GET, LS and cleanup: OK", flush=True)
    print(f"Listing source shard under {src_prefix}", flush=True)
    initial_source = list_shard(args.rclone, cfg, src_prefix, args.a, args.b,
                                run_dir, "source", snapshot=True)
    print(f"Source listing: {len(initial_source)} objects", flush=True)
    source_probe = initial_source
    if not source_probe:
        # An empty shard is valid. Check the unfiltered source only for prefix
        # existence and a GET probe; do not include its files in this shard.
        source_probe = list_shard(args.rclone, cfg, src_prefix, args.a, args.b,
                                  run_dir, "source", unfiltered=True)
        if not source_probe:
            raise RuntimeError(f"source prefix {src_prefix} contains no files; check the prefix")
    skipped = {}
    if validate_source(args.rclone, cfg, source_probe, run_dir, skipped):
        print("Source GET: OK", flush=True)
    else:
        print("Source GET probe returned 500; continuing with other objects", flush=True)
    if args.verify:
        result = verify(args, run_dir, cfg, dst_prefix, initial_source)
        if result == 0:
            cleanup_local_secrets(args.config, cfg, metadata_file)
        return result
    upload_metadata(args.rclone, cfg, metadata_file, metadata_uri, run_dir)
    print(f"Started: {started.isoformat()}; cutoff: {cutoff.isoformat()}", flush=True)
    print(f"Shard: {args.a}/{args.b}; metadata: {metadata_uri}", flush=True)

    discovered = {key: record for key, record in initial_source.items()
                  if eligible(record, cutoff)}
    copy_errors = {}
    for attempt in range(1, 4):
        print(f"Pass {attempt}/3: listing source and destination", flush=True)
        try:
            current = (initial_source if attempt == 1 else
                       list_shard(args.rclone, cfg, src_prefix, args.a, args.b,
                                  run_dir, "source"))
            target = list_shard(args.rclone, cfg, dst_prefix, args.a, args.b,
                                run_dir, "destination")
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"ERROR [{attempt}/3] listing: {exc}", file=sys.stderr, flush=True)
            continue
        current = {key: record for key, record in current.items()
                   if eligible(record, cutoff)}
        discovered.update(current)
        candidates = [record for key, record in current.items()
                      if key not in skipped
                      and (key not in target or target[key]["size"] != record["size"])]

        completed = sum(key in target and record["size"] == target[key]["size"]
                        for key, record in discovered.items())
        progress = (f"Pass {attempt}/3 | Present by size: {completed}/{len(discovered)} | "
                    f"Remaining: {len(discovered) - completed}")
        print(progress, flush=True)
        atomic_write(run_dir / "progress.txt", (progress + "\n").encode())
        if not candidates:
            print(f"Pass {attempt}/3: nothing to copy", flush=True)
            continue
        print(f"Pass {attempt}/3: {len(candidates)} objects to copy", flush=True)
        try:
            copy_batch(args.rclone, cfg, src_prefix, dst_prefix, candidates,
                       args.parallel, run_dir, attempt, completed, len(discovered), skipped)
        except (OSError, RuntimeError, ValueError) as exc:
            copy_errors[attempt] = str(exc)
            print(f"ERROR [{attempt}/3] {exc}", file=sys.stderr, flush=True)

    final_source = list_shard(args.rclone, cfg, src_prefix, args.a, args.b,
                              run_dir, "source")
    discovered.update({key: record for key, record in final_source.items()
                       if eligible(record, cutoff)})
    final_target = list_shard(args.rclone, cfg, dst_prefix, args.a, args.b,
                              run_dir, "destination")
    present = {key for key, record in discovered.items()
               if key in final_target and final_target[key]["size"] == record["size"]}
    missing = []
    for key in sorted(set(discovered) - present):
        record = discovered[key]
        target = final_target.get(key)
        if key in skipped:
            error = "source GET 500; skipped in this run: " + skipped[key]["error"]
        elif target:
            error = (f"size mismatch: source {record['size']} bytes, "
                     f"destination {target['size']} bytes")
        else:
            error = ("no longer in source" if key not in final_source else
                     "not copied; see pass logs" if copy_errors else "not copied")
        missing.append({"source": record["uri"], "destination": dst_prefix + key,
                        "error": error})
    report = run_dir / "failed.jsonl"
    atomic_write(report, "".join(json.dumps(item, ensure_ascii=False) + "\n"
                                 for item in missing).encode("utf-8"))
    print(f"Checked {len(discovered)} eligible files in shard {args.a}/{args.b}. "
          f"Missing or wrong size: {len(missing)}. "
          f"Report: {report}", flush=True)
    for item in missing:
        print(f"FAILED {item['source']} -> {item['destination']}: {item['error']}",
              file=sys.stderr)
    progress = (f"Finished | Present by size: {len(present)}/{len(discovered)} | "
                f"Remaining: {len(missing)}")
    print(progress, flush=True)
    atomic_write(run_dir / "progress.txt", (progress + "\n").encode())
    result = verify(args, run_dir, cfg, dst_prefix, discovered, final_target)
    if result == 0:
        cleanup_local_secrets(args.config, cfg, metadata_file)
    return result


def ensure_rclone(binary):
    if shutil.which(binary):
        return
    if binary != "rclone":
        raise RuntimeError(f"rclone executable was not found: {binary}")
    apt_get = shutil.which("apt-get")
    if not apt_get:
        raise RuntimeError("rclone was not found and apt-get is unavailable")
    privilege = []
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            raise RuntimeError("installing rclone requires root or passwordless sudo")
        privilege = [sudo, "-n"]
    print("rclone was not found; installing with apt-get", flush=True)
    environment = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    try:
        subprocess.run([*privilege, apt_get, "update"], check=True, env=environment)
        subprocess.run([*privilege, apt_get, "install", "-y", "rclone"],
                       check=True, env=environment)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"rclone installation failed (exit {exc.returncode})") from exc
    if not shutil.which(binary):
        raise RuntimeError("apt-get completed, but rclone is still not in PATH")


def main():
    started = now()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="JSON config file")
    parser.add_argument("a", nargs="?", type=int, default=0, help="shard remainder (default: 0)")
    parser.add_argument("b", nargs="?", type=int, default=1, help="number of shards (default: 1)")
    parser.add_argument("-p", "--parallel", type=int, default=10)
    parser.add_argument("--verify", action="store_true",
                        help="only compare this shard and report time ranges of missing files")
    parser.add_argument("--state-dir", type=Path,
                        help="state directory (default: copy_s3_state_<cid>)")
    parser.add_argument("--rclone", default="rclone", help="rclone executable")
    args = parser.parse_args()
    if args.b <= 0 or not 0 <= args.a < args.b:
        parser.error("require b > 0 and 0 <= a < b")
    if args.parallel <= 0:
        parser.error("require -p > 0")
    try:
        ensure_rclone(args.rclone)
        return run(args, started)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())