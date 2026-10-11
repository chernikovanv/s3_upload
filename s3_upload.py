#!/usr/bin/env python3
"""Copy S3 objects: python3 copy_s3_shard.py config.json [A B] [-p 10].

S3 provides LastModified, not the original creation time of an object.
"""

import argparse
import json
import os
import queue
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
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


def bucket(value):
    return urlsplit(value).netloc


def blocked_cids_in(name):
    """Cluster ids from the do-not-copy list that occur in this bucket name.

    BLOCKED_CIDS is embedded at the bottom of this file so the protection cannot
    be lost by copying the script without a sidecar list.
    """
    lowered = name.lower()
    windows = {lowered[start:start + size]
               for size in BLOCKED_CID_LENGTHS
               for start in range(len(lowered) - size + 1)}
    return sorted(windows & BLOCKED_CIDS)


def check_not_blocked(config):
    for side in ("source", "destination"):
        name = bucket(config[side]["prefix"])
        found = blocked_cids_in(name)
        if found:
            raise ValueError(
                f"refusing to run: {side} bucket {name!r} belongs to a cluster on "
                f"the do-not-copy list ({', '.join(found)})")


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

    check_not_blocked(config)

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
          "skipped.jsonl — unreadable source objects; "
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
               unfiltered=False, fast_list=False):
    fd, filename = tempfile.mkstemp(prefix=f".{name}-", dir=run_dir)
    os.close(fd)
    listing = Path(filename)
    found = {}
    try:
        flags = ("--use-server-modtime",) if name == "source" else ("--no-modtime",)
        hash_filter = () if unfiltered else ("--hash-filter", f"{a}/{b}")
        recursive = ("--fast-list",) if fast_list else ()
        rclone(binary, cfg, "lsjson", remote_path(base, name), "--recursive",
               "--files-only", "--no-mimetype", *flags, *hash_filter, *recursive,
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


def optional_json(key):
    """Sidecar JSON such as metadata.json or *_backup_stop_sentinel.json.

    Some sources fail to serve these small objects. Report them, but never abort
    the run over one; the bulk data is what matters.
    """
    return key.lower().endswith(".json")


def skip_reason(key, error):
    """Why this object may be skipped instead of failing the run, or None."""
    if source_get_500(error):
        return "source GET 500"
    if optional_json(key):
        return "unreadable JSON"
    return None


def skip_source_object(run_dir, skipped, record, error, stage, reason):
    key = record["key"]
    if key in skipped:
        return
    item = {"source": record["uri"], "key": key, "stage": stage, "reason": reason,
            "error": str(error), "time": now().isoformat()}
    skipped[key] = item
    path = run_dir / "skipped.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"SKIPPED {reason}: {record['uri']}; details: {path}",
          file=sys.stderr, flush=True)


# How long a copy pass may transfer nothing before a flood of errors is taken
# as a broken source rather than one slow object.
ZERO_PROGRESS_GRACE = 120


def pump(stream, lines):
    """Feed a subprocess stream into a queue so the reader can time out."""
    try:
        for line in stream:
            lines.put(line)
    except (OSError, ValueError):
        pass
    finally:
        lines.put(None)


def kill_group(process):
    """Kill rclone and anything it spawned.

    Killing only rclone would leave a child holding the write end of the pipe,
    so the reader thread would never see EOF and closing the stream would then
    deadlock against the read it is blocked in.
    """
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        process.kill()


def copy_batch(binary, cfg, src_prefix, dst_prefix, records, parallel, run_dir, attempt,
               completed=0, total=None, skipped=None, no_traverse=False,
               stall_timeout=300, max_errors=100):
    # files-from0 overrides hash-filter. Its input comes only from a shard-filtered
    # listing, so rclone's native hash function defines the shard for every pass.
    file_list = run_dir / f"pass-{attempt}-files.bin"
    atomic_write(file_list, b"".join(record["key"].encode("utf-8") + b"\0"
                                      for record in records))
    # rclone traverses the destination even with --files-from0, so a resumed run
    # pays for a second full listing per pass. --no-traverse replaces that with
    # roughly one lookup per listed file: cheaper only when the remaining set is
    # small next to the destination (see --no-traverse in the README).
    traverse = ("--no-traverse",) if no_traverse else ()
    command = [binary, "--config", str(cfg), "copy",
               remote_path(src_prefix, "source"), remote_path(dst_prefix, "destination"),
               "--files-from0", str(file_list), "--size-only", *traverse,
               "--transfers", str(parallel), "--checkers", str(max(4, parallel)),
               "--retries", "1", "--use-json-log", "--stats", "10s",
               "--stats-log-level", "NOTICE"]
    log = run_dir / f"pass-{attempt}-rclone.jsonl"
    errors = []
    unskipped = []
    skipped = {} if skipped is None else skipped
    records_by_key = {record["key"]: record for record in records}
    total = len(records) + completed if total is None else total
    last_transferred = 0
    aborted = None
    started = time.monotonic()
    with log.open("w", encoding="utf-8") as saved:
        os.chmod(log, 0o600)
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              text=True, encoding="utf-8", errors="replace",
                              start_new_session=True) as process:
            lines = queue.Queue()
            reader = threading.Thread(target=pump, args=(process.stderr, lines),
                                      daemon=True)
            reader.start()
            while True:
                try:
                    # --stats 10s makes rclone print continuously while it lives,
                    # so a long silence means it is wedged rather than slow.
                    line = lines.get(timeout=stall_timeout)
                except queue.Empty:
                    aborted = (f"no output for {stall_timeout}s while --stats 10s "
                               f"should be printing; rclone was killed")
                    break
                except KeyboardInterrupt:
                    # rclone runs in its own session, so Ctrl-C does not reach it.
                    kill_group(process)
                    process.wait()
                    raise
                if line is None:
                    break
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
                    record = records_by_key.get(key) if isinstance(key, str) else None
                    reason = skip_reason(key, message) if record else None
                    if reason:
                        skip_source_object(run_dir, skipped, record, message,
                                           f"copy pass {attempt}", reason)
                    else:
                        unskipped.append(str(message))
                    print(f"ERROR [{attempt}/3] {message}", file=sys.stderr, flush=True)
                    # A failing source errors on every object slowly, so letting the
                    # pass run to completion takes days. Stop once it is clear the
                    # source is broken: either many errors nothing can skip past, or
                    # many errors of any kind with nothing transferring at all. The
                    # grace period keeps a slow first large file from tripping it.
                    stuck = (len(errors) >= max_errors and not last_transferred
                             and time.monotonic() - started > ZERO_PROGRESS_GRACE)
                    if max_errors and (len(unskipped) >= max_errors or stuck):
                        aborted = (f"{len(errors)} errors ({len(unskipped)} not "
                                   f"skippable) after {last_transferred} objects "
                                   f"transferred; rclone was killed rather than "
                                   f"working through the remaining "
                                   f"{len(records) - last_transferred} objects")
                        break
            if aborted:
                kill_group(process)
            returncode = process.wait()
            # Let the reader drain before the stream is closed underneath it.
            reader.join(timeout=30)
    if aborted:
        raise RuntimeError(f"rclone copy aborted: {aborted}; details: {log}; "
                           f"last error: {(errors[-1] if errors else 'none')[-1000:]}")
    if returncode:
        # A non-zero exit caused only by skippable source reads is not a pass failure:
        # those objects are already recorded and excluded from the remaining passes.
        if unskipped or not errors:
            raise RuntimeError(f"rclone copy exited {returncode}; "
                               f"details: {log}; last error: {(errors[-1] if errors else 'unknown')[-1000:]}")
        print(f"Pass {attempt}/3: rclone exited {returncode}; all {len(errors)} errors "
              f"were skippable source reads; continuing", flush=True)
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


def validate_source(binary, cfg, records, run_dir, skipped=None, attempts=5):
    """Stream the smallest readable object in this shard to test GET without staging it.

    The smallest object is usually a sidecar JSON, so a source that cannot serve
    those would otherwise fail the probe and abort a run whose bulk data is fine.
    Skippable objects are recorded and the next smallest one is probed instead.
    """
    if not records:
        print("Source LS: OK; shard is empty, so GET cannot be checked", flush=True)
        return None
    skipped = {} if skipped is None else skipped
    candidates = sorted(records.values(), key=lambda item: item["size"])
    for record in candidates[:attempts]:
        operation_log(cfg, f"Source GET probe: {record['uri']}; "
                      f"expected size={record['size']} bytes")
        try:
            size = rclone_cat_size(binary, cfg, record["uri"])
            if size != record["size"]:
                raise RuntimeError(f"source GET returned {size} bytes for {record['uri']}; "
                                   f"listing reported {record['size']}")
        except RuntimeError as exc:
            reason = skip_reason(record["key"], exc)
            if not reason:
                raise
            skip_source_object(run_dir, skipped, record, exc, "source GET probe", reason)
            continue
        return True
    return False


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


def verify(args, run_dir, cfg, dst_prefix, source, destination=None, skipped=None):
    if destination is None:
        destination = list_shard(args.rclone, cfg, dst_prefix, args.a, args.b,
                                 run_dir, "destination", fast_list=args.fast_list)
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
        # Unreadable at the source, so they stay counted above as discrepancies.
        "skipped_source_reads": [
            {"source": item["source"], "reason": item["reason"],
             "stage": item["stage"], "error": item["error"]}
            for item in sorted((skipped or {}).values(),
                               key=lambda item: item["source"])
        ],
    }
    atomic_write(report, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode())
    print(f"Checked shard {args.a}/{args.b}: {len(source)} source files, "
          f"{len(missing)} missing, {len(wrong_size)} with different size. "
          f"Report: {report}", flush=True)
    if skipped:
        print(f"Unreadable at the source and still counted above: {len(skipped)}",
              flush=True)
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
                                run_dir, "source", snapshot=True,
                                fast_list=args.fast_list)
    print(f"Source listing: {len(initial_source)} objects", flush=True)
    source_probe = initial_source
    if not source_probe:
        # An empty shard is valid. Check the unfiltered source only for prefix
        # existence and a GET probe; do not include its files in this shard.
        source_probe = list_shard(args.rclone, cfg, src_prefix, args.a, args.b,
                                  run_dir, "source", unfiltered=True,
                                  fast_list=args.fast_list)
        if not source_probe:
            raise RuntimeError(f"source prefix {src_prefix} contains no files; check the prefix")
    skipped = {}
    if validate_source(args.rclone, cfg, source_probe, run_dir, skipped):
        print("Source GET: OK", flush=True)
    else:
        print("Source GET probe could not read any of the smallest objects; "
              "continuing with the rest of the shard", flush=True)
    if args.verify:
        result = verify(args, run_dir, cfg, dst_prefix, initial_source, skipped=skipped)
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
                                  run_dir, "source", fast_list=args.fast_list))
            target = list_shard(args.rclone, cfg, dst_prefix, args.a, args.b,
                                run_dir, "destination", fast_list=args.fast_list)
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
            # Everything eligible is already at the destination. Further passes
            # would only re-list both sides, which is the expensive part on a
            # large bucket; the final reconciliation below still re-checks.
            print(f"Pass {attempt}/3: nothing to copy; skipping remaining passes",
                  flush=True)
            break
        print(f"Pass {attempt}/3: {len(candidates)} objects to copy", flush=True)
        try:
            copy_batch(args.rclone, cfg, src_prefix, dst_prefix, candidates,
                       args.parallel, run_dir, attempt, completed, len(discovered),
                       skipped, args.no_traverse, args.stall_timeout, args.max_errors)
        except (OSError, RuntimeError, ValueError) as exc:
            copy_errors[attempt] = str(exc)
            print(f"ERROR [{attempt}/3] {exc}", file=sys.stderr, flush=True)

    final_source = list_shard(args.rclone, cfg, src_prefix, args.a, args.b,
                              run_dir, "source", fast_list=args.fast_list)
    discovered.update({key: record for key, record in final_source.items()
                       if eligible(record, cutoff)})
    final_target = list_shard(args.rclone, cfg, dst_prefix, args.a, args.b,
                              run_dir, "destination", fast_list=args.fast_list)
    present = {key for key, record in discovered.items()
               if key in final_target and final_target[key]["size"] == record["size"]}
    missing = []
    for key in sorted(set(discovered) - present):
        record = discovered[key]
        target = final_target.get(key)
        if key in skipped:
            error = (f"{skipped[key]['reason']}; skipped in this run: "
                     f"{skipped[key]['error']}")
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
    result = verify(args, run_dir, cfg, dst_prefix, discovered, final_target, skipped)
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


# Clusters that must never be copied. A run is refused when any of these ids
# occurs in the source or destination bucket name. Regenerate from a clusters
# CSV export with: python3 tools/update_blocked_cids.py clusters-prod.csv
# BEGIN BLOCKED CIDS
BLOCKED_CIDS = frozenset("""
c9q00git8mmr2mt99uk4    c9q01lr73n0boofe1ssg    c9q01ovrpqat1iefto6m
c9q03d18bhck4t1arv32    c9q03i8mned4nrttuvl0    c9q047j5hdhm32jr3mfa
c9q04i8odn3pbrd8802d    c9q05ef27ora6uvf6kbb    c9q05el53lhoo9tabe8s
c9q05h7t0i20tfrosruc    c9q064gcjih23f1cb5uq    c9q06g94cqd50oui25jr
c9q06gnr2n89sl2oc6ju    c9q07hr2hgd4et2rlp3v    c9q07o3sneeu93nqa5cp
c9q08bkeglt49hckv2fi    c9q08dlrfeb2chm1leic    c9q08qm0hp4ft2caekot
c9q09jcf7bf42ur5ohvn    c9q09vuemoi345s2ebq2    c9q0bahldt8rchkcj49b
c9q0bc1dmeimji76g902    c9q0bd8umeavnnunheug    c9q0bnu41eqfj8aangtf
c9q0ceda3tdf259igh06    c9q0ckvvlj6rj2di6r19    c9q0d0o7u502lofbiglg
c9q0del07tnq1el9laok    c9q0efpvoji1ao6g2mt0    c9q0fj048f5618evo8dc
c9q0h6jp3k4leajk3hb4    c9q0h8d5mcsgl4pkhhr5    c9q0h9bnak5n6ggsucoc
c9q0hdtrup3phtb0sndj    c9q0hqd68r0afmn31nr1    c9q0jtcmljcc3h5n2t62
c9q0ju2egn23bsjnretl    c9q0k479jv0bv4g3emub    c9q0ks9sd43ogb5cfheu
c9q0lj0r0fk15r21v8ub    c9q0lu6k9v6v0tj5a5n7    c9q0m043kshb08i14cov
c9q0nbughl5l40c7n7gs    c9q0nmc4f8ve6ne98urh    c9q0o5u0ueulcfcec560
c9q0oej4h6eetmt00u8r    c9q0omvgh2lpm5104tid    c9q0pej0b5j4caebg03r
c9q0ppneqa70cb4ls4vk    c9q0q9d9v0ah1e6ksq5r    c9q0q9gme5jsmd6blke9
c9q0rlri6118ct9o7eju    c9q0sm4fv6ssl4gt1ast    c9q0sro6p7tst56c14s5
c9q0u03ahk1uga86rrcn    c9q0u103cdftfqkep9n9    c9q0uaqs7tjduho7ujao
c9q0udqdij78ga527bgd    c9q0uhvj2bjv7os7v50a    c9q11u6efoibi98ku9e6
c9q132n68nn2rq7adf0t    c9q135svd53v21ei15ck    c9q136l95taqmgs47t7i
c9q157a307alill133ee    c9q158b55d3v4g5r9bb0    c9q16ci9b1sk64ksh7uu
c9q16g0n2ru678dikgea    c9q18qqecdj2kr8hqsee    c9q18raluemrtssfcuoc
c9q1aig2n3eo3mgn3foq    c9q1b9td80jbvo3iguej    c9q1bldsqih9kt24fk0q
c9q1bmr4mtmr7prlkpp5    c9q1bsfsrd05c1i23nld    c9q1c12apggevcj59vtf
c9q1cbnemgo9p2aubjpj    c9q1di8ritk3npuf9fe8    c9q1e1hde44c29uoj2h7
c9q1e6r0rr1m9cnl6raq    c9q1ffvdorkeekkmucau    c9q1fg34h6bmi4bmtrk8
c9q1figardd63oag4gge    c9q1gj7i17l7ogf8tghb    c9q1i11dhlt0g9o4a75o
c9q1im2tkduqvr4b29qo    c9q1j5cl753u8ikg1fc9    c9q1j5hcaasm01dit153
c9q1j9k9jf8k5fghnhoj    c9q1kclmjuloe3b9k3hp    c9q1klkj3kfum0i4mu0c
c9q1l4vf1blo7m19jvli    c9q1nfhd57psbgcal70r    c9q1omobes6h1t4bmm5b
c9q1pvi4fnrm2vkprur8    c9q1rf18qpu1c31hegc4    c9q1ruj216ksffcbu64q
c9q1sbk8n4the96jhl3h    c9q1spdne6ul899lkq8j    c9q1t65od1cfm09003k0
c9q1te505m75ch9r6mrt    c9q20489ltp3ul2eo5c3    c9q22om9i9c15lh12anv
c9q2431gf4ln6rq48e7s    c9q2570r4s9jlb4nl2f9    c9q25cvpsm3um82soibt
c9q25eo4dl98c7vn2pdc    c9q26ukqovlhet209q2m    c9q2725afn5u7nqtba5i
c9q276liigsv0b3jsj0m    c9q27uijno8a36d22tcn    c9q2820qcst3qoo78g4l
c9q28t3tndaig416ing6    c9q2908cpkuijd4t77tg    c9q2a8prm2vfo6mnr82o
c9q2b8neg6ru7dmhljdf    c9q2cegp24lnf7drsmuu    c9q2cl4jhubr48r4q2hv
c9q2ebmfksjvk6id6bi4    c9q2g7af30183fasj5fu    c9q2gsmue7tnadki8k84
c9q2j9orolpi7cmteifv    c9q2kuf99ilo23buaumk    c9q2l5voi3cvcto8k49d
c9q2ljotf8hfqgb78dk1    c9q2ls65u5bq8jfra11p    c9q2manssuu0m4podi34
c9q2me6mjmhl5eqmjmal    c9q2oes4qc45bh9s965s    c9q2ofu9p5t0188h8qbh
c9q2ohfs29t1k32i4sl1    c9q2oj4vbq8mji7jodot    c9q2p63k46c2fi090m5l
c9q2p7pj79go9lmh5l4i    c9q2ptkbmrq8dd9rlk9d    c9q2q1lj3tv0gfdc9etn
c9q2qm60mr5qh0ku2o7t    c9q2r4836oukci7n9k9d    c9q2rb6at1mveusp0l6g
c9q2rfmmbh3i4u0uo4h8    c9q2rnp1t5vjl7mpg7r9    c9q2spohc5vf4n2m4r7o
c9q2t5avedi3b64ag84v    c9q2tu7m9isuvege65is    c9q2ujvj1tg3di5di9f0
c9q2ustnds4lug16jr81    c9q30f8eeoggdng6tbkk    c9q30p2mkim24m7es16e
c9q3254j5ktlbva6dlbu    c9q33tosqhndmjpvtpgk    c9q34k2chddrem9q92u7
c9q34tub2e5eges4bfnf    c9q35ahtfir2m0lq7i55    c9q35jhp0019p5etp539
c9q35noi22a357nuv112    c9q36hr8caceam4p7ddk    c9q382rnaj6r8pe78s1q
c9q38ckrjrr8mm4fp6sa    c9q38ml8i1o8iur5vknl    c9q39sgjkmgk6ehmv62c
c9q3aulkpp67r2q976r0    c9q3b4g4k2614kuqhkbb    c9q3c490rsi6h96i9keg
c9q3d5shm4hc848n56c4    c9q3dnrannbntkr9vmaa    c9q3e3md8g8q1r1h09o8
c9q3ebuh74hhoanph3ib    c9q3ed638tpk3m8ck5a9    c9q3eppt2ps81js2ktu2
c9q3foh6qfeso4d4bre6    c9q3fqa8rffn57md0crp    c9q3gqalcj4uk6otfl77
c9q3h3reutlfjcmo0b0p    c9q3h6epcipmqp6dbbkr    c9q3hd2qb8cdr6r7il7a
c9q3heg9i6norgu1nqag    c9q3hmlsrpgld0gr4gbb    c9q3hvu0qr6cctplbf07
c9q3ibv3dl94lfcdb4u3    c9q3il6lrma6cpji966u    c9q3jhuobb10v5q6nvn1
c9q3jksi8sc4p7ig02s8    c9q3k726le4du2g3bbbe    c9q3lonn5ssqi0ehvcm5
c9q3ls0fk568i8ea1vjm    c9q3m1k01e4mh5k5o2r5    c9q3m9ritu543gi8hln7
c9q3mtn19ilkkd07ihtn    c9q3n2rk9ga1912d17m8    c9q3nc2lul039ca1jkf5
c9q3nonl0ljr1naedmpj    c9q3ofc2ofnpnf919pt5    c9q3pvcue1a181rp0rc3
c9q3qfnt633ov17repe8    c9q3qksfg5oe3mducbfc    c9q3r25j3e0niq434d2m
c9q3roitvlgm35rn7b3c    c9q3rvbafsngkh168bv9    c9q3sa4k52n4fvvdne80
c9q3svprkici6ke397ge    c9q3tgujtg5i9542f0he    c9q3ti7jkemchbg29232
c9q3v5qhldp2jepudgns    c9q3vjsi1e89m0jsj73g    c9q3vn32audh8kp71mds
c9q404p7npt2q3mob4cd    c9q40aut1qonf9q2nku3    c9q40dd35rgbk74311ad
c9q429ipjo8skskhup1m    c9q42s2j5f2vvas70fje    c9q42t6h15mu7s4r5d63
c9q43ac1i6fhvrqerotu    c9q44b7od29tgvm416pg    c9q44ifdpscjrr0rho27
c9q46h8qoe19rab39u2q    c9q471enfsdrvhi5jmlf    c9q486gs6msi3kn03dc2
c9q48clgndpsa9oue77k    c9q48k4tn7l39n14ogf7    c9q4954kgobt44n4v7l2
c9q49fb28onnns7upse1    c9q4akbtjqek8al9ssu1    c9q4c6privk46sgbn869
c9q4cd93e9ii466fejig    c9q4dc1l75uj24ttt7s8    c9q4dgb7ueghplti65md
c9q4eq1agvb93pir79j2    c9q4f7778mvgh9tov016    c9q4g6arj8j733lmj7dc
c9q4g7sd0240enli56jo    c9q4gblkniuek1v6s1i8    c9q4gbq7d3d1vtd167ok
c9q4ghipcjg48u2schcc    c9q4iarsej9909oiludj    c9q4j040shg51loukinl
c9q4j4al3sg7m35c3lpu    c9q4jfe2af3ij8cuudhq    c9q4jl51k1q4ptq42u14
c9q4k5g33a0e8r55ehll    c9q4k9vmn3fot7e1e64q    c9q4mk3mksfg1urt6n33
c9q4mr1ujsrpccpome6n    c9q4o62r3v88i64slr3p    c9q4p9r89ejd943sih4b
c9q4pgkq39vfj8j1p3p8    c9q4q9eom1lpatp6j6be    c9q4qfcc4l0btcif5v1q
c9q4sa19kal8i3eg7olb    c9q4t1iialm43pjf4j7b    c9q4t4u24mhc0qqhhgl1
c9q4t5kst2qtn3j9aigt    c9q4tr3psicm9lapjknh    c9q4tvna79o64l8062dj
c9q4uin7qbmcj97kta48    c9q4ujnhq2dl61g6pjcj    c9q4vl4s0pj3rh5en8i5
c9q500h8ovb852bf3aqp    c9q50dnopq1qqfshbava    c9q50jonps5i8abirm25
c9q514bdfk9nop479s47    c9q5183jhg63ujucjcik    c9q51pthjhai2sd756ph
c9q52iq3ri03i92am3s0    c9q52llv7qk4a70f1h1o    c9q53f56ifjji9dn1on8
c9q53he1oq9i629bs0tn    c9q5493emduukeprkhpn    c9q55e6dtoh2mdn5jkgn
c9q56154bn17u8mpuulq    c9q56prhctv0hm96dejm    c9q57eduujr5q2mp1qn5
c9q591gc51jo65oqcj8t    c9q5agfhh5lc5bfsd5t5    c9q5aij85ghfk6qv8oe2
c9q5aked8p4jtb2krpjt    c9q5ch8gemboqt2u8mdk    c9q5dvpail2p5qugi1d4
c9q5e4aqhkq010rheg0n    c9q5fdlv9b9ct8qr8rts    c9q5feo1fcc4e4rgdeag
c9q5fluth6c0p5qpon63    c9q5fnh7l88go3hjh20r    c9q5gjfh3h8itishrsem
c9q5ha0pktiq459ksru7    c9q5hih46g3u6gdmgnok    c9q5jhfenfm5honr3t8t
c9q5jr5nq8h86q30jp9j    c9q5k0s006bn13papgfa    c9q5k8cegtteuhd5i4bl
c9q5ki799ip9pru947qv    c9q5mbm4anr9uqpbf1fk    c9q5ms69voi1fdsvggvc
c9q5n6pmkdj5ng117g1m    c9q5nbpg2tnj3alvjhkf    c9q5ngrllrmfcj3qtlhf
c9q5pm7n8r9v0ob3p1q1    c9q5r5mq4pv9am76otpi    c9q5sech9bs7rmt6ecmv
c9q5tmodaf1d6tt82jk0    c9q5tpnvfhopequgsti8    c9q5tsuvens946ohmrbi
c9q5tt4c9coefng2afvb    c9q5udem7lt7560qfngp    c9q5ulmrcgcmdp2qef5e
c9q5uvvrn3jt134iefcb    c9q5v7h3fh45lds43kgp    c9q60s1rfbg32u30q85d
c9q630h1nluirlsek3nd    c9q63goli8f4secojs8s    c9q63mdm8ta9p8b25onm
c9q64ioa0jsfddc9bie1    c9q64ostt266rgumfgea    c9q6534qam3i5cj179dj
c9q65fr84lu295u0nl38    c9q65o6lbpuuuakpg02h    c9q6620bql8mm57d1bnl
c9q662jt2f7tvub0um36    c9q6651h9qsen0s6snce    c9q66iv8q36d6j6us5ku
c9q66mejddhd213vddpc    c9q67i21gqu8gc63vo2m    c9q68fr15t9ugkppsg05
c9q6927injk0t8n89ak3    c9q69da2im5nhvqpsjpn    c9q69hk7931u2gvfscpc
c9q6afso5jd3pm7gt0vs    c9q6amgf42uhf26kbbra    c9q6ap83htkp4i79aek1
c9q6b1rcdq2b4keg1dfn    c9q6ccmq9vebcng2gim3    c9q6e7r76a1v2drnbvle
c9q6ebs57umimpu5nhaa    c9q6gnbkbpcm4reo0n0i    c9q6hb1ap8qg937b6lig
c9q6hdjr1r6n12pjuuqk    c9q6iia45f6q7bckp1vq    c9q6ipqorl5a8dv9jeq9
c9q6j3h9361l0hpc0289    c9q6j86sdf7s4juv105f    c9q6jgjrrn7d15em4139
c9q6jpqlgvsiutk7p35u    c9q6k7po2ss06pfpj0ii    c9q6ko4lro9pu7unqodo
c9q6lbd0bbmk3gmbfu26    c9q6lbso5ud5l5rr2seq    c9q6llqvgcpk6ufudone
c9q6mi17902bmop8a7rk    c9q6mnc12l4o96no2tg6    c9q6mrnqupgthciffk4p
c9q6n9ac49oasgssfodd    c9q6nkq7giq1ft87m7hn    c9q6opmu8tkoru0uie9i
c9q6p4hto189bupkjsr7    c9q6pnu6263n2qlntreo    c9q6pr28p3943r979ns1
c9q6pvb7t9dgic727pl8    c9q6q2s8fkd742l96vn6    c9q6qojo8al1ssjutefi
c9q6qu8dvqs7htils2nm    c9q6qvtn2kgq3krdkvie    c9q6ri29g9s107u5rv42
c9q6tld0afsa5d0kh4bj    c9q6u32capntdgph1vd9    c9q6umrqvjseeisn73d5
c9q6unbu0bvv6tdbhbn6    c9q6v361nbr9tq32rahp    c9q6vg3v9afnh3e11l9r
c9q70kdt4abj25bm75fl    c9q70rjes7b6qomm312i    c9q719h59luqd8n880oc
c9q71jq6npnb7cm2p324    c9q720pg2rtfn89a2166    c9q72d0qg35sdjel8nub
c9q72j8jldkvv1ejibui    c9q72mccpq047j79l27p    c9q73296tdvojp2bfdce
c9q73jo2rror7r303s6h    c9q73rilketq2tjtcune    c9q742mcitqk2klvlv5m
c9q746qm24sjsulpro8s    c9q761p4barkcsi5fme5    c9q76p1s2itlpjqbfg99
c9q77tuppbmbgkms1ban    c9q7829o2o0kb7vu7lq6    c9q78j2hl5n7eq8v8efl
c9q7996072ch2bjbcugf    c9q79g8vn5nq3kvm4i3c    c9q7bev0t1cak3vhh6kc
c9q7bqjcqjvklbd0l67v    c9q7c5ibbkf7vl65h94t    c9q7clg3c5p6ck0grjr1
c9q7e8osle5obndpm09a    c9q7fq7mfplt817loots    c9q7gphqinro2thgo1mk
c9q7ho1su0p3dfkeqloi    c9q7hoe89mibnp6t7nvi    c9q7ikaelrtkcnvkb89m
c9q7j283jvsn7lgs7119    c9q7k9u07bdntapvd0hs    c9q7krq338gmnt9np8j4
c9q7ktccf7dgjq0e0k73    c9q7lcuog89t3bv6qkl1    c9q7lofjgm00acihevci
c9q7mi6826juru840unq    c9q7n29iuqfrg389jj5b    c9q7n369s3mjs0t2gnvp
c9q7oe4vnrvmig190jjr    c9q7ogjs7mks09ohqns9    c9q7oqagi81obn4en77v
c9q7p40t8gi9ckqedpb1    c9q7pcgp56dedeea3ofn    c9q7pl21eskt31pv9a04
c9q7q4pcv4egn3er0h22    c9q7qdrodijd099dg4l1    c9q7qoanvsds5gvnc26n
c9q7suep5004fuc6hqut    c9q7t87mpmdlufq80a5b    c9q7tqto2svs0m45qip0
c9q7u0bf7q0dc52tm1d0    c9q7udq657ppo3lq36i1    c9q7vrkmbb1clmd6b4os
c9q7vsqiquji7ch1rmh6    c9q7vuuoiqmlij9qsajb    c9q801akoldd72n3m75b
c9q80ah45tfv30kdaidf    c9q80gdi6tgflfaq2696    c9q81o5bub0pfdsoqoqs
c9q83anddjmogh1n35f0    c9q83b7fu14bqihs3uqs    c9q84k2hv6dkmbs2s7ci
c9q85kovn8810ip12sp4    c9q860f9gvq6askhn9bd    c9q860r68hp7igm7eqm4
c9q88mm61bv7qt7b390g    c9q88uhflpit7emss5cv    c9q89gofa6bhr9o85eav
c9q8a4bnd62q9kabjip9    c9q8c11c9m09c2iflbsc    c9q8d81uopqjoeu5pq8n
c9q8dkg7ecfhlbl98vhu    c9q8e9r08gt7ds2109t7    c9q8eg0hlm5bjsd09rck
c9q8evmc2pomgi18740d    c9q8f9detq1fi0jiejcp    c9q8fcqgc8fcgsjelrib
c9q8fd7ffrl5b7c0fksc    c9q8fl28jk0aaj1s0etd    c9q8fqifl6fl8276dp5t
c9q8h539kbhpqnt1pfee    c9q8i0m75t9hu3jst6nn    c9q8jnmos1rptr4rslpa
c9q8l70htmo86s9oudoq    c9q8leo6mthrd4drhhbc    c9q8m3h306otmmmmvosh
c9q8mson3k382qgb0nlm    c9q8nh026q1j1hu6d52l    c9q8ojbdrvt2ls3gc6hf
c9q8or8jdavne7qop98n    c9q8ptdgb4699rdm0d7v    c9q8puofh1hm2ec88cfe
c9q8qfqrj1ateukskagm    c9q8qopu92cm8qpudio5    c9q8rhil9mdlv1713obq
c9q8se8iik3skhsgge7g    c9q8sibi1kp7fgspkp21    c9q8ta9eeb0a4o2fd7hm
c9q8tcku36554ih7hud6    c9q8tk0gj1dl5t56j7dp    c9q8ufe29mgkmsv0gu22
c9q8uh4rura70klmu06i    c9q8v7ahp6gtcrulvi40    c9q9095dq6bsahcmvuba
c9q90so849oqjhst9fr9    c9q910kksh9m4plj1ikv    c9q918l4ptbhb11au4uh
c9q924cap3oh0krdl888    c9q92m4dn4rvut76qapp    c9q93ujpgsftq7lt3spf
c9q948jlfosq88ls2a65    c9q94b43e3q928cap73c    c9q94h484j8d9uaapsv2
c9q94og3p7p6i0hnfqhg    c9q966fisdp955kkohpf    c9q969lnqa3v3dgsc544
c9q96bsd2rbh6glfjcre    c9q9811l4511agug17i6    c9q987da428ik1vl0jdi
c9q98gvc0kt97ms27kt1    c9q9a06t9f5dga5bue7k    c9q9aktvebeba60nkl3c
c9q9albi5i3v3mqsoecm    c9q9ao1d86rs7h4roj63    c9q9b2d0ta96fhmqq7ih
c9q9bfufjadloae3a85b    c9q9co1f7b0ga0c070vc    c9q9cpormjqtjuc6d05j
c9q9djqleqtct1mhg4qf    c9q9dkc0vvmv7v5jre2t    c9q9dqik4cv2sa5u9r95
c9q9ec676j964f35n8or    c9q9f10caug6fiu4hc94    c9q9fbob7hv386t9n9m7
c9q9gi4312v2u46n4m42    c9q9h113amptvim2kc66    c9q9h9vlqivfav0q1g6i
c9q9i9t8u1a2181p6v26    c9q9jvnn88l1hq13359c    c9q9k19nsr594e1pcri1
c9q9kg3i1pcfcb57eid1    c9q9l1lbcgktnrn2kgcr    c9q9l6bjccuaai0f0jv1
c9q9lnn8q1uj21517dj5    c9q9m3sj5vhrmtkvjjgq    c9q9mp4dtta26utl1baf
c9q9mpq0a52iq3hp0jvp    c9q9nodob4u9ddokkf04    c9q9o8g6delfr8ki77qo
c9q9pl5kdrac44qji63i    c9q9ppbprdsbffen79jk    c9q9qnsvpl1at3gf2rck
c9q9tc3sbec3b9vrois9    c9q9uhg5ipiqtgb543ho    c9q9v7daaldu0o22uir3
c9qa07jvfk16spm40lpu    c9qa0l575h66t7d1qp3v    c9qa0m5ku3al4hs5h2mv
c9qa10ccplqlol075tdn    c9qa1b0n7isfp67j7qt6    c9qa1lgharb58cmm6h9c
c9qa1plu79agn2htcs00    c9qa1qrphmv9js6bjjgo    c9qa2ukkrd3ti98iaptk
c9qa32in2iimqoh24c5j    c9qa3hqef4p9vbvb8899    c9qa5itvomnmmmib3qcr
c9qa5vabd16ugfphmtfi    c9qa6rrltn95evnml5j5    c9qa76msbcgls9nb8nb4
c9qa81tfd1vfnrckcpf2    c9qa91tjri2ksq7rb3dk    c9qa9k8lipdn8qh8an1t
c9qaab2ckdp802kqfrb0    c9qaaqbkgl3ig1660gs7    c9qabhs8iifsngj3u7g2
c9qacg2j10kt03fjgnpe    c9qackm4gaeaf3ipm7b5    c9qacvvf4scka7dstdhe
c9qadtiml8a0pplj0mq1    c9qae18i7uvku1vhakfm    c9qae1rn1i1vjeth8cgo
c9qae4qm556m7iqhsf4e    c9qaf68r5vbc7b2v4uif    c9qafc6rd8o15ov677i0
c9qafcs0qe18314tg5ak    c9qai4pblgsb58dqbokf    c9qajsoebdtu7f72dhg2
c9qak2lssd25jhqbpe86    c9qakshp70rqltfga9gl    c9qalb3qal9v1j7fuq77
c9qan3f02utta2lhkmu2    c9qan6kb128ujdpd2636    c9qaq35cmpvkdjf5bnkl
c9qarbcnbvdr1j0u65gq    c9qaruvfufe6pil7eub7    c9qasfmu32hjkh34370v
c9qasg6k37qqosqdqn8f    c9qashg5gmgg0lu4639e    c9qasui6tonea61v5d0s
c9qat2n2qpbuh75v5k9t    c9qatp8npncm2eih7kvp    c9qatpiovoobp59id40m
c9qav3ik6so8v2h7cnls    c9qav7joqeh5m1quv54u    c9qb05ge8ctcmr2ig0mp
c9qb2dp56d7bg4qto8qu    c9qb2qnvebm3agtasl2j    c9qb38ve1r17ot6re5qo
c9qb3h1ll36j3pm4se0q    c9qb43ocvsncfttj7e0u    c9qb49ssd878geri3dhc
c9qb4via4abv2hmesdks    c9qb5ntablnab0f98kln    c9qb6gg0p6pjc7j7bfor
c9qb6i6o8fkjqb46ks34    c9qb6svo8qkb269u5k17    c9qb717s1rcbshlgacll
c9qb724srgchpuh7ba9n    c9qb7791svtia36p5i4o    c9qb798u5vb5j8lbcjlh
c9qb85pai839n8i19qvd    c9qb8m8rp0a719ece9a5    c9qb8v0s7gkp3p935g7r
c9qba69d6ah1fg9oo85f    c9qba6fvgcgv39nnbsut    c9qbb32okfd1i9hfv9n6
c9qbcgvpc6nci0dlt4ah    c9qbdc6jtffj30tdq5m2    c9qbdmopfljs9sl3s3ci
c9qbfg3ag5kotur8j83j    c9qbfj5qms7k7vet97c2    c9qbg76lnn0m5ab45rka
c9qbj29ragnrg03as2vh    c9qbk93i5uckdok33ila    c9qbliqjv94f393pec9m
c9qbmb6vqr4865uf5i81    c9qbmg9v8dp5s0d85o6q    c9qbn7tc8blk7i84cflp
c9qbnhhu3gdk5g7or0l1    c9qbojppcufv3dgpkeg3    c9qbolkuoltgq33m9c7l
c9qboo1kttpqbo5et2el    c9qbp2h1oh4tgq8pq9ml    c9qbp88u9s4628mt7mg7
c9qbqt5jq14j4aco3elp    c9qbr7j0c3vi00q08hc6    c9qbr8mbat9prho01s7v
c9qbrffgnn7h7um8fvfo    c9qbroch0ri3m8oi5tor    c9qbs1psq9njafrhopg2
c9qbteup6t2eo065hurs    c9qbtj4sjhm04re6jn1t    c9qbu17af7bkgv4shk77
c9qbu62546634mgvstp1    c9qc0of1eiponla1b0rt    c9qc0qlqdo7u247g3o42
c9qc0uf4oaai77igl00u    c9qc1n2oftcucliamjiq    c9qc2auuo95cr3urar6j
c9qc508p8671ir3tfi91    c9qc54a6sv382hton31b    c9qc6f4gl1rhf3v7ol20
c9qc6ojru19tn3a1460v    c9qc6vnsa7vc04gq3d0m    c9qc78l0hp3bage9teks
c9qc7rksfrnsvob8mh1o    c9qc8p2b8r2l4p8sps9q    c9qc8qsqui7t8p8i4s5g
c9qc910j5itm985gai90    c9qc93e5gfriifbbt0gl    c9qc9hehbj1gqkklpeve
c9qc9lcj4rm1njbaj3cb    c9qca1f13c5ipsuscf13    c9qca8v9tdioc32hmuj5
c9qcaivrf9u101b58eup    c9qcam31aghdsuk49un1    c9qcbdne9as05nhsg0v8
c9qcbt59g5ktmguba8j0    c9qccju47c6b9n89n7mg    c9qccut22gb76aerach5
c9qce24ceku006jpj1bt    c9qce8lj88oavd5i0a78    c9qcf4i7d8fji6u35336
c9qcf7rkpgd518km8rts    c9qcfkfc773hbdjvba5h    c9qcg7477qmapgveki6n
c9qchdiahm71arrkpkj4    c9qchfdsm28egsare9f4    c9qci3ev1bf8cnane3gg
c9qcig0c681o4f1lnjik    c9qcjfq98q2es92u7eb7    c9qcjik21roc6eks43f2
c9qclfjr67ptvggeha0n    c9qcm65vsjuaun8khv98    c9qcmo6pt55ptcki5j32
c9qcnhvkai2d8tivvr6b    c9qcnrjnbi92bdvm8hre    c9qcntmmk89bracp5na3
c9qcnv2oqd0vgset2vif    c9qcobu7n98u2s909gb5    c9qcomfc7oe9n3j7h3es
c9qcor9cboqk5ijcb3d8    c9qcov4v5hph7batm2d6    c9qcq4c0ck4mcamcoj4e
c9qcqfj4qf08or94b5i1    c9qcrgug7gmdk608cf10    c9qcs2rtp2c18b2385st
c9qcs8risinojpvmu36j    c9qcsmhn35teuhdjjhae    c9qcth68o7a24n0keunt
c9qcut269nmb4h12hgq4    c9qcvasv2qof3s298sgg    c9qcvh7lr8samtsje3f4
c9qcvqtj9te70icdck6k    c9qcvrvf2qmt6b987nra    c9qd0g82gfl97b61tpuo
c9qd0hds525mo4nc34fh    c9qd0jtv65hdqgmu02a7    c9qd1ra45d3m3pvoasl2
c9qd2gb7bkdiirmg96g5    c9qd3udpfp3oc4j0bivp    c9qd4fj9nri2ur5p35a5
c9qd4kl3alkg33ts70e0    c9qd55oci3c1nr5cj083    c9qd5b2rf83ro3eoql40
c9qd5p1jekt50vih3n9m    c9qd7ah9v1vasl72kpjt    c9qd8frpmb7sni22uhr5
c9qdaev8vnhkoaffstek    c9qdb2k64pirpjvvm2k8    c9qdb6jeb0lg85teh9a9
c9qdbm79djbuco32ee0v    c9qdct9u1msg2b4jn6ki    c9qdd0ik9nacgrj3fmhd
c9qde83qrmr9kit039e8    c9qdecttp5r657envcbl    c9qdelia4t2aasfu2cpc
c9qdemjei8i753vfdmvt    c9qdh60br7giu6hud39q    c9qdh7oc7ai57ckbq0vk
c9qdhg3j8k2no3eag2ja    c9qdk3gu5be57hh577ic    c9qdkc70543u7hh4p394
c9qdl59lrsjp6dd16tq4    c9qdlhl1bb6oh5bg4she    c9qdlicfcpph6lmk9nc4
c9qdmcl0pebh7afl3raq    c9qdmrg98mm17bt8nvpa    c9qdo89bbrosm0mogam4
c9qdonoub709dmj47dif    c9qdoue2upokvm88qj74    c9qdpv22a3245qtv4mld
c9qdqn7na2pahme12b4r    c9qdrel3o1aaed2gjhdb    c9qds10rjq5t22uqsav0
c9qdsjd9utj9l4gtsgqt    c9qdt0vd1opvinq9nin5    c9qdubm45006h07b7lmr
c9qdug07fucn6hg3oend    c9qdurhsg9ndkf3k1rn7    c9qdvajf8b7crg4l4e2i
c9qe0c2vcjtge9l06784    c9qe0s8ggn67iea3vv2f    c9qe0udg7p0i0fagdl2t
c9qe10rl51eqaspk5nnl    c9qe12dod3kk38gshfui    c9qe1pllu50b4a6jql6o
c9qe316abk86b5vbdbpv    c9qe346mk4nsr8jbjdbr    c9qe3qlandjvojk9d29m
c9qe4h06ve90gah3iim5    c9qe4p65fc6g81q1jtcp    c9qe5otaclj21kb9opvd
c9qe6tljv8hr84e2r7ij    c9qe7tkmai5jed800mrq    c9qe8gterg3bfl06f8fb
c9qe8o7mu8j6vs9lbbqe    c9qe9mc3bmiavq58drg3    c9qe9p55uq736rai9c59
c9qeadp0gsbnb31u2u72    c9qeal4k5bfma2ic7t6i    c9qeb6d75ve9ib710arr
c9qeb92ulmmp42iq9c8h    c9qeco403t2o7hpfqr6m    c9qed07aiab538830qqt
c9qedi3tpdcr92cd8qcj    c9qedp4qhr5rcjt497at    c9qee72jpejg1v7ivbt9
c9qee9tc1013rea3s72a    c9qef18kb42sffdj04tr    c9qefgvi8om9etgesae0
c9qegvte2udn7td04evf    c9qei23i6kopafqcpott    c9qeigp3mkfq6j68f04s
c9qeirav25ue7pbln4b5    c9qejfah75qsdljll73c    c9qejfi9jg093uh94tup
c9qejjlrgvppkr76bsut    c9qekhjifm84mjq4ac9i    c9qeljusvt7gd5dnrdre
c9qen04haf141v5mn071    c9qen971h7rnrboe8u7n    c9qep9emqk105n9c7neq
c9qepgrf4e6fakfieuce    c9qepoq574fvemoalru7    c9qeqjcodb6hj8v9qgmd
c9qeqmlpuqttccgiqv0f    c9qesn7lshhomh8fha2r    c9qesqi13p2701uocs93
c9qetjdemp40jt5713rg    c9qf0nt37sdmqbrnfktj    c9qf2076cck49obvj4tv
c9qf3oupb3eqvqfkes5g    c9qf3p3h8tp89q224eqm    c9qf48j3idk3bkavk9tl
c9qf4fstr2i5nfs0gpp4    c9qf574fkcbhnmn8docu    c9qf6cfr0j6skgb3qbvi
c9qf70ac0s8i1f5n7r1t    c9qf7c31l2vr3r26jv75    c9qf7dpkj6agkct47aot
c9qf7p4i8k7jlea26jgm    c9qf8adkb8nifodocgcu    c9qf8c28mou3upbulreo
c9qf8il8egv1l7sntr2i    c9qf8lhh6remrjqlfrc4    c9qf8o7e1uv6mdgcs7gr
c9qf8ta6s6bp53vq8ua0    c9qf9801rr7ecpmnioel    c9qf9mpjvofc60s1r9lh
c9qfbc643ro58cssl84l    c9qfdev2u27ndc0fa43m    c9qfghj758qu4jq29k3m
c9qfgvqmcsj057bgd2l4    c9qfh1fli6voh2v224lp    c9qfj799uuk5mbcoa84m
c9qfjn7u31oc2ifg2se7    c9qfk0b9eoa8o966020a    c9qfk6jdqqaamgr3fe1i
c9qfkc1fi0t2sir976f9    c9qfkqa1j5j4bbv9634i    c9qfl1ahe6io4ms17oq9
c9qflikcqe1p87bkuk1n    c9qfm23f4tjo70kcr1rh    c9qfmf57ic4u4lq1ac32
c9qfmj51s4crq5u93p2c    c9qfn8fouvbrsg6j0u0d    c9qfn8id1p3hj822dfts
c9qfppaidk64pfr23unf    c9qfq8aaspuab8t0nnd9    c9qfqb10m0c4f171cke0
c9qfqu73jdjatfjnd56q    c9qfr6v1o916otsr06j5    c9qfr703dtg4fkejsp8f
c9qfro61jmb4qposalpo    c9qfrvbs21vo0a56s5hm    c9qfu7ojvjpt38kik2fg
c9qfudu66u0hgoon1ql1    c9qfulfelv6lo1m4cnmc    c9qfv7986jb81tv54u77
c9qfvi6e14q6gfrp4ois    c9qfvjg72fghlgl6mjeh    c9qg1q3com420fafvufb
c9qg1tp4rl3cj54j31pb    c9qg279ukrhvf2nbb0b6    c9qg30ups052v76qolpb
c9qg3tvj7ug7jote5qpl    c9qg42lm4e1c6h6sdu1q    c9qg43va1eg2uvk7fcr1
c9qg5icrfainr84b78a7    c9qg5jg8h3vcv50uv5ar    c9qg61val9u74r4ir8fi
c9qg67qnav1jat9ucaoo    c9qg6v66k8u2a4das8vh    c9qg73n3nocnbbqne3qd
c9qg74gj24gj29k8lcem    c9qg9gpgl0b970aacdo8    c9qg9r6es61729pgj8uu
c9qg9thl2qu9hdln39fj    c9qga592pl75ecsssfba    c9qgaasegl1e3748utun
c9qgauvmfjpvskdujk41    c9qgavubom21h8706e9v    c9qgb3mai44gu46ltplh
c9qgbj920qi3qs34f8jo    c9qgckvumf30g3fbgeb4    c9qgd0pn5gdjfdcdmkcf
c9qgd1fggv0o9v38ttcq    c9qgdg5fp63u5p5rnqc3    c9qge0bf7o4e62q5s1nj
c9qgeq2a9mug30r5t3ee    c9qgf8poaht32c01nff9    c9qggbvjqs6r0ah9t4vn
c9qggtnr28qejti0ap6p    c9qgir7i7rdqidhqbl28    c9qgj2npalfie3aabvsk
c9qgj36h6b5jr9ott9gb    c9qgj7q134pj85uu0aji    c9qgk6edbr7ebeedtmrg
c9qgk6pnnlqf7uqva7lt    c9qgk9n82hsmpon489h4    c9qgkglba08v5jh1f3lp
c9qgl8ij8bs28nj14j5v    c9qglun17n7b72b5jlvc    c9qgmvu8mtd7djsrfb52
c9qgn26feesni4kaon80    c9qgo7bahl825dntbal6    c9qgo8ocne1apfjscka7
c9qgol46eovo5dvnlgd4    c9qgolrv5eh5o7q6997s    c9qgp65h1014npggvmci
c9qgpht25m9hnldmt243    c9qgpn17ea8fdmn32emb    c9qgq036kcnefmv8rlq6
c9qgs3mqug75rjmob9kt    c9qgsin9t1b1fcrdptkm    c9qgt5qo12bl9r5gqf6s
c9qgta4utt6jf2akh4d0    c9qgu2nlo12b6kl08i88    c9qgul1n4fvba3h7gg0v
c9qgv4apggsrgedop1oh    c9qgvnej6ogu26mcgqib    c9qh129l9edifdk8d8e5
c9qh19bv47rnaqc10dng    c9qh1ld7roou8iuu3ou6    c9qh1r8svktvs9d9f56b
c9qh3i2uvjvreujqs4ao    c9qh3r09584utj3d0tun    c9qh5q21mi974q99vtah
c9qh5qn99fj1drnm5hg8    c9qh60vb6agn2a7os5c2    c9qh63jg7ai95aiepf8d
c9qh72tdhro9he1u4eh9    c9qh7n9hbggobi69i99p    c9qh8j67t2glnjv82fre
c9qh8rbrptcc0ejgcg58    c9qh9kgoeqnsfied7gkf    c9qh9lktoshgo7ssvh76
c9qh9o6b9vl4ckkt1f45    c9qhaf1feou9i0kamqun    c9qhc4npsjro6ebdqahc
c9qhc8pa6r2rikfc2p0r    c9qhcfrfk6ig65oo28ac    c9qhckju67v9h41oedsa
c9qhcoaj8lasr166a8fj    c9qhdef8mg6k4cgemu88    c9qhe0tpr68is5f9ijuk
c9qhe53ren0ive6ftlkk    c9qhetvirufqjkei1pjl    c9qhf12pmvuo1ji0gs75
c9qhf5qgo01vd8vffnl4    c9qhfgc5lac9r6aa16u2    c9qhi2f90q0as35pj21l
c9qhic7h4jbankoc7ma8    c9qhie2tt5btnm2k92dt    c9qhig8ehq34inp8qkr4
c9qhisadlbd9tl8nfm2l    c9qhiuq9mu2ak44vv8c7    c9qhk9rb20sj93hplkjs
c9qhkloherb7p1g906ut    c9qhkrl3nbjvap0ke97f    c9qhl65d61q8ohoonqek
c9qhmill4pro90tkb1gh    c9qhn2e0khk8nbt46s2s    c9qhn4h6d9jb69jl1hev
c9qhndbfl63ut79ev346    c9qhndcr3fl1938lg6fj    c9qhnfgmdf3rbhkbhvvv
c9qho5g3flk028nmq4tm    c9qho5tickg3q2drtjd1    c9qhoonikei9bnrr3l8t
c9qhoota475hf0n7pnui    c9qhpum56mjkimm2lp11    c9qhqlksp2o45t0rmele
c9qhr7r54pk69ugkgusk    c9qhs4n73bo9a14pc21t    c9qhscpuk43vls4m3dm3
c9qhsd8bnmrig9ti0aa0    c9qhsr5gdjm7q2438o5e    c9qhtphqsrgs4ect3oqu
c9qhun00503sak8m8tp9    c9qhv2bd9rnjfhpu30j0    c9qhv7kf6nflpeif568a
c9qhviq9t6ct1dqt4pnd    c9qhvl5mjhc2llslj9gk    c9qhvnp61nocd5sm6b20
c9qi1bfjg51m3r8k1aok    c9qi1kgrj3lsbs25v569    c9qi4lce36hlbu4vvvra
c9qi5e4k4ghagliqpfka    c9qi5qi3bgng6dfr098f    c9qi65umlg1u18vrgdkm
c9qi7e5fs7g2unoe1vc0    c9qi80lm4jk9m1fplj1n    c9qi80vde9dslke3ajk3
c9qi8s3gcmsektm59pim    c9qi93bhovkimi7lbhbv    c9qi992da6doknqasjo7
c9qi9dtgqi9t2il5m201    c9qibjr1tl55adauc65n    c9qic51nkd8mb2r2j7df
c9qic6sdkkkf917s2djs    c9qidac2k15see1j8230    c9qie018vc3vq9u93roj
c9qiegf10v6fsgvhbhbm    c9qifpqdvba88n66m8fn    c9qihbmse516echtpf4d
c9qiilc1nbv1orvld4fj    c9qiiqs7caj8vir3iijp    c9qij4hk3iachm08r7d0
c9qij96hcu4tj0k8an12    c9qikfi6j2fa3d5a2nu5    c9qikh6lifa3v6v5nbe8
c9qikkdlable69lun971    c9qilg7bpeq769sdm27p    c9qilue470dcgff0igad
c9qim4sb6jc55mou6t9j    c9qim8590cono3r7thnf    c9qim8atae1jb5af8m3m
c9qimcb4gcba4un4raer    c9qimvhi0aao2l25r4n7    c9qin5dif6l1cioj7ttq
c9qin6bidch4o7km7v2t    c9qinc12t1b9tspar0t8    c9qins8isi0ge397q05g
c9qio10d0jru4iljve75    c9qio1vbp3gts5tkhaus    c9qiobtjdal2quvqd915
c9qiokj9cmbdvd0ubdp2    c9qionlul1aqg177d6d3    c9qiqluld98svqfplr08
c9qir7btfmb1hghorc3h    c9qirfnpplq5pet7aj9q    c9qirj59sqa3kf8juni5
c9qirqfrtm6gibm5st12    c9qisd8v65f7b5cler8e    c9qisg9dtc4ahf34619p
c9qishft3qhm4vquq9cs    c9qishia437nbhjp36rr    c9qismuk1b8kicmus47g
c9qitvij8svi06in5spc    c9qiu0p3pu12gb5561bh    c9qivf3fo0mtlpmba161
c9qivipmlchqa866onne    c9qj20bbssaertiilmgh    c9qj3eklch99ut0oahp0
c9qj4j1t4frqbhq50s4v    c9qj5am8ustnk7864ir2    c9qj5reapp3epfaj1c12
c9qj5v96kuts6vriousd    c9qj65uap5jfoet033q4    c9qj6d38gte2j1i6up9h
c9qj896sb09v41ee5aep    c9qj8lam6710pp53kac3    c9qj93fguuamado7q0tj
c9qjaabdhdn815lp86qp    c9qjae946lbu90fln7cl    c9qjaekkirolsimcc10d
c9qjam8qvduobikfa10h    c9qjbcku32o9lgp22gmm    c9qjbfqj3cvrtta8qrq4
c9qjbmaga086j1df38st    c9qjc6o2isqtlvt962h4    c9qjc9cq0ifhnbvmbal8
c9qjclc93pvmnib6bahv    c9qjcm3c2m3islkaunmo    c9qjdlgnrd8bc86v32bq
c9qje0t6vggkjhukttlg    c9qjfd68rnmifa6vvf24    c9qjg5m97ve1ksq699kk
c9qjh29u2bvhkg18hn36    c9qjh8oh567v00huacoj    c9qjjb4e66jc4rnsbipu
c9qjjucoeft4sg0bog5o    c9qjld2uajitp9jtdmqn    c9qjmc1rduv9einhv09h
c9qjmidpeg00ohuoh052    c9qjmnjs2clua95e0ro6    c9qjno5vfcrjf6a1qu6n
c9qjnvhmkt8f7bpueib1    c9qjo216nrd569p3f8i0    c9qjod8srmmlmjp76ee4
c9qjot1f97426orqrh73    c9qjpiqnllrgskosm7ha    c9qjpvvb71cvosopkj20
c9qjq6or5vpa1asr7q1u    c9qjrr4cvg19ub1mtvl3    c9qjrro7ab6v3s968kji
c9qjt1ki2n60fu5lajml    c9qju90qovorh2a8f8ig    c9qjua6ms4k3pvqvgadb
c9qjudl0g8ogeu14puo6    c9qjv24loug5la8rhquj    c9qjvac8s68huff7ccd9
c9qk0lut49l30k6l3dsp    c9qk169j8kpfs7ptfbdk    c9qk1hjdotql8n3iimeb
c9qk1kjtheuhu9qj5hk1    c9qk1l2p9u8724gsvlgd    c9qk2bfeeg4vovh6uuo9
c9qk2jaj39kramnkf69i    c9qk35rb7jhp03gn0d20    c9qk3iasmmi19vkae31t
c9qk3kr1r9ts504npndr    c9qk4icgv61vckg8mnc1    c9qk54h1bq6d0g6vsgcb
c9qk54nko6lt2k3r6foj    c9qk5kdm351gs70ti3n2    c9qk5qlbje2a0oie1um5
c9qk721d1jck521ilnlh    c9qk7a5924svtng40hjg    c9qk7jmeqc4966j1nsgp
c9qk850adhjcms9t83so    c9qk8e0cgjma8ij5touj    c9qk8k8nmf2oid9fdg3c
c9qk9er4u3idgvsbds6f    c9qkaba117seqvnur9nt    c9qkac30i6726vulq744
c9qkadrlv4s8e6kgij7j    c9qkc18c1tfijajv5o1l    c9qkd1a3f4s6s8ijfclj
c9qkdjurgbeand54mgov    c9qkdmh7vfkqk5lntpua    c9qkea0jpp17qti1rngt
c9qkejp44a9n6kofkubk    c9qkertb4musjhlr00tp    c9qkesaga144vuf34o7o
c9qkgds6ph20prt9vbda    c9qkgq7svshq70tac39r    c9qkgqhn25kq6v2a3ihe
c9qkhbntdkmtb872rn87    c9qkhcapv0a035iovpjj    c9qkhdk4uk2hb3p00o15
c9qkhhpg2600i9pen5uv    c9qkic3hlv5am2dsip0s    c9qkihtbl6plq42gvh2v
c9qknc6r0mbl1cg9v1i4    c9qknjva7s26cq9mvuua    c9qko00fmb3l391jfure
c9qkoa1mf8j8cbneq5te    c9qkojbrq5fbul02k5id    c9qkok5g1k8ba04mhc84
c9qkotprvv0pigoevrlj    c9qkp2l8ft4na6ndncts    c9qkp3v49sneg8vo0sik
c9qkros59mk0rb0ebhdu    c9qkrq1ar2id21sf621n    c9qkt654nd9q2mkh3109
c9qktag89h7uasc86avi    c9qktq5agrhd88afp7rp    c9qktvum1n5nofbjcjeo
c9qku0o201cli7at4756    c9qkuesn4c8b1lpstial    c9qkuvuctf9lsdunm473
c9ql1450gk36jueusns9    c9ql14sdrnsj6vhc1n3m    c9ql1ed4iouio4slomdo
c9ql1qupekqctse7btd4    c9ql1si9h76kpbanug59    c9ql1vle07avfb6qaj2c
c9ql2m4l72kretjptid6    c9ql30tebrjjbjv28fsc    c9ql4fm427hu92rm63k5
c9ql4qpbma3484on2k85    c9ql4s1fil45o4tqfih9    c9ql5crcdcftfvnum5or
c9ql6sc0sq9ctgf7vc3j    c9ql6v404uut3k0jcond    c9ql7jnc8fau1m487nhn
c9ql7kmqdqofrnsfigbo    c9ql7ttulm4h98vunpgm    c9ql8tnmqf13c4idet3k
c9ql9u8it5ghhf142gne    c9qlakm8b5mplvosmc0b    c9qlam8bvfrhbjqthv6n
c9qlaskq9dgd3i32n73o    c9qlb3e9e2pfjhdag0kl    c9qlbatra6bdomgguvtg
c9qlbgt52m1ag1u2john    c9qlbm7ae4rh8dmpl8s0    c9qlcc1fu4t7lua3mdr0
c9qld2ar5dhobpvc4et3    c9qldm68ce0vn9eriarn    c9qlefgenihk7ekphuoi
c9qlfoaf2lv94kqjj4a5    c9qlg1q67kpmi94eichc    c9qlg284j6nmiq24kobh
c9qlgiobk1jiskdeqq68    c9qlheoad0eu9tlsee0c    c9qlhg8nj75rlnsrpl17
c9qlhqiv6dvi8qptrhcn    c9qli94v3g43fkb3uepi    c9qlihvs0ato5tork5q1
c9qlj5ttrj130339ujiv    c9qllmpdsoihli879je6    c9qlmqbfa3j4lo6t50dk
c9qlnvt9og662shjjufc    c9qlonv379jan5uhjfn6    c9qlougsraktgbo0fb5s
c9qlp6s5bgs24n4s0lme    c9qlrmgkb4p88ss7em13    c9qlrtefl6mjni4f878v
c9qlse275u23n23ht9fn    c9qltd7agnvc6p760o9q    c9qltf6e8duh4ethqql7
c9qlu0hr26tkd2pn177h    c9qluhgk32n2tvc4j7cj    c9qlut52csu0hs7ba1ft
c9qlvg1kdcperm0pjht1    c9qlvrnhi5fc63caoopi    c9qm062f3ug009h76f21
c9qm085ves08f28bgqqj    c9qm0lu7c5dp95jvusfu    c9qm114153k43nflthqe
c9qm1pulq9gf9027dlqq    c9qm2d5vjsttc5e3f17q    c9qm2obkgrfgpj2612o6
c9qm2p8r0vdkiu43n2c5    c9qm468us5b0ctclopgi    c9qm5avqqtnsei77e99c
c9qm5ii7uiar0hfnqds3    c9qm6r4gtonhgclgibu9    c9qm6sbsn05a7968vntd
c9qm7b55jik16r8q9h0d    c9qm81tjk08u213naf8i    c9qm886l8g5se2ighpi8
c9qm8jagnkqq6m47uqnd    c9qm8uvs17p43603u096    c9qm9raef240vujtckf0
c9qma45dmm1tcgal0s7v    c9qma8hmugcn24j3vekk    c9qmalh6tluucpif8gn5
c9qmb9tkvm9vbul5m6sg    c9qmcdv8o6mrbosiu4fi    c9qmcf33n6q1qbcvs004
c9qmef94tc9nqm7km7n5    c9qmej62j6190364qm6t    c9qmfgs56sk7r3gf6vmb
c9qmglkc4m2lgttidkkt    c9qmhm9dvdkt04nf569v    c9qmia3q53s6knqa0qlh
c9qmjh1pak0hq7buq9tl    c9qmjsb3vkevtkkmtvem    c9qmkvkve9g0ubmallsj
c9qmmrpercjkeulla4ds    c9qmnnq3orce5b2ql0iu    c9qmoga5ehtub7l44bp0
c9qmou9dt7luogr3eqqj    c9qmpebnv5n1ctbbc3et    c9qmpie4hl09g302u7ti
c9qmpl537p7mqvf8j0m8    c9qmrdm9mhmnirrb4376    c9qmrr5214f7sb21e4ol
c9qmso5tsosohsmmp9il    c9qmstukp6htr8cqbnin    c9qmsvbt8b76ta873hdg
c9qmtjooa0o188nilmkt    c9qmtogip32ajpqp3jnv    c9qmtrlvoqs2u6oqbucg
c9qn06rtqtdsl9ehioui    c9qn11l9q14horbr7nft    c9qn1ps06i04dra0l59u
c9qn2os171edrf6b4ipb    c9qn2udg594rf59qok0j    c9qn3bssh0o4405bvq24
c9qn46qvft8f62bl2ock    c9qn4ck7qvqi6lm5tc3e    c9qn4dba3rsoccm9len5
c9qn5253a71aio2fkqul    c9qn5549sfo2b6bijum6    c9qn5g11l53b9vinjjag
c9qn5oo8tmnhi08b5cfd    c9qn6b99h7o60ojuv148    c9qn8e1o6opjdivghdnq
c9qn8h7oc6itni9eq034    c9qn8u2k38771c7u25jo    c9qn9bibffhin8gvbtcl
c9qn9cjg1h2c7icdr5us    c9qna9kj317ebgkpa7o0    c9qnabbbql95u1be762g
c9qnb04en018asm4bktv    c9qnd5lu119scir0emnp    c9qne9t1snnr47una8s4
c9qnfrcef09a70lknnf9    c9qng3mk0021q5a2unol    c9qng3r42uiai758sqq4
c9qng6j9cpv7q28egs43    c9qng8sb9of8vss59bt0    c9qngnbbu434ev1d2l11
c9qnhb9mfhiqr2mhaf0o    c9qnhc36knbags1ls51e    c9qni6ecc3g9uisg26p2
c9qnj8mlbrsruvvn8v8a    c9qnjao1aiq3if3uq2s3    c9qnjieksh8fvpfuelpg
c9qnjst2e6t59jitsebc    c9qnkl132sq8c976lsct    c9qnkv96kc24vpgtt6sv
c9qnlfdcdud055393o98    c9qnlqr37bgp53r9pbek    c9qno3th2n7l4o8ibe9s
c9qnpddtrkqnhvngvugp    c9qnpealm854ie5ng3am    c9qnph7k8t1tojg0dq18
c9qnps332bif93kt94bt    c9qnrgrs9vl6sf40dirg    c9qnrmhjf4idbiq1bt3l
c9qns3aos2fo89eueafe    c9qns5e1l09jut8apvhv    c9qnsge15cb5ita5fjhm
c9qntakhov6feup3g6l6    c9qnutcpjqk6r18c3bbk    c9qnv1es1q2ddqnu30q6
c9qnv4h8cs5kavmlgop9    c9qo018d13j344osgvk7    c9qo065dkq85c0kcbf2b
c9qo0o9benfkfktg69b5    c9qo11fmlkfggve0qfoi    c9qo16fio3ejd33c86t0
c9qo1imrjjndj7sibv0f    c9qo1jk551j2r1h3ppg0    c9qo1qhfk32a2desgadc
c9qo2am0up6natibos74    c9qo2fd7slvb95qnlvcj    c9qo3nr9a655gcfno5n0
c9qo6defrvn9chqd0lep    c9qo760al1cn8db6o553    c9qo7fv43od6n56qnq7c
c9qo82le0c1ni7ngdse4    c9qo85a7blcvkc2qao75    c9qo949f3v3f9bq6b819
c9qoa6442msfs4cletbs    c9qoa8kkrcp3vb6us39c    c9qoai8c81n3vtqa0mia
c9qoc66kb6l9jn6oagde    c9qocjktuansmn2cifkl    c9qodugaho9kh0i8o0h1
c9qoe6ehi4og9vml65g3    c9qof3krolab5a6ss4fu    c9qofij0d6f7llg8q6o7
c9qogrv4it18ft41j7ab    c9qohrkhkt7d065pt27l    c9qok8hvf3ivepe3ifi6
c9qokdpp5q5lc8kee68c    c9qolc1ffa6en1go9d4f    c9qolo8bafcvtb2t2vrv
c9qomcpm4c25ukb563i2    c9qompo0u4rv2v0rbjc1    c9qooqf15ulee3s6s8dr
c9qop0qt50oduljlt664    c9qoppi8bejhq20drs6a    c9qopt3le2316m8nt2eh
c9qoqq9blqjeofl96lgf    c9qor3kr6ckfpj4g9tjf    c9qor64lg45gllan0q2k
c9qor8r9a29rs00s3rbg    c9qorh387oit3vc31asu    c9qos85pp3h7g0hpuh45
c9qot5tuuoblkn9noq0n    c9qot6sub0k0r3oicrlf    c9qot9372c14nr8q9d0p
c9qotp9uc4jou94m05rd    c9qov7a2d13qao27ccqi    c9qov8723b2d0eamuoht
c9qovle3kcrhfagmplch    c9qovmr6uqfrehblkm3c    c9qovt5mcfmb3t5rquld
c9qovtqfvf7id97dil52    c9qovujdd5fq946019fm    c9qp0gisoju4g46rnju9
c9qp0hduadi3fiq2h8bc    c9qp0keu5897hf7lpb2b    c9qp0mrb0gsckm3mi4e5
c9qp0nn6ninkr7ta5ess    c9qp2fqqpj8chqk7rjep    c9qp36rjcacohk7qf18t
c9qp37ndb4kv5aphd3so    c9qp38etp703ama6u99d    c9qp4bc74ta766cum644
c9qp4kio2bkksenno286    c9qp51qrvv5d6ccsvmjh    c9qp58mh8l3o3f2r4hs2
c9qp75k9t1lp531r7ru5    c9qp7oapbumt47nj8gst    c9qp8e6vct5ta16sn24s
c9qp8jej9ab1bob1n23j    c9qp90fibpgfjfvko3pv    c9qp9icf30j6jc8t57gj
c9qpa6pfo98gfakm8bp3    c9qpaku690mg9m2tqs8m    c9qpchk6ljo88i1oik73
c9qpd0jd99mejml5ccdu    c9qpd7jqng4s22a0su92    c9qpdkq5etolcp9u6cdj
c9qpdp2pgfplgquibi4v    c9qpe1t3r9gbd75kbakv    c9qpe9lrguuv77r534qm
c9qpekbb7cabc6ls24kj    c9qpf3pfncupk26gklq6    c9qpf6aadn3pgojt02gf
c9qpfkk6v2o62n9mtfvj    c9qpflbvj2f8du3r5u1q    c9qpfqm9rrtlkr0mds3j
c9qpg0ghchmmpjck7q22    c9qpgk1841vmiugtkak2    c9qph2iq0g5flckvfftb
c9qpi3e3uh740r5jf1k8    c9qpicf4pms7h3idt2su    c9qpimm2oess25dja37g
c9qpinr3u0n770s7nen2    c9qpj32a4gb6o0fdpvdi    c9qpjn2uhajsdtoc8asb
c9qpk6ljuhknavenc35p    c9qpk9ujg37k0aah5vi4    c9qpkr7j0bs4vm23v5ni
c9qplk2jra3t7bosivpp    c9qpm1uavao9hb10c78d    c9qpn3nnsgi8jo9hdth8
c9qpn6qkpet4lvdv3deb    c9qpn7idf2pvl1077h8j    c9qpnne13gj7ejt025od
c9qpnrhm2tfc123jtd90    c9qpnshubbe36clggn66    c9qpoa4e3pccrbh5kse6
c9qpoe57cutgstj9ib66    c9qpp6dha8r3akogl9na    c9qpq4qu1p6g8hb4apvi
c9qpr7q1t9cs9lp1q82n    c9qprlp4kmc1ifva1ni4    c9qprp8ipotmbbe7hglk
c9qprsckmtrpgg1obq8m    c9qpsf92g0gu4detq8if    c9qpshic06m8970rum3d
c9qpskhudvbm2gfbpe04    c9qpsvs80b8ahs52hfce    c9qpti0hgfcck3kb2t0c
c9qpuh5rncubnnql01s3    c9qpuss33r1p6731ehgf    c9qpvha0bmlu4okoirpo
c9qq04l6odpg9np0fh84    c9qq1mkljjudqcd973i1    c9qq2iripgjhdnl861a1
c9qq4apijnph91tptv6l    c9qq4h31jn3jeh36ttbm    c9qq4igiretap3p9mslj
c9qq4s41v6hm6uhvdsre    c9qq5eda61fc21i8mmn4    c9qq5qvl0l4nr1dlirc0
c9qq6df98qq6nok37u88    c9qq8e76m0lpkujs2koj    c9qq8j550981vcp6u3a5
c9qq99aqg12fb6uqnqlo    c9qq9gi3kkeofsquerje    c9qqa36c1mjob68vm3ij
c9qqaqp7om9ak8m93uru    c9qqarfe8duldacdmbif    c9qqc0gg5do3s438ne8e
c9qqccm65uglh05ffc5h    c9qqcnfvcha2dip88l69    c9qqd5pcu3g36hin8s1i
c9qqddneues3pfga5ash    c9qqdmas0brhubf9s04a    c9qqf6f2kb74os0p1js9
c9qqgt00un3rh2hffs08    c9qqh58ueoo1et9jutki    c9qqiu5u1c7gvreb87n8
c9qqjap8mcfeutk6c1r2    c9qqjkeql85fq8gldg9s    c9qqjp5k2orveva4r2jg
c9qqjs4vmr1mp3p5upsb    c9qqjs8fmgaj18i3nsv6    c9qqjsjj2lcnlkmm2q45
c9qqk0cvr7mjr5dvlpan    c9qqk0uhfqmhfhc36eli    c9qqkl2tn3j2stk3c3oa
c9qqkve5707c8o4ismjl    c9qqlvg8buvm2n557vqe    c9qqmace3mbo98t6jqrt
c9qqme4tgao7s68ovroi    c9qqop3afhbf2de2ljah    c9qqovk7kdjnba1341ho
c9qqp4jln428khea6ebe    c9qqpdnvi15lf3g70378    c9qqpiqf2470mc0ntjrq
c9qqq3n4t81dvf24pvuq    c9qqq5egsq3kpeqibv97    c9qqqckfaddrsmvs2ssr
c9qqqco1ihvll0vlko9k    c9qqqgcdj714hmo0hh6i    c9qqqp6iga7b371qgikf
c9qqqv8gvd9geddp8da9    c9qqr7djprtf0u5v88e2    c9qqrptqv2vajhk3bklj
c9qqs841hu1v9fb59itb    c9qqscvfjpg5au45tio3    c9qqshes7loqo1unb05j
c9qqt2q9m8rltqaethhh    c9qqtavjpfimgh79hkki    c9qqtfv31ppvl3ip3it9
c9qqtmdiaa4l66li48or    c9qqukoc3ud460o1k8ro    c9qqul1hh650et7l1a3m
c9qqush5kgpltkoq280q    c9qqv135s8oadbbjcq7m    c9qqvniiqmh1cenubuhk
c9qqvvroofse5c3lakoh    c9qr02qgpuhb9cfl059o    c9qr1p1j0oi659ed7mur
c9qr3roculuqgq5tmp8a    c9qr41fgvnv8r0v129gh    c9qr47b579rtkrrm4pn5
c9qr48mrvd4e2pe1lp66    c9qr4k5tnn8dg36js50p    c9qr508d375ervv12go3
c9qr5edhidvs17l9cl10    c9qr6eedm2m6skq1u294    c9qr6js6f0h4f4ror1ck
c9qr6m7rmn3i9abov0h2    c9qr6rt68147qo2o4tgu    c9qr6sl4843bdt5n3id4
c9qr72gie0pq4l6l3t05    c9qr7ljfedbsggjtfbke    c9qr8uab4kj2ts40amui
c9qra8cu74encgsvull3    c9qrakj1h8f7ofneqe9j    c9qrbe7kira0hs3gbduh
c9qrbrtvpjjqve3ag8n6    c9qrbucrcvm6a50tblv2    c9qrctpvl0cjret0arbt
c9qrcu90ob71ee43elk6    c9qrdr93u6ihlqpta2sb    c9qrefpsen8jdqmtij92
c9qrfpicejkdmrhaghbs    c9qrfqd92phua3ebge5c    c9qrgbu0rte2in7o5psp
c9qrh1di7rt447g3ddtr    c9qrhe23l27mfc4s748d    c9qrhils1dg625g7u3dv
c9qritckb34luf4apeg3    c9qrjtjejvb1hl61armb    c9qrktjfmg8tetil6f6n
c9qrma4kfqr7mperf8ck    c9qrmumrr58vsfo6j479    c9qrnf9frb99iqp7ccrb
c9qro5ic2umhhtmim282    c9qrosct43gb105ugg40    c9qrotbj0v6tvb8qhm3j
c9qrp7l75shu7a17e9cg    c9qrplqhgjmgu9tmr3b2    c9qrr2tbkk0glatnaql3
c9qrruu0mnloqg4gdsjr    c9qrs63l1utt0enad5sg    c9qrsg6ur82oh56in92i
c9qru763g1rs89mesooo    c9qrvbq0704cb2qvf7bb    c9qrvjgm62n2k72uq1t4
c9qs0ra2j4ndv6o14uf4    c9qs1b44fqt9rqv8r71u    c9qs1fvvm1d3gog6vg4r
c9qs1m3l7qn5c19ivg85    c9qs21mvsquqiptbqosm    c9qs28lhes1p13cctl3a
c9qs2obut535omc0o6dc    c9qs2tm9ri6au88belop    c9qs31ooomur8bm9btr7
c9qs3f367ji8mohhdv32    c9qs3f5heea2h4qteaoi    c9qs3f615m09fgpasa59
c9qs45l4ds4860cg7q72    c9qs4r7ocgd6vpktrsb6    c9qs50vrsnl9vmbl4r7i
c9qs5efl1ht9dh9qmi1o    c9qs5v0ht57lq3vn5rop    c9qs60ii0fo8sv462j16
c9qs63etomr134sv72of    c9qs6khgtsrh339qgt0h    c9qs724uu7jaheiqinpl
c9qs75d2nsioaq1ugim2    c9qs7pgjcp01kajj3m6b    c9qs8mlgu2cdiilsh6he
c9qs9vtoj5fulq5vuqad    c9qsac1onharvdiu39no    c9qsd2ej8eiphqq37q3r
c9qsd3ugh1p01tqqvjtl    c9qsda053krrbhncp4jt    c9qsgb9d07o1b842sbl7
c9qsheu9kg9qejjdrc5s    c9qsheufn5trhk2cdern    c9qsi9t2oqqdj9e8k0jo
c9qsifrbc80efhk6irj0    c9qsivhjd1q6if34g466    c9qsj2gr7a653hepivam
c9qsj68kedpif0ovvhik    c9qsjnkiv3c3g57m8e8t    c9qsjq3kdb54n86p23cd
c9qsle0k0vo1nf57nsm7    c9qslhp669mjlulrdt4b    c9qsll68hvcclr4nt0kj
c9qsmbrofeff7d2m2kqg    c9qsn4bflr1n3qo7orh5    c9qsn4r60h7b6otf041e
c9qsnhdg4qdfkl7i0pjc    c9qsprf87bvcac2ji274    c9qsq510bg9da6b3in2r
c9qsr4ftogmekcsenp9s    c9qsr4i43md4qd4qhd84    c9qssjuqth6rk6lphh22
c9qsslovakoj48fb76uo    c9qssr7pchifa4pt8oan    c9qst3gtru17nuptoj6b
c9qstarvvdmfpfhhgr6u    c9qsumgj3viotbf1hu03    c9qsutu8qeuo1lvtvf9t
c9qt0bdqme9f145hslt2    c9qt155u0nog3g7v09qn    c9qt165c7i3dshikafkh
c9qt1u9qf4fo21mmoen8    c9qt2eu3g8gu2n4qvvml    c9qt3fphvsdha1b62263
c9qt4b8rkgup9sll86nd    c9qt5givl2vfinmgor9v    c9qt69r8us90hc22t1i8
c9qt6vdo726m5hp49vct    c9qt7dapiomgdi0bbml3    c9qt7gte8obl09a9b31d
c9qt835nb8v0sipqm3rm    c9qt8t0kgrhouvat4rra    c9qt92hhgd6v794q3fo3
c9qt98at5pr1gqe2he9g    c9qt9ah2r0nld1h4sub6    c9qt9hmt2k9lkue2q6rc
c9qt9qsgt65u7dl2ami1    c9qtalvjrngnc8p3o96e    c9qtaoc221ov0ni75ed0
c9qtb15hvoguq4iq54sg    c9qtbnrjd0f07tsko5h5    c9qtc6c8a2ls1jehjtlm
c9qtch667svt05lt3taa    c9qtddpr4rk8u4glsh0q    c9qtdri1ino1kgtvg47u
c9qte8l5lhb4vuadou1u    c9qte9f0m6ghmr3cihuu    c9qtf7rgq75lql7k6mv8
c9qtfa5rpcv7c7ds9l1c    c9qtfk8pqmqoq6bdetv1    c9qtgl4k431tprg2qhh6
c9qtgvq4b461kgdcpjsk    c9qth49g7r8v99d7samt    c9qthgt1o49f60e1aook
c9qthuo7vb79vqnr27e4    c9qtimr2uauqljavovpe    c9qtjg98hu7l4mebr6sc
c9qtjlm80c8bofmlmvim    c9qtk660k83g14ss6rjt    c9qtkodavtt39l8jr8bb
c9qtkp61r55jajkqf4cp    c9qtkq93cc0ic7v46fqq    c9qtkqfsgtkn94pkc3kd
c9qtm6ifdv2s7hpjbc59    c9qtn6r7gdca278kf4qv    c9qtn7i9l841ba9f49ro
c9qtodoqs2mrmof8v0us    c9qtolob2tcmk679h49d    c9qtooljtqpgh6ram0bb
c9qtp62t96j0stvjjfsk    c9qtpo63g4uebhoiet6n    c9qtqj7np4ohfdpp9d5e
c9qtr413d448msbd64lu    c9qtrs8buic07tm8gevo    c9qtt09cgta8jbkf04i4
c9qtt5otfl47s1kqk870    c9qtuhtgjo7eak4fpj9h    c9qtv0jloum8hm1o5jh2
c9qtvcq1uk8c8l6mbmgv    c9qtvk46ebcqhuo01emt    c9qu0h1fg6rt1jnu62ro
c9qu0kc44r4ugub4gia6    c9qu303tc7nsqrrvkaum    c9qu3kf54p54tulf74ei
c9qu4eici0kl4h87thb6    c9qu57sjgllc4nid7f29    c9qu5hnf3a406t21qh49
c9qu72de112p0k4irmto    c9qu768169sgthjk42ic    c9qu7kf8h5nkpn8n2ks5
c9qu7qtptve5i7u2e9pi    c9qu812acoiho4ptlt4r    c9qu938dj06rb4c5uu14
c9qu9719i1hd00u2fsar    c9qu9gc4pgq2o0nmkkch    c9qu9ocm5j3t9n007ra5
c9qu9s2smlilgfhfbbs3    c9qubnube1je0qnkrp9b    c9qubqq9njklp2e8f2c1
c9qucejafik149u8l847    c9qudijig8tb7oqjtr0p    c9quf7fdj0fnadrib22l
c9qufevef7l99evbhuef    c9qug2nf192a7f45gt39    c9qug8tu95llp0npsndq
c9qugbnacktb28a6hstd    c9quhu6l9id2ao2abft8    c9qui9qemr21euvos8mr
c9quijt9f2a5aha76vnp    c9quik5kh93saa3gqci6    c9quiuhhvfoag3i9o1it
c9quivaoako9fuaec2f6    c9qujqm0pr4slahgje3a    c9qunvvke2omji12vmn0
c9qup67hrt0tkgufe6vo    c9qup96beco1i7kpb5aj    c9qupfq1es2k276dd6sb
c9qupoq43l9so21kijej    c9quq92rjm6cbhoqkbbu    c9qusjhusosq8bqn0gh2
c9qusqucbb6irttidvke    c9qut6hclc1e7v09bcfg    c9quuau79ffrcf6r6uc4
c9quvhtdicqcdssmo0mf    c9quvpnhjm49ilqi4ats    c9qv0vfgt2p4sr94f5r6
c9qv1a4a4l6hooi43s1c    c9qv1tclodkm05c61obc    c9qv29pefbaju6qj3ss8
c9qv2lreb091i2k26p7l    c9qv2mibeikbju8aqogl    c9qv3u0tiv0vd1pevlmr
c9qv4hm49if2knh4q98m    c9qv5q72dfo8olbu6lkn    c9qv5t0jo2okll8j3fek
c9qv6q4mcduu3sd6j248    c9qv71t76nfvr1b64jup    c9qv7aausr7h7e7kh0gj
c9qv7nucl2ucne56627l    c9qv89dheopdkb532omb    c9qv9la3cmq8pcd08nuf
c9qv9o8t4q9t1k4k87lf    c9qva077p9lcgkgskc7u    c9qva14md3c2g6n98ti5
c9qvaucn1l8ovj50dm9o    c9qvaujrgvvnkkrihg56    c9qvb4o0gnrh8ene82l7
c9qvbjqj76kbourleela    c9qvbrq0kptk44ch05b1    c9qvcideslba6a64lnr4
c9qvcn8sms64b2k4mmhv    c9qvcvk59n5sbulb8b9k    c9qvfc05vftpaqio6qc6
c9qvfrj9gnp6b0uvr154    c9qvfvfgboeehvfn8hrd    c9qvg18fousiijutbies
c9qvgbbj7gmsdd7dikrs    c9qvh61a9o1liokcu1ht    c9qvhs93md9855l6d3ve
c9qvikdpblmcd8j3nefu    c9qvimkn29efbuetngi9    c9qviu9kqigcckv49t5v
c9qvk2mlgs5fs3jvii6j    c9qvk9n5ja7vpocialn6    c9qvl5h53jnlpm21gi91
c9qvlfdampeqrtjjjk8l    c9qvn82popa55icu83cv    c9qvnbu8gehuo7lsusg5
c9qvo6ao57lnfvh8mdm8    c9qvo9oihgipvbvccbrg    c9qvpaafbve5e3u5brna
c9qvpdopj67hg487c8p3    c9qvq250p2su6o605t9d    c9qvq7kjraud0on32j6j
c9qvr2ljkiju5harnbrq    c9qvrhdrs2d92qlt3gf1    c9qvrsi1nlc9huo4dhfe
c9qvsj0ir3huucvbcmnj    c9qvsp9ggkac4fkdtl59    c9qvtbf95kge5q9pmtmf
c9qvtfopnqt80m8sfnmg    c9qvthq2407gd70pthjt    c9qvtr9ps2qbs7437mi5
c9qvu9vh3bj2s8lnvcnk    c9qvudao1svjrva6ll31    c9qvuh8t1g21v08dj9ve
c9qvulpu7ogfbelmk496    c9qvutfa1tr7vkj9nnf5    c9qvutir26pll35d2con
c9qvv02mu4t63u96lbav    etn00299fm0ldv1cr69i    etn008d9ccb5c7j8t8ek
etn0097764aglcuauvrk    etn009kj9had1pi305jq    etn00b4vvrtkmtaa0fe0
etn00bmphhamlodhu71i    etn00cdt1gdq3p43krne    etn00eh4rn084ncm8cbb
etn00fk9vjgm5kv366ob    etn00iuq6ugj8jcsj2kv    etn00k9ne7f9h5qqobv0
etn00mg3v48triigqgae    etn00rbcr21ip4039p06    etn00tth6t9iai6ckeq1
etn011knfgulho67c1qt    etn011tocetighvf0jof    etn013dlk0p7mfe9vb6o
etn015cb1uvi2qbat07c    etn0171v7qadg58ounbs    etn01bpgj8nvmlku3jr0
etn01ca2b2mcnrdrg18i    etn01ds0q0ac5ssm016g    etn01enoaum0sciuhrqi
etn01ldl95hqkjs089mg    etn01loh7qdvf8m1hqbn    etn01m6aotihu9t9dfpn
etn01mr4goo9tg4kvm96    etn01mu9loa5n20dimrt    etn01n3hc6gua1qrkbss
etn01ncrid7r3o75vj2q    etn01p6qpj8rtlq595ge    etn01pp55otetd3u805d
etn01ptumnsj1h7mjmq9    etn01t6c3eilhl31nl7j    etn01ucm5r2ric9l4j91
etn0204tskifvmam0904    etn0236mrcb6csmmbiav    etn023ju4bnkrepi63ip
etn023q3n8g579akfvfh    etn0251q8e7d9epalq0t    etn02auo9o9lc78g9cs6
etn02k6q91dnqcgquana    etn02ln06jl1gskf6efj    etn02oiteplvteesuihk
etn02s7hjnfj9c9k663q    etn02v2fqtnkc8mr6g95    etn032fu78e5uuv6kibr
etn033klt4t6rh5m9cbn    etn034inmnmk1qnsc2f5    etn035a73tf5dg7natpm
etn035ga3gnd0d3lm7ds    etn0386k7kcs2a648mik    etn03cu6v7riun0ppis8
etn03hg22ajs8gmbl0s6    etn03i15s9mbk2prncar    etn03j3mmotvuncp8v1b
etn03jkhq4lku67do6vg    etn03ps8sqe5s6u9si9l    etn03rk2gl03781uq2uh
etn044u0nokqfah3oanj    etn053j0up2f18fjidec    etn06h9os2r3djeit17h
etn08n03d11t5gsvqc8i    etn090bgvdjt3accdore    etn09o9b2f8tb52hkg0g
etn0agg2pad10qck2i5f    etn0d0dbtqi4m74bj0l3    etn0f9qb3mki26o2bk67
etn0fvr2stdh13gjp4sb    etn0i0ap9jf9jjlc2f19    etn0i9aqghn0nu0uq54m
etn0if5b387kdg34gkso    etn0jp4ch3oade7ru959    etn0l954jmnc0cacnr8d
etn0llgfohgul7uvfgp2    etn0mi37jfrmoftbn3m0    etn0mj34e6e048kmd342
etn0njknkv15k4tp768v    etn0oabctj0ti9h5farh    etn0omml95rjapsbp86s
etn0p08aksijaq10td82    etn0qo40ouobqlais10i    etn0sk8pvf7vqjlmdk1g
etn0ue4dunh1sdkt4f4h    etn0v327d84a6okmmku8    etn0v3aeht6t421c7u6f
etn0vlg8u5frc7m96ouv    etn10ev9noqmppbu9nlb    etn128bsg3p0lil5910l
etn12dcp7su0nm0mkvpb    etn12nc16c24c37bgj33    etn131igqpl0dq1b9n7l
etn13rf199idh5ja2seb    etn149emhnigt31uc8qv    etn150hbitbpn7ihc8oe
etn17s9kajm3agdrit5k    etn17u0bognv8bhscs46    etn19c7gkusvt90dgq0a
etn19pd0mjpb9rnpnsl1    etn1a5lgml8au463k7j9    etn1ajksnmlooqnqvgtq
etn1b20apdrlhpf6vfdf    etn1dqh03ojritl9pj3c    etn1dsd9ova1nb1fk2rj
etn1et88ki0i2eghlns1    etn1f4fa4fmgur6eiqnb    etn1gcsngr22cdn4cc46
etn1ggsjqvtvkgaje0bg    etn1i1f7vt7usks84r41    etn1l734muofsau1kecs
etn1lku3mhahlnrv0eh7    etn1mkqujos334m30mqk    etn1ocpe0emkmuddohmh
etn1odjcd9eih3in5fjh    etn1qe6vuj4k9c639ulr    etn1r4ocabf0qimn040e
etn1riasvli5q9fqkirc    etn1s7esl83u1p6eno8n    etn1se5domrta8h8n7f6
etn1soprgmhq2lu2svvd    etn1svdcbpkbuq0vf806    etn1u57v2ksld1mfgbh0
etn1vplrn2078f655v70    etn2017f5mrj4rr7g8l9    etn21ceod8gl6s5o6jnp
etn221r0as8ea64t6u0f    etn23e02e16p13839b2v    etn23pt28uh9alb3lfhv
etn25bvla840jqdhhmff    etn26jsidkki70p15d74    etn26p7kv7jm2rig5854
etn279uavjsb5tulg4av    etn27m0m8troqirspiv7    etn28s19q2thk5m0i393
etn2999abdldjdcol420    etn2bammodr19cv8sbtu    etn2cme61sov1naeehbb
etn2cvj62c5p96buu0te    etn2dincvpr87eeu28up    etn2epr9rquodfn1aba1
etn2ghtunlob8m4dau6s    etn2goo6d9lm0hkp8b7q    etn2h4nr9v724q310pn0
etn2h4ou7ctqjl6dor0m    etn2iv8jcdkppb5vih8k    etn2j3chbdsaro761ecg
etn2jqjuast1i5p41go8    etn2lar2m8b6gknav45v    etn2lp4d9tib1dd2q00s
etn2lv4fo09gco8oe9un    etn2m526lroa0smimdbp    etn2madg68rp9cfq0ro5
etn2p5r2u1lgai20lede    etn2pfjk8sf9cp3ju1l6    etn2qat3kai19q37va1l
etn2r2dtk0pkbodegsi7    etn2rs0gnbu5kknbbsm1    etn2s4qbrmbk6rjjpska
etn2tb11a8uo1ah6dtsj    etn2tuic087asn4gqdo3    etn2vpp7v8hp5qove53j
etn31i7hvdl39ds9llkg    etn329n50fle17hg15qs    etn348380t0sf4eb4r2o
etn399ourp4sa7ovbvmj    etn3a66vp4i2rkqcl78p    etn3b7lu6hgo2p5fu439
etn3bfmlej4au05q22vl    etn3c0cpggirmau5rsgb    etn3fk520g0gqsdkc48g
etn3gcvgvs9q3mfdsr12    etn3h2i509ufs57h7vej    etn3hbof9oom84rckg1p
etn3idv4577m9sjgpa4b    etn3ie2ldspg28ha4ji4    etn3kbe55dl25ud4mrdf
etn3lvd75ecau5o0algs    etn3m4rlmfgkb36568dq    etn3ngkf69lvbag43ja1
etn3qlu5tlchj3g581kp    etn3r716djlkgi86q9r4    etn3s2tsjmkc1au31fum
etn3s8etrfalr9l0d7h0    etn3satp1gt5qjutpaqb    etn3shuarlgaehas61m6
etn3tbjmbvk36hscq3fh    etn3tritfq642sa10cuc    etn3umv1phvrjiaf9lsr
etn40lgtrm0nq05bb4ur    etn41udc8rq4ldi7serq    etn44rdus098lisvoc7c
etn453kh0utqdkdpch9o    etn482g5o8lr32m040o6    etn486afgbleqhdtk0tf
etn496rp98hcgmlpf3vl    etn4cb5h2lmavpmcu0k2    etn4f4co0mjquo4t6ck0
etn4f9j50o26nhlc6765    etn4fk5cpemcufckom16    etn4gd5lspgcmihch18e
etn4ghdu8d3rooc143cr    etn4h1h2jpjbmgvdh425    etn4i19b771juusmlmt4
etn4i522gscb5h9q4v08    etn4iqg2139adth8cnuk    etn4kns8lipncf8h87n8
etn4luaiedj3pk6s2229    etn4m5s7cf315g7munbh    etn4ni8fltdgq6o7d34o
etn4nv4ep8752etqk26t    etn4uarmqvi8drtmnv5f    etn4v12ruhab57iim1jr
etn4v7hme35af66ckrbj    etn508rpp8s52jtks1mn    etn5179rr29qq3v42brk
etn51rdvm8pg9t26osm9    etn539vl92jnrk6etjro    etn571tk31vkhofqgevg
etn58obj5jf0i7aph489    etn5a92v76no4i76b5p5    etn5ah48q867hr7ca9vp
etn5cdc1ttgco7okc07n    etn5hgnhivbsmchm89ji    etn5hm86cnohl8u2hcjr
etn5hmibe5s6abnj0icf    etn5hsmtt99l08lorol7    etn5lavqdc6d1oqrn7ua
etn5lorq8d6qbd1ig7uq    etn5n4982edi7p7msck0    etn5o50q2g2u4nahctda
etn5odk7k15vruip79hg    etn5oihf6ikib37i4266    etn5pegekm3ar6gtqqmd
etn5pild7ecsns6gdc21    etn5s15v4h11t1jrrcv2    etn5s94297cbbd9d4fss
etn5tbebr5c0qup0rh6a    etn5ua3emeet0p9c6g61    etn5vml83jcit4en0jr6
etn60m2q3u5kl80fq0lb    etn61jq28b8qrutn9jav    etn62pplf6vnhdhfdva2
etn64vst0d8qipc7incl    etn671h2qasovlgbabnb    etn683e2br6jmp050tfo
etn6a0k3v7luv45tcnjp    etn6afdu56u9cd18sbei    etn6arba4s3gep92k930
etn6dh1am2l40o3qg71f    etn6e8kmvtjsaqjub2k2    etn6gp7mftp94me1krno
etn6h5emgmjenu097i5p    etn6igi6ar4qurm2hpqd    etn6l5ee6m9rcd3k9imd
etn6lp9u1j13d87tn39r    etn6mfu0qeq39okcd019    etn6mk7htnpunjp4bnmt
etn6nk6ijjgisv7q3im5    etn6ntnivh323n9lq2fl    etn6oa8q7c4l0mce04rv
etn6objf9aopqa9ltfus    etn6olon1ivfsdnpapb1    etn6ottf4phu88q96ho2
etn6r1mjgr341s71co4u    etn6te4kp859rjpupg82    etn6tj1io6ga914idiik
etn71jr451mrhplmbkmf    etn730km2kf9jdk536ec    etn737qp5c7um4l24651
etn75jsr1s3ejpsvmagm    etn75thq5l7fdrl3dh93    etn7789qnm327p9etqac
etn77atb9o1epq4chevd    etn78lr1e87sb2l1hcuf    etn78sonv2iro6g7ol57
etn7999k7n3gmiiqvgke    etn7b6rrrdrnh7kf7n51    etn7bh2qo1v3cva2ta97
etn7bq8154731nq4925c    etn7c07m1e3nnrtpmk8o    etn7d5bq07979o9kridf
etn7ghgipo0c033bfkgd    etn7gvugakp9cjcoooja    etn7h5t38591hl2ulc87
etn7ic4norfmmljnbifo    etn7j5l5gkt6regpqcqm    etn7j7ohhvad5jo5p31v
etn7m22n7jfjflo8h7p0    etn7min9tf5tikst5k11    etn7mukm20e3vqkqllls
etn7n1c12v011nap5me9    etn7puvdfa7uu2jucmqe    etn7q5msijviplp3ss5e
etn7qm9ei1me79snckvp    etn7qq06l7cfg1l2loch    etn7sd4b90q4gehasanm
etn7ubdip3amuol46tgb    etn80n24p2k58je46pc6    etn81o4f5rk8mtccdoad
etn8303gm0vpf7eino6c    etn89km63k1li33bga5p    etn8ch8nkc8d2d61ugs2
etn8f5r5vgh2t0encn3c    etn8faia3s4hbom84dg3    etn8itfl7p1htftigj1u
etn8jcaj70spqneh7cgt    etn8je3aoa5qmitq1nop    etn8krc5kj2l8be6v3c9
etn8l1oj05m6nmq4j2bl    etn8lhpivri4v4jjbhge    etn8mhmetvl3nnfo5msi
etn8mquvvmdvjbmfo56k    etn8pkheamcvmep8guh5    etn8pmo9b35fb9333n03
etn8rm8h8s5ns90rtk2r    etn8t2monmbbrm71vuua    etn8vkt1lsq2r3qke1bq
etn90bom8q70nmesclvp    etn90uen7ltfm3omfrt7    etn91gm08n86bs151u81
etn9236orn0p1gdo0cip    etn92h0gjin6c6a1veqp    etn93g1orr3772lauihd
etn952fh3eo2jd1gtj9h    etn95hf7as24s9cs4ulr    etn95ncqhg5i344rdmai
etn9ak8vbf3kn0j06i51    etn9aqf883qbbh0boneh    etn9dtats9pufttl0b69
etn9e7ekrslja20hvv0s    etn9foq9o4l3sf7m2rdu    etn9g1aj6gkmp527a1l5
etn9i2a631tksrutjjp7    etn9io2ihlusca62gduv    etn9kk2dqvbudpl2cckr
etn9o206mndomdpn9n0u    etn9ob1lqgtod16gjfl7    etn9p8577052puat48co
etn9qpiqa254qavl03gm    etn9r3kk4gf9tokgbvnh    etn9rgfs6h0r1o2evbhr
etn9rs6gge4n6rjatfk7    etn9so4duq5gebck3r3i    etn9t4ip8rnnn1qe21dr
etn9telvl0sq0m7sbb30    etn9trrha20l7nt4f8e6    etn9uc3midg1cqbjt89k
etna0d5hikresa1v8l84    etna0qv6ru792r8tvcke    etna21radv6quf451krp
etna2t0nj0l4f58ri36f    etna45annd9smmbje5fv    etna6bvi9106hppif75t
etna8oh931n9ja2ob6v2    etnaa9fu9n7hjpqh6reo    etnaarfpmfei9p1ogguk
etnabc22db9hrh176oim    etnaeg6ng5kqvi7j0bdl    etnahn19q0vtdsfmmr5s
etnaicqntosd9gfhqqis    etnakncdmq1jub6eugah    etnakr2jtmgc5u0a3252
etnal5pa13cjqibkvbhr    etnamkqd5fmalkttfivd    etnamv6fb81sjt1hgotg
etnanl7279o2gu2hq7tb    etnaopfe136ur8m7i9li    etnaphcnvhu5iq2k0ffc
etnar6dk8im5piv8jre8    etnaslqlo78g4vlcsb7o    etnatq3vjft7173jvbdu
etnau5h5e3r1hdha5iku    etnauabntnotjvt1hb9f    etnauukmc6v3fq02kcof
etnavhcta9tgv4l5rtis    etnavqksj9q5j7vld1p1    etnb0a18t52umhbvl406
etnb1p888fdi3961k33d    etnb31k5e2ee2v6lc5f0    etnb4nqlupu05ci4hjqr
etnb575qn9rluso712c7    etnb63a1qp81iikkj517    etnb7l0hh1gjgebhmcuq
etnbactbuo49o8j2g76r    etnbb7ofahvmtvgckjhd    etnbc9kt7h2i5v89o27o
etnbecgp260nhh978298    etnbeqg2t6f3h9uir7h6    etnbfgu2abpsbqe2a3mf
etnbftich6qeplie022e    etnbgc0i607tqfcbp51a    etnbghvstlupmmmc63tv
etnbgvttosps5mp10i1l    etnbii4r45him152rl1t    etnbjeb9aoc15bs4agjf
etnbocef1bftsoudqnbn    etnbolm35v9ar3ptonp2    etnbpfggectc5dlmn6g8
etnbppms5fg68nf0rr16    etnbrtlini51k7cinbdr    etnbsdekqdsdq347065v
etnbtnbgg71iorq7gc6h    etnbu8ad1dgoglb7o7sb    etnbuqk99uacd5fk1dqm
etnbv142moltqkd4phfj    etnc1vq2itkomm8he2fh    etnc21pt7vr6ck3johkp
etnc261plo0at2uc3m6p    etnc2jqg0kcm2fuv2u1u    etnc2tve13ts2knucr08
etnc363je4lalh7fpgi0    etnc3n9kd99k0977rr4t    etnc3oqbf17drhc1adrr
etnc3pfp3476do623rto    etnc5rq5tuj231s5kki7    etnc6mjl174khmog2383
etnc8soenng72urdge8f    etnc9tk7pkdf30tfmmtn    etncbvvhco22d2io1m9i
etncd99ndnptevva8tp4    etncfrousve6ofbvg67u    etncm5kp8k7kt9pfn6mb
etncmdpt7bt82gkdji7n    etncolc13541cgbmvoah    etncos2uahbkrj6onn27
etncp5gpbo09lffb1r6b    etncpvcmj91ft293rhel    etncsgv53rllgusq3bou
etnct1ale8a6m8rsn1h2    etnctt9sd5sv7h5v3v2c    etnd0apg7i1p88trnndj
etnd36gn82kq54f722cr    etnd4j8l67r4gt9ui0ck    etnd65cbcl0n3guushh0
etnd7sdrivddno09goip    etnd83v48v3v15j27jff    etnd8ca0709i1un7p0pn
etnda33qn538er4or7pg    etndb4ocsit53rlgt7h5    etndbj70g039ne9n3m41
etndc7o5ile831404n12    etndhdqovjdblfickq52    etndj65fujhgcsios3pc
etndjmlvulmr721ib77o    etndke0fdo81b153i93h    etndm5a7cnoga2rc3lpk
etndn941eg62bj9hprod    etndo4n36cp31ve824p5    etndo8nk2auh4afmui4m
etndpt44vtlkqc0o8p90    etndq984sged1i4sdko7    etndrrs0k3njobfs9dam
etndshaa678pccp3kia6    etndsimuefu2sfd7bht1    etndta0jk4us20e557i7
etndtlts7ut66mcemdgb    etne0om86aqefor3phi4    etne12ogr38beqso50d5
etne1fummohokk7u89ff    etne1tk3kg04cv2oot82    etne31ua920oagmiijag
etne36gfcg43aje6vriu    etne3t9a9nmq90hr5nm8    etne4le44e25ukdalsmq
etne5332p9pibqt2siic    etne5be9v4q56ti4n37s    etne72blanpjs6frekh9
etnebn5olbh98fpilssm    etnebodf3qj0c5uh7vo0    etnec2gvnv9p0onb3qjc
etned4gpa14oaql61pbh    etneekiv6194mpo93g35    etneg0m0jn4t5e2bfmbl
etnehl2hqo5ot3bi0j47    etnei5j6noj2sunrt64j    etnejle6hb72cdr6aqps
etnemoa6l07fruj2giov    etneo3a4hp095q810981    etneope4ltdqj4abi29s
etnepo58m9g5t1ga4dqi    etneqk7kjtolv7k2f3t6    etner0au3q0dns25t87c
etnesrp7r5pp4b3c2vvv    etnet0vblde7q06ktm9g    etnetfc8qonhbrambqp0
etneu3vlbiok8dkm6k5t    etneuh23f5767crf2tf3    etnevi42ks5ggrsg3pei
etnf2a8o5mipovuh2qte    etnf9ve36ch7nkhbjk7l    etnfa9viebanlitej0nd
etnfdlh5qpbrdakkqol2    etnfecena5vfg8qtcn4u    etnfei1ku5qbts4fq776
etnfepe5lr9v9pmv2p6l    etnfjeh4md8noj6mgp1r    etnfjeplteensdqfrgr5
etnfkg8ei5n5vc2la5hg    etnfnok72gsg7onc5m26    etnfp8ncmlpjesdkn4u2
etnfpumt8a8qnrl65gej    etnftdqlv2084040ubb9    etnfv350583coc7jh8mq
etnfvpbmbjfikmg2gtoq    etng0c0h2upo4hb5k3pi    etng0vmem6lp5h8updu5
etng159tsca6ta82a8p3    etng6ttphit2c9ddhfmv    etng9ariostodmvtu6v7
etngaklcauonbub50kk5    etngaq4n5qgdiem5h64p    etngbgg0sgectd38ehn6
etngc5t8as5p4pj6tlta    etngdku22dr87khka1dr    etngeboalggu5pp7lmd9
etngepdn2jcqif951ph0    etngfmlo16o46o4om5um    etngg2cn0ujakogthdjj
etnggf25semanvrgge5s    etnghaos3jn15s27j1p5    etnghk87mnn4u6pvnpgl
etnghubspmui0p9e3426    etnglicvbv587e8uqc74    etngngui93u23j4o6397
etngnt04f3j1q7fnlbo6    etngpj3867629hbdm98b    etngqvtst2cp86fv301c
etngu0oc891pko6k07p3    etngu1bpm9k7sgtpq6s7    etngv01ligf0v998engn
etngvj2lq4rtkkfn8gco    etnh15592k38igv9ulq4    etnh1mgbnfhbccmgnebs
etnh3k8uhgin8ajqfj7t    etnh5r17k9t0b9au38l8    etnh94d78ab33fikm9pt
etnhb12rlo1drqi4sm5e    etnhepcssap1u8f5t0d7    etnhho5f959civ2q2j7r
etnhiq29j68eop8h6f15    etnhkee07423th4lih9r    etnhockr5lead7jc4qs5
etnhoh25fn8a5dn48tii    etnhp3jrqt0ud1kbo9kf    etnhpno0i0vp8mhkrt2t
etnht27bvpkve5mugc3d    etnhtmmo6t485qrka1in    etnhussrgvecm5icil9v
etni0uas5d83l85ub2o1    etni11fg6r18kq9hsf6t    etni2t4f6opd4nsvei9l
etni3b4kocod6u9rqt2p    etni4kc8g7ii41qnt7qd    etni5nbqitl0u4v493ak
etni6urggpmfit9f0q7a    etni7fum5ti97uk0t6ug    etni7lajailj31k1npp7
etni7pr0vbkmvjpt637i    etni7v0tm5rfjhdil1o2    etni8j973q23cbtb1gpi
etni8pumlo8mo3e0cemr    etni9bc59iqemem7b0ea    etni9eec374rqalkdi9g
etnia38oap6e8rfpqr84    etnians6lo3ke8309mtc    etnib6jc4cib54q35nh9
etnie52uumtmodvc1okp    etniefi915f2bnqmarm7    etnigsahlf4p223cl0jc
etnii1ju8uijknrggone    etnijbr5t2gd84qkpa30    etnije6hfjdrhavm7ft0
etnikssgtjfgpcc881bq    etnil74t99i3oefhrju7    etnilaf6mqjllvtuurbo
etnin2kb39kbg8lta5k2    etniphg9los5mn9401e6    etnis6qaj1sk9vqolhqa
etnisidgnu1l9qcu5g2p    etnisjul4c2s6h2cc3a7    etnispt7jvm39n634hmk
etnit9es201h3hptn1bi    etnitjcdbc1ndau3dguv    etnj1s6j9v9b0hnc1iki
etnj1vkbheg4po6bt3i6    etnj270tv1liq56q0n38    etnj2tmud2m7822df94r
etnj3c42ga769a15eq6i    etnj4bp0f4ctd3caa5kb    etnj6ntcvm5vilqfd8cg
etnj7hsjf2plihgs39uv    etnj7mmq9ooah97rh02b    etnj8bqd00kll7i07jlg
etnja0qqnqgrjipkum9h    etnjad3mchcode1qg965    etnjd0s2v77gjl9ljagb
etnjek0j3aghd4e46u03    etnjf8jnj5j95e5m5e1u    etnjjfgipe502bvno7lc
etnjjj9uq5ih31hs44gm    etnjkrr1uhjoeg2vokll    etnjm7soivub47mn2har
etnjm9pdbe7amiqfk176    etnjpjnd8intbddot24e    etnjpkft840qk99pq6se
etnjpnt4pek84j5t5lme    etnjrbtqm9qt8q134pgu    etnjruqlaj4v6iflui2k
etnjt2a2ldvnu36rq7vd    etnju7lnng1luj97hrau    etnju9njeilujpsgbuch
etnjuarnu9nbbb5nrvo5    etnk0r1bk3jcr6q6qbkp    etnk1aoovnfellc1ugt7
etnk1jct94cpuhuk3hga    etnk5ik1ajp39th5vbd1    etnk8u3i6u12sra6kv9q
etnkb88aqv55q8alchdr    etnkb9br3mvraleihuvk    etnkbctrass3da65q31j
etnkbu1lag6kh0lvpo3v    etnkd5smj735945a0sta    etnkdbbage40lob3lp9s
etnkdiihshiblingbr4q    etnkfhfg62s289q3jr77    etnkfsge08bqq4q031rc
etnki93q2acvis1k52ag    etnklnarrrl9if46bcct    etnkm077bpamcfti0r82
etnkmc7mj84b2s84t61p    etnknhpm59tatihh4kbk    etnkosi73mb07u52aa5p
etnkqrek67i3l296koan    etnkr25d1qgm50un6sl1    etnkr8t9kqsdab2lhu3l
etnkscatmqg6lkgm6hcm    etnkslhdfen5v16fth8t    etnkt2imnks55qf4jif6
etnkts37t6qgp1sua5bq    etnkudgceo96b4r1to1k    etnkv0sj4mdq8ji40i5h
etnkvbgqavdnf0gv67jk    etnl11u1i4eo21g3s6bq    etnl2jggopjsden3ffvh
etnl2svgqd6jdrm1uc0k    etnl46ekfd06beoik9et    etnl6cu4u38bmd7sdc7p
etnl7rfonso4ltpl0130    etnl9d614rjuimi2q9q2    etnl9jhnj1f78dead7i0
etnlalchtcmqjo3c4umj    etnlbmirjtt8obhn5agv    etnlc3067hhpmpecbkv3
etnlck4g15ua2n34m0pv    etnld2lk8jgf1fvj0092    etnle1vukpstmf22glam
etnlesfmlrqddm250c40    etnlfbcmtn86m6mtiuak    etnlg7guk8405rcpprld
etnlh8atro4pegnjgcav    etnlhthkhhbfo4p1ki3s    etnljhdsj422jhii17ht
etnll58egb0if4lcibvl    etnlopesa71asmbfq3qp    etnlrmdturk4cs99omn9
etnlrqrbkbjbf3372e67    etnls7skbof6qq3rlsn0    etnlt7o6a39a1n00hup5
etnlu5vqdtvnp7gamq0d    etnlu8p30r8qdb7adnhv    etnlvquupc5pgholujgp
etnm0hqum825v5q8cdj4    etnm10nah7fl3gjdrt3b    etnm28nqh0tk10e1ck34
etnm44q6l6lq0kkopoak    etnm55u937b7ht8172tb    etnm5nd9k8iue3e8vc0r
etnm5va1v1cofhocp3f4    etnm624rn6rf219oe0it    etnm62nb2g45hj83v3nl
etnm6uph5m57i4empmk6    etnm7gqn0to7kt9onhp9    etnm9830dp0i7eto5bp6
etnm9b2hgqnq4o5ug3rc    etnmbqukhoj9df7vgquq    etnme9he9pgvheh3c346
etnmhei69pikicrm29so    etnmi8kmsmudhh7mt9lr    etnmics8bvfjuh4j9c05
etnmjgvps1gm05shq68b    etnmjj163pvi08hu1ge5    etnmljaitddbfabnatab
etnmorlsikr0sh2de8di    etnmpbvtiju3ekgmdaks    etnmr1b752k07r5h62qp
etnmrcrrbqrtedg7d5tc    etnmroiqmaa3lfl3opd7    etnms5oo9iofngv83nhh
etnms9qfqej3p30q7l9t    etnmsqu90tr7llbeijev    etnmt24m40av0q1vjgl8
etnmtke7n0hstlgf6nic    etnmu7seoh33caqs0dp3    etnmulveneib6lkjljma
etnn00toiljdhhs5kf9q    etnn0an5mp16pn5asqgp    etnn14u1pgba0b6cm0g4
etnn17j101ooj50esa5f    etnn38j5f4u45p6466tp    etnn3a5c1j4fn7a98bs5
etnn3gs4nt6bv5mbkj0n    etnn4k9i7d17riepiqam    etnn9ch7r3m74o2r7bnf
etnncq1odt8qa001ai3b    etnndnc39ioipollqqhl    etnnea347tnt5msjehj0
etnnfgmg0qj6moci0810    etnnj9g8vf4ihn85k8rs    etnnm0cmb9baho0b6iug
etnnqi1ftvh2ujtn51r1    etnnt42rjl7ko779hdhp    etno15jil9ctaurpjlvk
etno39ltdc07hmes2o68    etno3j69le99mb9t16od    etno4ps193o9eev57kvf
etno57rmaq1scaruj0s2    etno81fk1popvl6878uu    etno93jptniuppfb206c
etno9ur1te8svdb3uebk    etnoac766p0q20jg2tps    etnod29er8h09mmq75l5
etnodrisr7a746cgmt4d    etnoe8lsng6t2cbu0uq8    etnof5j00ikkbf2bq4ho
etnoimfg8qufdaggi8ro    etnok9dvmblk1g47ubeb    etnon55vlcnrmgmh4nqp
etnooouhl8q3epgfqcs0    etnoqunmg5vejs5h9edf    etnot14j21lg144utluo
etnotb6841cg71g2uco0    etnotehi2stcpdo0cjsn    etnou58eeskoehetr1ta
etnov5qlkrj9trqungtj    etnp0n0l4s1ii3pfe04s    etnp28nboroe854o6pim
etnp2bfhbuqg1ji40ugq    etnp3u8nr160mjjpmbf5    etnp8g05hk0nf7to9l72
etnp9f7uqj4pp06rjp7c    etnpbuti7oufj2snllrv    etnpd9r9nfap3c0bud9r
etnpdip8smf2q0l2lpt4    etnphdf37qd6e0bln3c1    etnpi3nsj62kfcdo1693
etnpingljkfu8lfb286l    etnpisjhugcdq63j42hi    etnpit4gg56bd0geo38m
etnpkhueu26r138bg5vj    etnplogej9ha5lbor8vg    etnpqq7fa3cngn2oolas
etnpqu688m4llufmv169    etnprait7mpv4j1hjrbg    etnpshbuncq3v0ghtju0
etnptgo38jrqs9pupj7l    etnq0p2e6stfckmq30ei    etnq2cc1lu66maqmfflc
etnq32vblkp06qhcddip    etnq3uoqs461e8nk79a0    etnq43jdbfqb3m3rcsfa
etnq4m501pqg6ji4dk4o    etnq66slo2s8ks33qpmj    etnq6ousl3m33kdsh8l3
etnq7e97u1e0mi8fbrg0    etnq9lsobt2a7g2pi5vr    etnq9vu03klv8iv0h7j0
etnqb177rgdf4tg4chvp    etnqep7u8ke2btoojoog    etnqgop3s8thhhs634et
etnqh5f6arn16h8is3vs    etnqhk8spj7tnaihpk1i    etnqi584u4idpi6iumgf
etnqiejilqbftf75mra5    etnqilp5hcvri86jhgns    etnqiueto1kasn0cecg3
etnqjb2o36urig35qtbi    etnqo9mj1p0tc385p2g0    etnqonoq7dqjm2vrb73m
etnqq6p8hqfbho1eid4n    etnqqm06i6luq6p5jihn    etnqrhpg3rb5rhrc2jia
etnquj4kkkj3k7tvpihe    etnr0evo6mog07p5up0a    etnr1ctpv5qer2k6lst4
etnr325pdkg0sjbh6m9h    etnr3mmdj4shnj49qmuq    etnr7a9qd5en7qppnnfd
etnr8b7hnglsj9tttdiu    etnr9k8kbrjcc4gksn9a    etnrdtt8ofudk34ivl4k
etnrh0880di6n4bi88ds    etnrh5brqlj2ifbgcqvp    etnrhiqqr6v3sk3um7si
etnrienfbsdlihfmikct    etnrl72k7ka8v1fsj2f8    etnrl9q2isl6gv0drsdg
etnrpiigajocin6l6tjk    etnrpkb65pn3rdtpf8bi    etnrpniumbmdr9fg70j0
etnrpv10p46iveu91nl9    etnrrgfr93c9o0t3osip    etnrsj9m7nfegve2m0l0
etnrsnh5no63q7dn6ru2    etnrsvhq2pebg11g8hba    etnru1d7b5t6l6atr3nm
etnru7279i5etsrde1ug    etnrvgdaisptjc7702uo    etns0641qf73btm7j21k
etns3nt5ifahebmgqp5s    etns5g9ugrib1l8i80gu    etns6u4mdtoe4b39c9lr
etns809eem44446ieqjc    etns8fhkn70uad01idqd    etns8l8j1ddv22e1j4d7
etns9r3kv6cl95p3criu    etnsa6ubpntftfr15n90    etnsadv47gr69hqlnk1i
etnsaq9rbg08mld6fgbh    etnsehn1gqvq0kjj77f6    etnsfck2irefuiht3iv6
etnsg9tiqi753atih4ua    etnshltnthjjomm1gibv    etnsidll60in31a5eogv
etnsm8bbadnqlakatv2c    etnsmrr0mttm87c5r69h    etnsn489uhs9vrav1pma
etnss9vbn77hmgnadink    etnssc71t8phu9duki0i    etnsudgckugd1qsno5iu
etnsuhkq2i3o3g69gb8p    etnsutkdivn1vtoeqoj9    etnsvm1i074tt0ndtkc3
etnt0p6gcq5l50jn8se6    etnt1ub86fnnkodeaocc    etnt395896lvesdle9tb
etnt3s4fv4nju68i2ea3    etnt4976hu16cop8k15f    etnt4fb8ep6q98rod3nt
etnt5trjg7k6mja7jds9    etnt66itpk643u6qfjt7    etnt7s7fo4p8m5on7pu3
etnt7vmff37mh4o8vvdn    etntaknjq9bq496nrp0t    etntbjj1vggtqf821ppf
etntbkbf4su57rudikg7    etntbu7ko3u5pl5bimon    etntcq035t8itnhecest
etntepi087re76d7ieen    etntg4ij2sehqah2ki3i    etntgscr6l8b3j02c71d
etntiu7rg5390fssgspr    etntl1pur5coev6qfcgr    etntoiag729s5le45ivh
etntqunisnljcj0u9idb    etntqv0ci538is7dp30a    etntron5t5phlmfkrhev
etntt07u4cgsh7brkgrg    etntunehjleg8urn47gf    etnu05r83sshqhngt8sl
etnu34sobk4hbciv0p0u    etnu536mmt4p033o0tic    etnu84e8albehgkft9po
etnu8bjkm7msbhjg36j1    etnu98gtahltkvietir4    etnuc1g8o0b6h78rtfrv
etnui91l980qjvc7o8tf    etnuigem054aj10idjau    etnuk1u7v97f7iv65qtn
etnukag07fvql7d6m8t4    etnukd6nkv47nkrqq117    etnulnk1jaighnc2lh0e
etnulqv5j6r33m1tbv77    etnumrm1blujphdieb7e    etnuqrcd3pke4scvsc40
etnutcvjd946bs0r312k    etnuu4nhn17rquv2r45o    etnuvfv3vs71dlnr94fq
etnuvj1vkeqgibt8s8a1    etnv002ki5i1h45rvf76    etnv043fer9t3t0o7qfr
etnv0ffrtlci0l3s9j0e    etnv0i6p2detgdfq699s    etnv0sr4t2q5bmm6chk8
etnv2l9kok3lti7q9n4m    etnv34vgvc4652s9jq29    etnv3gv86nef2dpkqg96
etnv40917i856mbgo1q9    etnv47vg78ois2p9o24j    etnv4rm39ihi1ec602rm
etnv5bolkbospppf6tpn    etnv5g6qvh4h3dv5ghnf    etnv5jfpufttfk2mn3lh
etnv6mr75vuukm1p8t4s    etnv6o39k3pafjg8lhtd    etnv80enhif21k32bckk
etnvd4q9njq4mngt3mks    etnvdmikvjb56hckgfh4    etnvejjtf1g7asb1q73h
etnvep1vbeo3dngsrqal    etnvh214j9bid99t2tr1    etnvhbgsa3q97u1u09ml
etnvhs8j7v22m0m4i0fm    etnvls7mtsvueu5vik9c    etnvltbkr3nluq5ldgge
etnvm0pqd7t33g7roo8h    etnvmm88cmlbafv72vel    etnvo8bg72dehjv1on8p
etnvs67q6qhpl1gc1t31    etnvt44p7q8replglj42    etnvtfjhrc89rgbg5h9d
""".split())
# END BLOCKED CIDS

BLOCKED_CID_LENGTHS = frozenset(len(cid) for cid in BLOCKED_CIDS)


def main():
    started = now()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="JSON config file")
    parser.add_argument("a", nargs="?", type=int, default=0, help="shard remainder (default: 0)")
    parser.add_argument("b", nargs="?", type=int, default=1, help="number of shards (default: 1)")
    parser.add_argument("-p", "--parallel", type=int, default=10)
    parser.add_argument("--verify", action="store_true",
                        help="only compare this shard and report time ranges of missing files")
    parser.add_argument("--max-errors", type=int, default=100,
                        help="abort a copy pass after this many errors that cannot be "
                             "skipped, instead of grinding through every remaining "
                             "object on a failing source (0 disables; default: 100)")
    parser.add_argument("--stall-timeout", type=int, default=300,
                        help="kill rclone if it prints nothing for this many seconds; "
                             "--stats 10s should print continuously (default: 300)")
    parser.add_argument("--fast-list", action="store_true",
                        help="list with rclone --fast-list: far fewer S3 requests on a "
                             "large bucket, at the cost of holding the listing in "
                             "rclone's memory as well as this script's")
    parser.add_argument("--no-traverse", action="store_true",
                        help="copy with rclone --no-traverse: skips rclone's own "
                             "destination listing in favour of one lookup per copied "
                             "file; only pays off when little is left to copy")
    parser.add_argument("--state-dir", type=Path,
                        help="state directory (default: copy_s3_state_<cid>)")
    parser.add_argument("--rclone", default="rclone", help="rclone executable")
    args = parser.parse_args()
    if args.b <= 0 or not 0 <= args.a < args.b:
        parser.error("require b > 0 and 0 <= a < b")
    if args.parallel <= 0:
        parser.error("require -p > 0")
    if args.max_errors < 0:
        parser.error("require --max-errors >= 0")
    if args.stall_timeout <= 0:
        parser.error("require --stall-timeout > 0")
    try:
        ensure_rclone(args.rclone)
        return run(args, started)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())