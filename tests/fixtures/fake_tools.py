#!/usr/bin/env python3
"""Offline rclone/WAL-G subprocesses backed by a temporary directory.

Tests install this script in <sandbox>/bin. It never opens network connections.
WAL-G's backup selection is represented by an explicit fixture object list.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARGS = sys.argv[1:]
CONTROL = json.loads((ROOT / "control.json").read_text())


def option(name):
    return ARGS[ARGS.index(name) + 1]


def storage_path(uri):
    if uri.startswith("s3://"):
        return ROOT / "storage" / uri[5:]
    if uri.startswith(("source:", "destination:")):
        return ROOT / "storage" / uri.split(":", 1)[1]
    return Path(uri)


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def record(data):
    with (ROOT / "calls.jsonl").open("a") as stream:
        stream.write(json.dumps(data) + "\n")


def rclone():
    command = next(item for item in ARGS if item in ("lsjson", "copyto", "copy", "deletefile", "cat"))
    index = ARGS.index(command)
    values = ARGS[index + 1:]
    record({"tool": "rclone", "command": command, "args": ARGS})
    if CONTROL.get("source_list_fail") and command == "lsjson" and values[0].startswith("source:"):
        sys.exit("AccessDenied: source listing")
    path = storage_path(values[0])
    if command == "lsjson":
        files = path.rglob("*") if "--recursive" in ARGS else path.glob("*")
        result = []
        for file in sorted(files):
            if "--files-only" in ARGS and not file.is_file():
                continue
            if "--dirs-only" in ARGS and not file.is_dir():
                continue
            result.append({"Path": file.relative_to(path).as_posix(), "IsDir": file.is_dir(),
                           "Size": file.stat().st_size if file.is_file() else -1,
                           "ModTime": datetime.fromtimestamp(file.stat().st_mtime, timezone.utc).isoformat()})
        print(json.dumps(result))
    elif command == "copyto":
        target = storage_path(values[1])
        metadata = "__migration__/config-" in values[1]
        if metadata and CONTROL.get("fail_metadata"):
            sys.exit("AccessDenied: metadata upload")
        copy_file(path, target)
        if "__migration__/config-" in values[0] and CONTROL.get("bad_metadata"):
            target.write_bytes(b"corrupted metadata")
    elif command == "copy":
        target = storage_path(values[1])
        names = Path(option("--files-from0")).read_bytes().decode().split("\0")
        for name in filter(None, names):
            copy_file(path / name, target / name)
        print(json.dumps({"level": "notice", "stats": {"transfers": len(names) - 1}}), file=sys.stderr)
    elif command == "deletefile":
        path.unlink()
    elif command == "cat":
        sys.stdout.buffer.write(path.read_bytes())


def walg():
    command = "copy" if "copy" in ARGS else "backup-list"
    destination = json.loads(Path(option("--config")).read_text())
    entry = {"tool": "walg", "binary": Path(sys.argv[0]).name, "command": command,
             "args": ARGS, "destination_config": destination, "environment": dict(os.environ),
             "config_mode": Path(option("--config")).stat().st_mode & 0o777}
    if command == "copy":
        entry["source_config"] = json.loads(Path(option("--from")).read_text())
    record(entry)
    for value in CONTROL.get("leak", []):
        print(value, file=sys.stderr, flush=True)
    target = storage_path(destination["WALG_S3_PREFIX"])
    if command == "backup-list":
        if CONTROL.get("list_exit"):
            sys.exit("AccessDenied: destination backup list")
        if "list_output" in CONTROL:
            print(CONTROL["list_output"])
        else:
            backups = sorted((target / "basebackups_005").glob("*_backup_stop_sentinel.json"))
            print(json.dumps([{"backup_name": p.name[:-len("_backup_stop_sentinel.json")]} for p in backups]))
        return
    if CONTROL.get("slow_copy"):
        child = subprocess.Popen([sys.executable, "-c",
                                  "import pathlib, sys, time; p = pathlib.Path(sys.argv[1]); "
                                  "exec('while True:\\n p.write_text(str(time.monotonic()))\\n time.sleep(0.05)')",
                                  str(ROOT / "heartbeat")])
        (ROOT / "ready.json").write_text(json.dumps({"parent": os.getpid(), "child": child.pid}))
        time.sleep(120)
    source = storage_path(entry["source_config"]["WALG_S3_PREFIX"])
    if CONTROL.get("fail_copy") or source.as_posix().endswith(CONTROL.get("fail_root", "!never!")):
        sys.exit("AccessDenied: copy refused")
    for name in CONTROL["selected_objects"]:
        file = source / name
        if file.is_file():
            copy_file(file, target / name)
    print("Success copy.", flush=True)


if Path(sys.argv[0]).name == "rclone":
    rclone()
else:
    walg()
