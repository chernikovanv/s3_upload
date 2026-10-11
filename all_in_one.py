#!/usr/bin/env python3
"""Prepare a ticket's backup export and invoke s3_upload.py."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from s3_upload import atomic_write, validate_config, load_blocked_cids as uploader_blocked_cids

REPO = Path(__file__).resolve().parent
SEC = Path.home() / "sec"
EXPORTS = Path.home() / "exports"
CTYPES = ("postgresql", "mysql", "redis", "clickhouse", "mongodb", "greenplum")


def _read_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path, value):
    atomic_write(Path(path), (json.dumps(value, ensure_ascii=False, indent=4) + "\n").encode())


def load_blocked_cids():
    return uploader_blocked_cids(SEC / "org_cids.csv")


def prepare_export_dir(ticket):
    EXPORTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = EXPORTS / ticket
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def manual_ticket_info(ticket):
    data = {"id": ticket}
    data["cluster_type"] = resolve_ctype(input("Тип кластера:"))
    data["s3_endpoint"] = input("S3 endpoint:").strip()
    data["s3_bucket"] = input("S3 bucket:").strip()
    data["s3_access_key_id"] = input("S3 access key (короткий):").strip()
    data["s3_secret_key"] = input("S3 secret key (длинный):").strip()
    data["cluster_id"] = input("Идентификатор кластера:").strip()
    write_json(EXPORTS / ticket / "ticket.json", data)


def get_ticket_info(ticket):
    meta = _read_json(SEC / "all_in_one_config.json")
    subprocess.check_call([
        sys.executable, str(REPO / "tools/supporthub_get_ticket.py"),
        "--key", str(SEC / "ticket_private_key.txt"),
        "--key-id", meta["ticket_key_id"], "--sa-id", meta["ticket_sa_id"],
        "--ticket", ticket, "--out", str(EXPORTS / ticket / "ticket.json"), "--force",
    ])


def get_gpg_key(cid):
    key = _read_json(SEC / "gpg_keys.json").get(cid)
    if not key:
        raise ValueError(f"no GPG key for {cid}; supply --source-config from dbaas s3_migration")
    return {"key_id": key["gpg_key_id"], "key": key["data"]}


def resolve_ctype(ctype):
    if not isinstance(ctype, str):
        raise ValueError("cluster type must be a string")
    ctype = ctype.lower().strip().split("-")[-1]
    if ctype.endswith("_cluster"):
        ctype = ctype[:-len("_cluster")]
    if ctype not in CTYPES:
        raise ValueError(f"invalid cluster type: {ctype}; expected one of {', '.join(CTYPES)}")
    return ctype


def resolve_region(endpoint):
    return "ru-msk" if "vkcloud-storage" in endpoint else "US"


def prepare_upload_config(ticket, source="mds", source_config=None, blocked_cids=None):
    ticket_info = _read_json(EXPORTS / ticket / "ticket.json")
    cid = ticket_info["cluster_id"].strip()
    ctype = resolve_ctype(ticket_info["cluster_type"])
    blocked_cids = load_blocked_cids() if blocked_cids is None else blocked_cids
    if cid.lower() in blocked_cids:
        raise ValueError(f"{cid} is a cluster in our organization; BLACKLISTED")

    config = {"cid": cid, "cluster_type": ctype}
    if source_config is not None:
        imported = _read_json(source_config)
        if not isinstance(imported, dict):
            raise ValueError("source config must be a JSON object")
        if imported.get("cid") != cid or resolve_ctype(imported.get("cluster_type", "")) != ctype:
            raise ValueError("source config CID and cluster type must match the ticket")
        for name in ("source", "gpg", "clickhouse", "mongodb"):
            if name in imported:
                config[name] = imported[name]
    elif source == "yandexcloud":
        raise ValueError("--source yandexcloud requires --source-config from dbaas s3_migration")
    else:
        config["gpg"] = get_gpg_key(cid)

    if source == "mds":
        meta = _read_json(SEC / "all_in_one_config.json")
        config["source"] = {
            "endpoint": "https://s3.mds.yandex.net",
            "prefix": f"s3://copernic-cp-{cid}-backups/",
            "access_key": meta["copernic_access_key"],
            "secret_key": meta["copernic_secret_key"],
            "region": "ru-central1",
        }
    endpoint = ticket_info["s3_endpoint"].strip()
    if "://" not in endpoint:
        endpoint = "https://" + endpoint
    bucket = ticket_info["s3_bucket"].strip()
    if not bucket.startswith("s3://"):
        bucket = "s3://" + bucket
    config["destination"] = {
        "endpoint": endpoint, "prefix": bucket,
        "access_key": ticket_info["s3_access_key_id"],
        "secret_key": ticket_info["s3_secret_key"],
        "region": resolve_region(endpoint),
    }
    try:
        validate_config(config)
    except ValueError as exc:
        if ctype in ("clickhouse", "mongodb") and ctype not in config:
            raise ValueError(f"{exc}; supply restore fields using --source-config from dbaas s3_migration") from exc
        raise

    output = EXPORTS / ticket / "config.json"
    if source_config is not None and Path(source_config).resolve() == output.resolve():
        raise ValueError("--source-config must be separate from the per-ticket runtime config.json")
    write_json(output, config)
    print(f"Ticket {ticket}: cluster {cid} ({ctype}), source {source}", flush=True)
    return output


def run_upload(ticket, engine="rclone", walg=None):
    command = [sys.executable, str(REPO / "s3_upload.py"),
               str(EXPORTS / ticket / "config.json"), "--engine", engine]
    if walg:
        command.extend(["--walg", walg])
    subprocess.check_call(command, cwd=EXPORTS / ticket)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    manual = parser.add_mutually_exclusive_group()
    manual.add_argument("--manual", action="store_true")
    manual.add_argument("--no-manual", action="store_false", dest="manual")
    parser.set_defaults(manual=False)
    parser.add_argument("ticket", help="ID тикета из backoffice")
    parser.add_argument("--source", choices=("mds", "yandexcloud"), default="mds")
    parser.add_argument("--source-config", type=Path, help="JSON generated by dbaas s3_migration CID")
    parser.add_argument("--engine", choices=("rclone", "walg"), default="rclone")
    parser.add_argument("--walg", help="WAL-G executable override")
    args = parser.parse_args(argv)
    if not args.ticket or args.ticket in (".", "..") or Path(args.ticket).name != args.ticket:
        parser.error("ticket must be one directory name")
    if args.source == "yandexcloud" and args.source_config is None:
        parser.error("--source yandexcloud requires --source-config")
    if args.walg and args.engine != "walg":
        parser.error("--walg requires --engine walg")
    if args.walg and "/" in args.walg:
        # The child runs in the ticket directory.
        args.walg = os.path.abspath(args.walg)
    try:
        blocked = load_blocked_cids()
        if args.source_config:
            if args.source_config.resolve() in {
                    (EXPORTS / args.ticket / name).resolve() for name in ("config.json", "ticket.json")}:
                raise ValueError("--source-config must be separate from per-ticket runtime files")
            _read_json(args.source_config)
        prepare_export_dir(args.ticket)
        if args.manual:
            manual_ticket_info(args.ticket)
        else:
            get_ticket_info(args.ticket)
        prepare_upload_config(args.ticket, args.source, args.source_config, blocked)
        run_upload(args.ticket, args.engine, args.walg)
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"FATAL: export command failed (exit {exc.returncode})", file=sys.stderr)
        return exc.returncode if exc.returncode > 0 else 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
