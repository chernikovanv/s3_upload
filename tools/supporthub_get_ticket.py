#!/usr/bin/env python3
"""Fetch a backup-export request from Yandex Cloud Support Hub and take it into work.

Usage:
    python3 tools/supporthub_get_ticket.py --key SA_KEY.pem --sa-id <SA_ID> \\
        --ticket <TICKET_ID> --out <TICKET_ID>.json [--dry-run] [--skip-status] [--force]

Steps:
  1. Read the ticket and write its fields to --out as JSON (always, even if nothing
     else happens). The S3 fields are parsed from the request form in `description`.
  2. If the ticket is already in work (private status `in_progress`, or it has an
     assignee), stop without changing anything and exit with code 3, unless --force.
  3. Apply the `take-on` action: status becomes `in_progress`, the service account
     becomes the assignee. The customer sees "In progress" in the console.
  4. Add an internal comment (message type `inner`, not visible to the customer).

Authentication: an authorized key of a service account (PEM, as issued by
`yc iam key create`; the first line carries the key id) is exchanged for an IAM token,
which is kept in memory only. Requests go to the Support Center private API directly —
the backoffice gateway accepts browser sessions only.

The output JSON contains the customer's S3 access key and secret key. It is created
with mode 0600; handle and delete it accordingly.

Exit codes: 0 done (or --dry-run), 3 ticket already in work and nothing changed,
1 any error. Note: if take-on succeeded but the comment failed, the exit code is 1
and the status is already changed — rerun with --skip-status to add the comment.
"""

import argparse
import base64
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

IAM_URL = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
API_BASE = "https://support-center-api.private-api.cloud.yandex.net/private/v1"
MESSAGE_TYPE = "inner"
EXIT_IN_WORK = 3

# Questions of the backup-export request form -> output fields
LABELS = {
    "Эндпоинт S3": "s3_endpoint",
    "Идентификатор бакета в S3": "s3_bucket",
    "Секретный ключ для доступа к S3": "s3_key",
    "Идентификатор кластера": "cluster_id",
}
PARSED = ["cluster_id", "s3_endpoint", "s3_bucket", "s3_access_key_id", "s3_secret_key"]


def mask(text):
    return re.sub(r"(t1\.|y[0-3]_|AQAD-|eyJ)[A-Za-z0-9._\-]+", "<masked>", text)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def iam_token(key_path, sa_id, key_id=None):
    lines = key_path.read_text().splitlines()
    header = next((line for line in lines if line.startswith("PLEASE DO NOT REMOVE")), "")
    if key_id is None:
        match = re.search(r"Key ID <?([a-z0-9]{20})>?", header)
        if not match:
            raise SystemExit(f"{key_path}: no key id in the first line, pass --key-id")
        key_id = match.group(1)
    pem = "\n".join(line for line in lines if line != header)
    key = serialization.load_pem_private_key(pem.encode(), password=None)

    now = int(time.time())
    jwt_header = {"alg": "PS256", "typ": "JWT", "kid": key_id}
    payload = {"aud": IAM_URL, "iss": sa_id, "iat": now, "exp": now + 600}
    signing_input = f"{b64url(json.dumps(jwt_header).encode())}.{b64url(json.dumps(payload).encode())}"
    signature = key.sign(
        signing_input.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    response = requests.post(IAM_URL, json={"jwt": f"{signing_input}.{b64url(signature)}"}, timeout=30, verify=False)
    if response.status_code != 200:
        raise SystemExit(f"IAM: HTTP {response.status_code} {mask(response.text[:200])}")
    return response.json()["iamToken"]


def parse_description(text):
    """Form blocks are separated by '---'; the first non-empty line is the question, the rest is the answer."""
    fields, problems = {}, []
    for block in re.split(r"^\s*---\s*$", text, flags=re.M):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines:
            continue
        name = LABELS.get(lines[0])
        if name is None:
            problems.append(f"unknown_question:{len(lines[0])}_chars")
            continue
        values = lines[1:]
        if name == "s3_key":
            fields["s3_access_key_id"] = values[0] if len(values) > 0 else ""
            fields["s3_secret_key"] = values[1] if len(values) > 1 else ""
            if len(values) != 2:
                problems.append(f"s3_key:{len(values)}_lines")
        else:
            fields[name] = " ".join(values)
            if len(values) != 1:
                problems.append(f"{name}:{len(values)}_lines")
    return fields, problems


def ticket_fields(ticket, service):
    fields, problems = parse_description(ticket.get("description") or "")
    cluster_types = [s for s in ticket.get("services", []) if s != service]
    if len(cluster_types) != 1:
        problems.append(f"cluster_type:{len(cluster_types)}_services")
    return {
        "id": ticket["id"],
        "publicStatus": ticket.get("publicStatus"),
        "supportLevel": ticket.get("supportLevel"),
        "cluster_type": ";".join(cluster_types),
        **{name: fields.get(name, "") for name in PARSED},
        "parse_status": "ok" if not problems and all(fields.get(name) for name in PARSED) else "check",
        "parse_problems": problems,
    }


def write_json(data, out):
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
    os.chmod(out, 0o600)


def get_ticket(token, ticket_id):
    response = requests.get(f"{API_BASE}/tickets/{ticket_id}",
                            headers={"Authorization": f"Bearer {token}"}, timeout=15, verify=False)
    if response.status_code != 200:
        raise SystemExit(f"get ticket: HTTP {response.status_code} {mask(response.text[:300])}")
    return response.json()


def take_on(token, ticket):
    response = requests.post(
        f"{API_BASE}/apply-action",
        json={"ticketId": ticket["id"], "action": {"type": "take-on", "payload": {}}},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
        verify=False,
    )
    if response.status_code != 200:
        raise SystemExit(f"take-on: HTTP {response.status_code} {mask(response.text[:300])}")
    return response.json().get("ticket", {})


def add_comment(token, ticket_id, text):
    response = requests.post(
        f"{API_BASE}/messages",
        json={"ticketId": ticket_id, "message": text, "type": MESSAGE_TYPE, "attachmentIds": [], "summoned": []},
        headers={"Authorization": f"Bearer {token}", "Idempotency-Key": str(uuid.uuid4())},
        timeout=15,
        verify=False,
    )
    if response.status_code not in (200, 201):
        raise SystemExit(f"add comment: HTTP {response.status_code} {mask(response.text[:300])}")
    return response.json()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--key", required=True, type=Path, help="service account authorized key (PEM)")
    parser.add_argument("--sa-id", required=True, help="service account id")
    parser.add_argument("--ticket", required=True, help="Support Hub ticket id")
    parser.add_argument("--out", required=True, type=Path, help="where to write the JSON")
    parser.add_argument("--key-id", help="key id; default: taken from the first line of --key")
    parser.add_argument("--comment", default="MDB: взяли в работу", help="internal comment text (default: %(default)s)")
    parser.add_argument("--service", default="mdb-backup-export",
                        help="form service, excluded from services when deriving cluster_type (default: %(default)s)")
    parser.add_argument("--skip-status", action="store_true", help="do not take the ticket on, only add the comment")
    parser.add_argument("--force", action="store_true",
                        help="proceed even if the ticket is already in work: take it over to the service "
                             "account if take-on is available, and add the comment")
    parser.add_argument("--dry-run", action="store_true", help="only write the JSON, do not change the ticket")
    args = parser.parse_args()

    token = iam_token(args.key, args.sa_id, args.key_id)
    ticket = get_ticket(token, args.ticket)
    data = ticket_fields(ticket, args.service)
    write_json(data, args.out)
    print(f"saved {args.out} | parse_status={data['parse_status']} {data['parse_problems'] or ''}")

    state = f"{ticket.get('publicStatus')}/{ticket.get('privateStatus')}, assignee={ticket.get('assignee')}"
    in_work = ticket.get("privateStatus") == "in_progress" or bool(ticket.get("assignee"))
    if args.dry_run:
        print(f"dry-run: ticket not changed (now {state}{', already in work' if in_work else ''})")
        return
    if in_work and not args.force:
        print(f"{args.ticket} is already in work ({state}), nothing changed. Override with --force")
        sys.exit(EXIT_IN_WORK)
    if MESSAGE_TYPE not in ticket.get("messageTypes", []):
        raise SystemExit(f"message type {MESSAGE_TYPE} is not allowed on {args.ticket}: {ticket.get('messageTypes')}")

    if args.skip_status:
        print("status: not changed (--skip-status)")
    elif ticket.get("assignee") == args.sa_id:
        print("status: already assigned to this service account, take-on not needed")
    elif "take-on" not in ticket.get("actions", []):
        if not in_work:
            raise SystemExit(f"take-on is not available on {args.ticket} ({state}), nothing changed")
        print(f"status: take-on is not available in status {ticket.get('privateStatus')}, not changed (--force)")
    else:
        updated = take_on(token, ticket)
        print(f"status: {ticket.get('publicStatus')}/{ticket.get('privateStatus')} -> "
              f"{updated.get('publicStatus')}/{updated.get('privateStatus')}, assignee={updated.get('assignee')}")

    message = add_comment(token, args.ticket, args.comment)
    print(f"comment added: id={message.get('id')} type={message.get('type')} createdAt={message.get('createdAt')}")


if __name__ == "__main__":
    main()
