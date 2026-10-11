#!/usr/bin/env python3
"""Fetch a backup-export request from Yandex Cloud Support Hub, check it against a
clusters reference and take it into work.

Same interface and behaviour as supporthub_get_ticket.py, plus a mandatory check of the
request against a reference of existing (not deleted) clusters.

Usage:
    python3 tools/supporthub_get_ticket_v2.py --key SA_KEY.pem --sa-id <SA_ID> \\
        --ticket <TICKET_ID> --out <TICKET_ID>.json --clusters-ref clusters.csv \\
        [--dry-run] [--skip-status] [--force]

Steps:
  1. Read the ticket and write its fields to --out as JSON (always, even if nothing
     else happens). The S3 fields are parsed from the request form in `description`.
  2. Check the request against --clusters-ref, a CSV with the columns cluster_id,
     cluster_type, cloud_id, organization_id. The check fails if the cluster_id from
     the form is not in the reference, or if the ticket's organization_id differs from
     (or the reference has no) organization_id for that cluster. The ticket carries no
     cloud_id, so cloud_id is not compared; it is taken from the reference into the
     JSON. On failure nothing is changed and the exit code is 4 (also with --dry-run).
  3. If the ticket is already in work (private status `in_progress`, or it has an
     assignee), stop without changing anything and exit with code 3, unless --force.
  4. Apply the `take-on` action: status becomes `in_progress`, the service account
     becomes the assignee. The customer sees "In progress" in the console.
  5. Add an internal comment (message type `inner`, not visible to the customer).

Authentication: an authorized key of a service account (PEM, as issued by
`yc iam key create`; the first line carries the key id) is exchanged for an IAM token,
which is kept in memory only. Requests go to the Support Center private API directly —
the backoffice gateway accepts browser sessions only.

The output JSON contains the customer's S3 access key and secret key. It is created
with mode 0600; handle and delete it accordingly.

Exit codes: 0 done (or --dry-run), 3 ticket already in work and nothing changed,
4 the reference check failed and nothing changed, 1 any error. Note: if take-on succeeded but the comment failed, the exit code is 1
and the status is already changed — rerun with --skip-status to add the comment.
"""

import argparse
import base64
import csv
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
EXIT_CHECK_FAILED = 4
REF_COLUMNS = ("cluster_id", "cluster_type", "cloud_id", "organization_id")

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


def load_reference(path):
    """Clusters reference: cluster_id -> row with cluster_type, cloud_id, organization_id."""
    if not path.is_file():
        raise SystemExit(f"{path}: clusters reference not found, the tool does not run without it")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        missing = [name for name in REF_COLUMNS if name not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(f"{path}: missing columns {missing}")
        reference = {row["cluster_id"].strip(): row for row in reader if row.get("cluster_id")}
    if not reference:
        raise SystemExit(f"{path}: clusters reference is empty")
    return reference


def check_against_reference(ticket, cluster_id, reference, reference_path):
    """Compare the request with the reference; returns the `check` block for the JSON."""
    ticket_org = ticket.get("organizationId") or ""
    result = {"status": "error", "cluster_id": cluster_id, "ticket_organization_id": ticket_org,
              "ref_organization_id": None, "ref_cloud_id": None, "ref_cluster_type": None, "message": ""}
    if not cluster_id:
        result["message"] = "no cluster_id in the request form, cannot check it against the reference"
        return result
    row = reference.get(cluster_id)
    if row is None:
        result["message"] = f"cluster_id {cluster_id} is not in the clusters reference {reference_path.name}"
        return result
    result.update(ref_organization_id=row["organization_id"], ref_cloud_id=row["cloud_id"],
                  ref_cluster_type=row["cluster_type"])
    if not row["organization_id"] or row["organization_id"] != ticket_org:
        result["message"] = (
            f"request attributes failed the check: organization_id of the request "
            f"({ticket_org or 'empty'}) does not match organization_id in the reference "
            f"({row['organization_id'] or 'empty'}) for cluster_id {cluster_id}")
        return result
    result["status"] = "ok"
    result["message"] = f"cluster_id {cluster_id} found in the reference, organization_id matches"
    return result


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
    parser.add_argument("--dry-run", action="store_true",
                        help="only write the JSON and run the check, do not change the ticket")
    parser.add_argument("--clusters-ref", required=True, type=Path,
                        help="CSV reference of existing clusters (cluster_id, cluster_type, cloud_id, organization_id)")
    args = parser.parse_args()

    reference = load_reference(args.clusters_ref)
    token = iam_token(args.key, args.sa_id, args.key_id)
    ticket = get_ticket(token, args.ticket)
    data = ticket_fields(ticket, args.service)
    check = check_against_reference(ticket, data["cluster_id"], reference, args.clusters_ref)
    data["organization_id"] = check["ticket_organization_id"]
    data["cloud_id"] = check["ref_cloud_id"]
    data["check"] = check
    write_json(data, args.out)
    print(f"saved {args.out} | parse_status={data['parse_status']} {data['parse_problems'] or ''}")

    if check["status"] != "ok":
        print(f"ERROR: {args.ticket}: {check['message']}. Ticket not changed")
        sys.exit(EXIT_CHECK_FAILED)
    print(f"check: ok, {check['message']}, cloud_id={check['ref_cloud_id']}")

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
