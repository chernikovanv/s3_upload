#!/usr/bin/env python3
"""Mark a backup-export request in Yandex Cloud Support Hub as solved, with a taxonomy and an internal comment.

Second half of the chain: tools/supporthub_get_ticket_v2.py (or supporthub_get_ticket.py)
takes the ticket into work with the `take-on` action, so the service account becomes the
assignee; this tool then solves it.

Usage:
    python3 tools/supporthub_solve_ticket.py --key SA_KEY.pem --sa-id <SA_ID> \\
        --ticket <TICKET_ID> [--taxonomy NAME] [--comment TEXT] [--dry-run] [--force]

Steps:
  1. Check that the taxonomy exists in the Support Hub taxonomy list
     (GET /private/v2/taxonomies). The server does not validate names: a typo would
     silently create a new taxonomy.
  2. Read the ticket. It must be `in_progress` with this service account as the
     assignee. Already solved or closed: nothing changes, exit code 3. Not taken into
     work by this service account: nothing changes, exit code 5 (override with --force,
     if `solve` is available).
  3. Add an internal comment (message type `inner`, not visible to the customer).
  4. Apply the `solve` action with the taxonomy and read the ticket back.

The customer gets no notification from these steps; the console shows the public
status "Solved". Support Hub auto-closes a solved ticket after its closing timer and
notifies the customer then.

Exit codes: 0 solved (or --dry-run), 3 already solved or closed, 5 not in work by this
service account, 1 any error. If the comment was added but `solve` failed, the exit
code is 1 and the comment is already in the ticket.
"""

import argparse
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from supporthub_get_ticket import API_BASE, MESSAGE_TYPE, add_comment, get_ticket, iam_token, mask  # noqa: E402

TAXONOMIES_URL = API_BASE.replace("/private/v1", "/private/v2") + "/taxonomies"
DEFAULT_TAXONOMY = "Проблема в Облаке: compute: инцидент"
FINAL_STATUSES = {"solved", "closed"}
EXIT_ALREADY_DONE = 3
EXIT_NOT_OURS = 5


def known_taxonomies(token):
    response = requests.get(TAXONOMIES_URL, headers={"Authorization": f"Bearer {token}"}, timeout=15, verify=False)
    if response.status_code != 200:
        raise SystemExit(f"taxonomies: HTTP {response.status_code} {mask(response.text[:300])}")
    return set(response.json())


def solve(token, ticket_id, taxonomy):
    response = requests.post(
        f"{API_BASE}/apply-action",
        json={"ticketId": ticket_id, "action": {"type": "solve", "payload": {"taxonomies": [taxonomy]}}},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
        verify=False,
    )
    if response.status_code != 200:
        raise SystemExit(f"solve: HTTP {response.status_code} {mask(response.text[:300])}")
    return response.json().get("ticket", {})


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--key", required=True, type=Path, help="service account authorized key (PEM)")
    parser.add_argument("--sa-id", required=True, help="service account id")
    parser.add_argument("--ticket", required=True, help="Support Hub ticket id")
    parser.add_argument("--key-id", help="key id; default: taken from the first line of --key")
    parser.add_argument("--taxonomy", default=DEFAULT_TAXONOMY, help="resolution taxonomy (default: %(default)s)")
    parser.add_argument("--comment", default="MDB: выгрузка выполнена",
                        help="internal comment text (default: %(default)s)")
    parser.add_argument("--force", action="store_true",
                        help="solve even if the ticket is not in work by this service account (if solve is available)")
    parser.add_argument("--dry-run", action="store_true", help="only run the checks, do not change the ticket")
    args = parser.parse_args()

    token = iam_token(args.key, args.sa_id, args.key_id)
    if args.taxonomy not in known_taxonomies(token):
        raise SystemExit(f"taxonomy {args.taxonomy!r} is not in the Support Hub list, ticket not changed")
    ticket = get_ticket(token, args.ticket)
    state = f"{ticket.get('publicStatus')}/{ticket.get('privateStatus')}, assignee={ticket.get('assignee')}"
    print(f"{args.ticket}: {state}")

    if ticket.get("privateStatus") in FINAL_STATUSES:
        print(f"{args.ticket} is already solved or closed, nothing changed")
        sys.exit(EXIT_ALREADY_DONE)
    ours = ticket.get("privateStatus") == "in_progress" and ticket.get("assignee") == args.sa_id
    if not ours and not args.force:
        print(f"{args.ticket} is not in work by this service account ({state}), nothing changed. "
              f"Take it on first with supporthub_get_ticket_v2.py, or override with --force")
        sys.exit(EXIT_NOT_OURS)
    if "solve" not in ticket.get("actions", []):
        raise SystemExit(f"solve is not available on {args.ticket} ({state}), nothing changed")
    if MESSAGE_TYPE not in ticket.get("messageTypes", []):
        raise SystemExit(f"message type {MESSAGE_TYPE} is not allowed on {args.ticket}, nothing changed")

    if args.dry_run:
        print(f"dry-run: checks passed, solve with taxonomy {args.taxonomy!r} is available; ticket not changed")
        return

    message = add_comment(token, args.ticket, args.comment)
    print(f"comment added: id={message.get('id')} type={message.get('type')}")
    solve(token, args.ticket, args.taxonomy)
    after = get_ticket(token, args.ticket)
    print(f"status: {state} -> {after.get('publicStatus')}/{after.get('privateStatus')}")
    if after.get("privateStatus") not in FINAL_STATUSES:
        raise SystemExit(f"after solve the status is {after.get('privateStatus')}, check the ticket manually")


if __name__ == "__main__":
    main()
