import argparse
import json
import pprint
import os
import sys
import os.path
import subprocess
from pathlib import Path

REPO = os.path.dirname(__file__)

HOME = os.path.expanduser("~")
SEC = os.path.join(HOME, "sec")
EXPORTS = os.path.join(HOME, "exports")

def _read_json(path):
    with open(path) as fh:
        return json.load(fh)

META_CONFIG = _read_json(os.path.join(SEC, "all_in_one_config.json"))

BLOCKED_CIDS = []
with open(os.path.join(SEC, "org_cids.csv")) as fh:
    BLOCKED_CIDS = [l.strip() for l in fh.readlines()]

if len(BLOCKED_CIDS) < 10:
    print(os.path.join(SEC, "org_cids.csv") + " seems empty ?")
    sys.exit(1)

BLOCKED_CIDS = frozenset(BLOCKED_CIDS)

def prepare_export_dir(ticket):
    p = Path(os.path.join(EXPORTS, str(ticket)))
    p.mkdir(parents=True, exist_ok=True)

def manual_ticket_info(ticket):
    data = {
        'id': ticket,
    }
    data['cluster_type'] = resolve_ctype(input("Тип кластера:"))
    data['s3_endpoint'] = input("S3 endpoint:").strip()
    data['s3_bucket'] = input("S3 bucket:").strip()
    data['s3_access_key_id'] = input("S3 access key (короткий):").strip()
    data['s3_secret_key'] = input("S3 secret key (длинный):").strip()
    data['cluster_id'] = input("Идентификатор кластера:").strip()
    with open(os.path.join(EXPORTS, ticket, 'ticket.json'), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=4)

def get_ticket_info(ticket):
    subprocess.check_call([
        'python3', os.path.join(REPO, 'tools/supporthub_get_ticket.py'),
         '--key', os.path.join(SEC, 'ticket_private_key.txt'),
         '--key-id', META_CONFIG['ticket_key_id'],
         '--sa-id', META_CONFIG['ticket_sa_id'],
         '--ticket', ticket,
         '--out', os.path.join(EXPORTS, ticket, 'ticket.json'),
         '--force',
    ])

def get_gpg_key(cid):
    gpg_keys = _read_json(os.path.join(SEC, "gpg_keys.json"))
    key = gpg_keys.get(cid)
    if key is None:
        print("GPG KEYS NOT FOUND, POSSIBLY BAD CLUSTER")
        sys.exit(1)
    return key

CTYPES = [
    'postgresql',
    'mysql',
    'redis',
    'clickhouse',
    'mongodb',
    ]

def resolve_ctype(ctype):
    ctype = ctype.lower().strip()
    ctype = ctype.split('-')[-1]
    if ctype not in CTYPES:
        print(f"Invalid cluster type: {ctype}.  Should be one of {CTYPES}")
        sys.exit(1)
    return ctype


def resolve_region(endpoint):
    if "vkcloud-storage" in endpoint:
        return "ru-msk"
    return "US"


def prepare_upload_config(ticket):
    ticket_info = _read_json(os.path.join(EXPORTS, ticket, 'ticket.json'))
    print('Ticket info:')
    pprint.pprint(ticket_info)
    cid = ticket_info['cluster_id'].strip()
    if cid in BLOCKED_CIDS:
        print(cid + " is cluster in our organization. BLACKLISTED")
        sys.exit(1)

    endpoint = ticket_info['s3_endpoint']
    if endpoint[:8] != 'https://':
        endpoint = 'https://' + endpoint
    bucket = ticket_info['s3_bucket']
    if bucket[:5] != 's3://':
        bucket = 's3://' + bucket
    ctype = ticket_info['cluster_type']
    ctype = resolve_ctype(ctype)

    gpg_key = get_gpg_key(cid)

    uploader_config = {
      "cid": cid,
      "source": {
            "endpoint": "https://s3.mds.yandex.net",
            "prefix": f"s3://copernic-cp-{cid}-backups/",
            "access_key": META_CONFIG['copernic_access_key'],
            "secret_key": META_CONFIG['copernic_secret_key'],
            "region": "ru-central1"
      },
      "destination": {
        "endpoint": endpoint,
        "prefix": bucket,
        "access_key": ticket_info['s3_access_key_id'],
        "secret_key": ticket_info['s3_secret_key'],
        "region": resolve_region(endpoint),
      },
      "cluster_type": ctype,
      "gpg": {
        "key_id": gpg_key['gpg_key_id'],
        "key": gpg_key['data'],
      },
    }
    with open(os.path.join(EXPORTS, ticket, "config.json"), "w", encoding="utf-8") as fh:
        json.dump(uploader_config, fh, indent=4)

def run_upload(ticket):
    subprocess.check_call([
        'python3', os.path.join(REPO, 's3_upload.py'), os.path.join(EXPORTS, ticket, "config.json")
    ], cwd=os.path.join(EXPORTS, ticket))

# Создаём парсер с описанием программы
parser = argparse.ArgumentParser(description="export backups all in one")
parser.add_argument("--manual",  action=argparse.BooleanOptionalAction)
parser.add_argument("ticket", help="ID тикета из backoffice")
args = parser.parse_args()

print("PREPARING EXPORT DIR")
prepare_export_dir(args.ticket)

if args.manual:
    print("ENTER TICKET INFO")
    manual_ticket_info(args.ticket)
else:
    print("GETTING TICKET INFO")
    get_ticket_info(args.ticket)

print("PREPARING UPLOAD CONFIG")
prepare_upload_config(args.ticket)

print("RUNNING UPLOAD")
run_upload(args.ticket)
