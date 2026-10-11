# s3_upload

`s3_upload.py` copies every object under one S3 prefix to another S3 prefix — across
different endpoints and providers — and then verifies that the copy is complete.

It is a thin, auditable driver around [`rclone`](https://rclone.org/): the script builds
a throwaway rclone config, lists both sides itself, decides what still has to be copied,
runs `rclone copy` in passes, and writes a machine-readable report of whatever did not
make it.

Designed for one-shot migrations of a cluster's backup bucket, where the run must be
restartable, shardable across machines, and must leave evidence of what happened.

---

## Table of contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Command line](#command-line)
- [Configuration file](#configuration-file)
- [Sharding](#sharding)
- [How a run works](#how-a-run-works)
- [Output files](#output-files)
- [Exit codes](#exit-codes)
- [Verify-only mode](#verify-only-mode)
- [Error handling](#error-handling)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## What it does

- Copies `source.prefix` → `destination.prefix/<cid>/`, preserving the key layout.
- Splits the work into shards (`A` of `B`) so several processes or hosts can run in
  parallel over disjoint parts of the keyspace.
- Runs preflight checks before touching data: source `LS`, source `GET`, and a full
  destination `PUT` → `GET` → `LS` → `DELETE` probe cycle.
- Uploads a sanitised copy of the config (everything except S3 credentials) next to the
  data, as migration metadata, and reads it back to confirm it landed.
- Copies in up to **3 passes**, re-listing both sides between passes so each pass only
  transfers what is still missing or has the wrong size.
- Verifies the result by comparing full source and destination listings, and groups the
  discrepancies into time ranges by `LastModified` so you can see *when* the gaps are.
- Deletes the local credential files once verification passes.

Objects are compared by **size only** (`--size-only`). Checksums are not compared,
because source and destination providers generally do not agree on ETag semantics for
multipart objects.

> **Note on timestamps.** S3 exposes `LastModified`, not the original creation time of an
> object. The script lists the source with `--use-server-modtime` and treats
> `LastModified` as the object's time everywhere — in the eligibility cutoff and in the
> reported discrepancy ranges.

---

## Requirements

- **Python 3.8+**, standard library only — no `pip install` needed.
- **POSIX host** (Linux or macOS). The script calls `os.geteuid()` and is not supported
  on Windows.
- **rclone** on `PATH`.
  If it is missing and you are on a Debian/Ubuntu host, the script installs it with
  `apt-get update && apt-get install -y rclone`, using `sudo -n` when not running as
  root. On any other platform, install rclone yourself, or point at a binary with
  `--rclone /path/to/rclone`.
- Network access to both endpoints, and credentials with:
  - source: `ListBucket`, `GetObject`
  - destination: `ListBucket`, `PutObject`, `GetObject`, `DeleteObject`
    (`DeleteObject` is required — the destination probe cleans up after itself)

Both remotes are always addressed in **path style** (`force_path_style = true`), and
bucket existence is not checked (`no_check_bucket = true`).

---

## Quick start

```bash
# 1. Describe the migration
cat > config.json <<'JSON'
{
  "cid": "mdb-cluster-1a2b3c",
  "cluster_type": "postgresql",
  "source": {
    "endpoint": "https://s3.source.example",
    "prefix": "s3://backup-src/wal-g/mdb-cluster-1a2b3c/",
    "access_key": "...",
    "secret_key": "...",
    "region": "ru-central1"
  },
  "destination": {
    "endpoint": "https://s3.destination.example",
    "prefix": "s3://backup-dst/restored/",
    "access_key": "...",
    "secret_key": "..."
  },
  "gpg": {
    "key_base64": "LS0tLS1CRUdJTiBQR1AgUFJJVkFURSBLRVkgQkxPQ0st..."
  }
}
JSON
chmod 600 config.json

# 2. Copy everything, 10 parallel transfers
python3 s3_upload.py config.json

# 3. Or copy shard 0 of 4, with 32 parallel transfers
python3 s3_upload.py config.json 0 4 -p 32
```

Data lands under `s3://backup-dst/restored/mdb-cluster-1a2b3c/` — note that `cid` is
appended to `destination.prefix` automatically.

---

## Command line

```
python3 s3_upload.py CONFIG [A [B]] [-p N] [--verify] [--state-dir DIR] [--rclone PATH]
```

| Argument | Default | Meaning |
| --- | --- | --- |
| `CONFIG` | — | Path to the JSON config file (see below). |
| `A` | `0` | Shard remainder handled by this process. Must satisfy `0 <= A < B`. |
| `B` | `1` | Total number of shards. Must be `> 0`. |
| `-p`, `--parallel` | `10` | rclone `--transfers`. Checkers are set to `max(4, N)`. |
| `--verify` | off | Compare only; copy nothing. See [Verify-only mode](#verify-only-mode). |
| `--state-dir` | `copy_s3_state_<cid>` | Where run directories are created. |
| `--rclone` | `rclone` | rclone executable name or path. |

---

## Configuration file

A single JSON object. Validation is strict — the script refuses to start on anything it
does not recognise, rather than silently ignoring it.

### Top level

| Key | Required | Type | Notes |
| --- | --- | --- | --- |
| `cid` | yes | string | Cluster id. Used as the destination subfolder, so it must match `[A-Za-z0-9][A-Za-z0-9._-]*` — one path segment, no slashes. |
| `cluster_type` | yes | string | Free-form, e.g. `postgresql`, `clickhouse`, `mongodb`. Two values trigger extra required sections (below). |
| `source` | yes | object | S3 endpoint to read from. |
| `destination` | yes | object | S3 endpoint to write to. |
| `gpg` | yes | object | Backup decryption material, carried as metadata. |
| `clickhouse` | if `cluster_type == "clickhouse"` | object | Must contain a non-empty `encryption_key`. |
| `mongodb` | if `cluster_type == "mongodb"` | object | Must contain a non-empty `admin_password`. |

### `source` and `destination`

| Key | Required | Notes |
| --- | --- | --- |
| `endpoint` | yes | `http(s)://host[:port]`. No path, query, fragment, embedded credentials, or newlines. A default port (`443`/`80`) is normalised away. |
| `prefix` | yes | `s3://bucket/optional/prefix/`. No query or fragment. A trailing `/` is added if missing. |
| `access_key` | yes | Non-empty, no newlines. |
| `secret_key` | yes | Non-empty, no newlines. |
| `region` | no | Non-empty string without whitespace, if given. |
| `path_style` | **rejected** | Path style is always on; supplying this key is an error, so a stale config cannot imply otherwise. |

If both sides resolve to the same endpoint, the script additionally rejects configs
where `source.prefix` and the effective destination prefix overlap — i.e. where the copy
would read its own output.

### `gpg`

Either form is accepted:

```jsonc
{ "key_base64": "<base64 of the armoured key>" }     // or
{ "key": "<armoured key>", "key_id": "<key id>" }
```

An optional `passphrase` may be added to either form; if present it must be a non-empty
string.

### What happens to these fields

Only `source` and `destination` are used to talk to S3. **Everything else — `cid`,
`cluster_type`, `gpg`, and the `clickhouse` / `mongodb` sections — is validated, then
written verbatim to the destination** as migration metadata at:

```
<destination.prefix>/<cid>/__migration__/config-<timestamp>-<A>-of-<B>.json
```

The upload is read back and byte-compared before the copy starts. This is deliberate:
the restore side needs the decryption material alongside the data. It also means the
destination bucket will contain your GPG key and any passphrase or admin password —
see [Security notes](#security-notes).

S3 credentials are **never** uploaded.

---

## Sharding

Work is split with rclone's `--hash-filter A/B`, which assigns each object to a shard by
a hash of its path. Shards are stable and disjoint, so running

```bash
python3 s3_upload.py config.json 0 4 -p 32 &
python3 s3_upload.py config.json 1 4 -p 32 &
python3 s3_upload.py config.json 2 4 -p 32 &
python3 s3_upload.py config.json 3 4 -p 32 &
```

covers the whole prefix exactly once, with no coordination between the processes. They
may run on different hosts; each gets its own run directory and its own reports.

Within a copy pass the file list is passed to rclone with `--files-from0`, which
overrides `--hash-filter`. That is safe because the list itself is produced from the
shard-filtered listing, so rclone's own hash function defines the shard on every pass.

An empty shard is valid and is **not** an error. If the shard is empty the script
re-lists the source unfiltered, purely to confirm the prefix exists and that `GET`
works; those objects are not copied by this shard. If the unfiltered listing is also
empty, the run fails with `source prefix ... contains no files`.

---

## How a run works

1. **Validate config**, create `state_dir` (mode `0700`) and a run directory inside it.
2. **Write `rclone.conf`** into the run directory with both remotes. The destination
   remote pins `storage_class = STANDARD`, because rclone otherwise forwards the source
   storage class (e.g. `ICE`) into `PutObject`, which another provider may reject.
3. **Preflight**
   - source `LS` over the whole prefix;
   - destination `PUT` → `GET` (content compared) → `LS` (exact key) → `DELETE` of a
     random probe object under `__migration__/`;
   - source `GET`: the **smallest** object in the shard is streamed and its byte count
     compared with the listed size — nothing is staged on disk.
4. **Snapshot the source listing** to `initial_source_listing.json`.
5. **Upload metadata** and read it back.
6. **Set the cutoff** at `start + 10 minutes`. Only objects whose `LastModified` is at or
   before the cutoff are eligible. This bounds the run against a source that is still
   being written to: new objects appearing mid-run are ignored rather than chased
   forever.
7. **Up to 3 copy passes.** Each pass re-lists source and destination, computes the
   candidates (missing at the destination, or present with a different size, and not
   already skipped), and runs one `rclone copy`. Progress is printed and mirrored to
   `progress.txt` from rclone's JSON stats.
8. **Final reconciliation.** Source and destination are listed once more, everything
   discovered across all passes is compared by size, and `failed.jsonl` is written with
   one line per object that is missing or mismatched, each with a reason.
9. **Verification.** `verification.json` records missing files, size mismatches, and the
   discrepancies collapsed into time ranges (successive `LastModified` values less than
   an hour apart are merged into one range), so a gap shows up as
   `2026-02-11 03:10-04:40` rather than 4 000 individual lines.
10. **Cleanup.** If verification found nothing, the local config file, `rclone.conf` and
    `destination_config.json` are deleted.

Passes are not retried on top of each other blindly: a pass that fails to list, or whose
`rclone copy` exits non-zero, is recorded and the next pass simply recomputes the work
from the current state of both buckets.

---

## Output files

Everything lives in
`<state-dir>/run-<timestamp>-<A>-of-<B>-<pid>/`, created with mode `0700`:

| File | Contents |
| --- | --- |
| `run.log` | Full console transcript, timestamped, `INFO` / `ERROR` tagged. |
| `operations.log` | One `START` / `OK` / `ERROR` / `RETRY` line per rclone invocation, with elapsed time. |
| `progress.txt` | Latest progress line only — cheap to `cat` or poll from another terminal. |
| `pass-N-rclone.jsonl` | Raw rclone JSON log for pass *N*. |
| `pass-N-files.bin` | NUL-separated key list handed to rclone for pass *N*. |
| `initial_source_listing.json` | `lsjson` snapshot of the shard taken before any copying. |
| `skipped_500.jsonl` | Objects skipped because the **source** returned HTTP 500 on `GetObject`. |
| `failed.jsonl` | Final per-object failures: `{source, destination, error}`. |
| `verification.json` | Structured verification report (see below). |
| `rclone.conf` | Generated remotes, **contains credentials**. Deleted on success. |
| `destination_config.json` | Metadata uploaded to the destination. Deleted on success. |

### `verification.json`

```jsonc
{
  "shard": { "a": 0, "b": 4 },
  "source_files": 128034,
  "missing_files": [
    { "source": "s3://...", "destination": "s3://...", "last_modified": "2026-02-11T03:10:04+00:00" }
  ],
  "size_mismatches": [
    { "source": "s3://...", "destination": "s3://...",
      "source_size": 1048576, "destination_size": 524288,
      "last_modified": "2026-02-11T03:12:51+00:00" }
  ],
  "ranges": [
    { "start": "2026-02-11T03:10:04+00:00", "end": "2026-02-11T04:40:12+00:00", "count": 412 }
  ]
}
```

Watching a running shard from elsewhere:

```bash
cat copy_s3_state_<cid>/run-*/progress.txt
tail -f copy_s3_state_<cid>/run-*/run.log
```

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Verification passed — every eligible source object is present at the destination with the same size. Local credential files were deleted. |
| `1` | The copy ran, but verification found missing objects or size mismatches. See `verification.json` and `failed.jsonl`. **Nothing was deleted.** |
| `2` | Fatal error — bad config, failed preflight, unreachable endpoint, rclone missing. |

`1` is the "re-run me" code: running the same command again re-lists both sides and
copies only what is still absent.

---

## Verify-only mode

```bash
python3 s3_upload.py config.json 0 4 --verify
```

Runs the preflight checks and then compares the shard without copying anything, writing
`verification.json` and printing the discrepancy time ranges. Useful for auditing a
migration after the fact, or for checking one shard while others are still running.

Note that `--verify` also deletes the local config and `rclone.conf` when it finds no
discrepancies, exactly like a full run.

---

## Error handling

**Transient rclone failures.** Every rclone invocation is retried up to 3 times with a
5s → 10s backoff, but only when the error matches a transient pattern: status
`429/500/502/503/504`, `InternalError`, `ServiceUnavailable`, `SlowDown`,
`TooManyRequests`, `connection reset`, `connection timed out`, `i/o timeout`,
`unexpected EOF`. Anything else fails immediately — a `403` is not worth three attempts.

**Source 500 on `GetObject`.** Some source providers have permanently unreadable
objects. When `GetObject` returns HTTP 500, the object is logged to `skipped_500.jsonl`,
excluded from later passes, and reported in `failed.jsonl` with the reason
`source GET 500; skipped in this run`. The run continues instead of aborting. If the
source GET *probe* hits this, the run continues too, with a warning — the probe picks
the smallest object, which may well be the broken one.

**Objects that vanish.** An object listed early and gone by the final listing is
reported as `no longer in source`, not as a failure of the copy.

**Interruption.** `Ctrl-C` is logged and re-raised; partial state stays in the run
directory, and a fresh run picks up from whatever is already at the destination.

---

## Security notes

- The config file holds live S3 credentials and GPG material. Keep it at mode `0600`;
  the script writes everything it generates at `0600` and its directories at `0700`.
- **On success, the script deletes the config file you passed in**, along with
  `rclone.conf` and `destination_config.json`. Keep a copy elsewhere if you intend to
  re-run. If cleanup itself fails, the run raises rather than reporting a clean success.
- Credentials are passed to rclone through a generated config file, never on the command
  line, so they do not appear in `ps` output.
- The uploaded metadata object contains the GPG key, the optional passphrase, and the
  ClickHouse encryption key or MongoDB admin password. Treat
  `<destination>/<cid>/__migration__/` as secret material and restrict access to it.
- Endpoints, prefixes and credentials are rejected if they contain newlines or
  structural surprises, so a crafted config cannot inject extra rclone config directives.

---

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `FATAL: config.cid must be one folder name...` | `cid` contains a slash or starts with a punctuation character. |
| `FATAL: source.endpoint must be http(s)://host[:port] without a path` | The endpoint has a path component — move it into `prefix`. |
| `FATAL: source and destination prefixes overlap on the same endpoint` | The destination would be inside the source. Change `destination.prefix` or `cid`. |
| `FATAL: source prefix ... contains no files; check the prefix` | The unfiltered source listing is empty — wrong bucket, wrong prefix, or no `ListBucket` permission. |
| `destination LS did not show ...` | Destination is eventually consistent, or the credentials can `PUT` but not `LIST`. |
| `probe deletion failed` | Destination credentials lack `DeleteObject`. A stray probe object is left under `__migration__/`. |
| `rclone was not found and apt-get is unavailable` | Install rclone manually, or pass `--rclone /path/to/rclone`. |
| `installing rclone requires root or passwordless sudo` | Install rclone yourself; the script will not prompt for a password. |
| Exit `1` with ranges clustered in one window | A source-side incident during that window. Re-run the shard; objects that are still absent will show up again. |
