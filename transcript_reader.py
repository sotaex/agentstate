#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Antinel Security Suite v0.27.0 - transcript usage reader (三问三答 v1.0, A1/A2).

Harvests per-turn token FACTS from the host's transcript JSONL into the audit
chain. This module is the ONLY place that knows the host's transcript format
(adapter layer): if the host changes its schema, only this file changes.

Verified facts (2026-09-19, WorkBuddy): entries of type function_call/message
carry message.usage {input_tokens, output_tokens, cache_read_input_tokens,
total_tokens}; the model id lives at providerData.model. ~84% of
function_call entries carry usage; entries without it are skipped.

Reads are INCREMENTAL: the caller keeps a byte offset per transcript path and
this module parses only the bytes appended since. A single session file can
reach 100+ MB -- never parse it whole. First sight of a transcript (and a
size-shrink reset) reads only the tail (TAIL_FIRST_SIGHT_BYTES), complete
lines only, so one hook call never stalls on a big file.

Failure discipline: any unreadable/unparsable content is skipped; the caller
receives fewer or zero entries -- it never receives invented data. Absent
evidence is not evidence.

stdlib only, no network. Python 3.10+.
"""
import hashlib
import json
import os
from datetime import datetime

# ------------------------------------------------------------ adapter layer ----
# The host-format knowledge lives in these definitions and nowhere else.
_USAGE_ENTRY_TYPES = ("function_call", "message")
_WRAP_USAGE_KEY = "message"                      # usage dict location: d["message"]["usage"]
_MODEL_KEYS = ("providerData", "message")        # model id: d[k]["model"], first hit
_ENTRY_TS_KEY = "timestamp"
_ENTRY_ID_KEYS = ("callId", "id")
_USAGE_FIELDS = (
    # (canonical name, accepted aliases in the usage dict)
    ("input_tokens", ("input_tokens", "inputTokens")),
    ("output_tokens", ("output_tokens", "outputTokens")),
    ("cache_read_input_tokens", ("cache_read_input_tokens", "cacheReadInputTokens")),
    ("cache_creation_input_tokens", ("cache_creation_input_tokens", "cacheCreationInputTokens")),
    ("total_tokens", ("total_tokens", "totalTokens")),
)

# ------------------------------------------------------------ read policy ------
TAIL_FIRST_SIGHT_BYTES = 64 * 1024        # first sight / reset: tail only
MAX_ENTRIES_PER_HARVEST = 200             # bound one usage_delta record's size
MAX_NEW_BYTES_PER_CALL = 8 * 1024 * 1024  # absolute cap on one incremental read
SEEN_FINGERPRINT_CAP = 500                # dedup window kept in the state file


def normalize_entry(d):
    """One transcript entry -> a flat usage-fact dict, or None if this entry
    carries no usage. Aliases resolve here; callers see canonical names."""
    if not isinstance(d, dict) or d.get("type") not in _USAGE_ENTRY_TYPES:
        return None
    wrap = d.get(_WRAP_USAGE_KEY)
    usage = wrap.get("usage") if isinstance(wrap, dict) else None
    if not isinstance(usage, dict):
        return None
    out = {}
    for canon, aliases in _USAGE_FIELDS:
        v = None
        for a in aliases:
            if isinstance(usage.get(a), int):
                v = usage[a]
                break
        out[canon] = v                      # absent alias stays None, not 0
    model = None
    for k in _MODEL_KEYS:
        w = d.get(k)
        if isinstance(w, dict) and w.get("model"):
            model = w["model"]
            break
    out["model"] = model
    out["ts"] = d.get(_ENTRY_TS_KEY) or ""
    eid = None
    for k in _ENTRY_ID_KEYS:
        if d.get(k):
            eid = d[k]
            break
    out["id"] = eid
    return out


def _entry_fingerprint(e):
    """Dedupe key across offset resets: entry id when present, else the entry's
    canonical content hash (the same turn re-harvested yields the same value)."""
    if e.get("id"):
        return str(e["id"])
    canon = json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "h:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:32]


def _parse_chunk(chunk):
    """bytes -> (entries, lines_seen). Complete-lines only; unparsable skipped."""
    entries, lines_seen = [], 0
    for raw in chunk.split(b"\n"):
        line = raw.strip()
        if not line:
            continue
        lines_seen += 1
        try:
            d = json.loads(line.decode("utf-8", errors="replace"))
        except Exception:
            continue
        e = normalize_entry(d)
        if e is not None:
            entries.append(e)
    return entries, lines_seen


def harvest(transcript_path, offset, first_sight=False,
            max_new_bytes=MAX_NEW_BYTES_PER_CALL):
    """Read new bytes from transcript_path and return
    (entries, next_offset, meta); (None, offset, None) on I/O failure.

    - first_sight=True ignores `offset` and parses only the file tail's
      complete lines (a first hook call on a huge session must stay cheap).
    - next_offset always points at the end of the last COMPLETE line; a
      partial trailing line is simply re-read next time.
    - meta: {"scope", "bytes_read", "lines_seen", "truncated_read"}
    """
    try:
        size = os.path.getsize(transcript_path)
        if size <= 0:
            return [], (0 if first_sight else min(offset, size)), {
                "scope": "incremental", "bytes_read": 0, "lines_seen": 0,
                "truncated_read": False}
        if first_sight:
            start = max(0, size - TAIL_FIRST_SIGHT_BYTES)
            scope = "tail_first_sight"
        else:
            start = min(offset, size)
            scope = "incremental"
        cap = min(size, start + max_new_bytes)
        with open(transcript_path, "rb") as f:
            f.seek(start)
            blob = f.read(cap - start)
        if not blob:
            return [], start, {"scope": scope, "bytes_read": 0,
                               "lines_seen": 0, "truncated_read": False}
        complete = blob.rfind(b"\n")
        if complete < 0:
            # no complete line in this window -- offset stays; retry next call
            return [], start, {"scope": scope, "bytes_read": 0,
                               "lines_seen": 0, "truncated_read": cap < size}
        if first_sight and start > 0:
            nl = blob.find(b"\n")            # drop the (likely partial) first line
            if 0 <= nl < complete:
                blob = blob[nl + 1:]
        entries, lines_seen = _parse_chunk(blob[:complete + 1])
        meta = {"scope": scope, "bytes_read": complete + 1,
                "lines_seen": lines_seen, "truncated_read": cap < size}
        return entries[:MAX_ENTRIES_PER_HARVEST], start + complete + 1, meta
    except Exception:
        return None, offset, None


def path_tag(transcript_path):
    """Privacy: ledgers store a stable tag for the transcript path, never the
    path itself (it leaks the home-directory layout). The full path lives only
    in the local offset-state file."""
    return "sha256:" + hashlib.sha256(
        (transcript_path or "").encode("utf-8", "replace")).hexdigest()[:16]


def load_offsets(state_dir):
    try:
        with open(os.path.join(state_dir, "usage_offsets.json"),
                  encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_offsets(state_dir, offsets):
    try:
        os.makedirs(state_dir, exist_ok=True)
        tmp = os.path.join(state_dir, "usage_offsets.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(offsets, f, ensure_ascii=False, indent=1)
        os.replace(tmp, os.path.join(state_dir, "usage_offsets.json"))
        return True
    except Exception:
        return False


def harvest_delta(transcript_path, state_dir):
    """One post_tool_use call: decide the read scope from the offset state,
    harvest, dedupe against the seen-window, update state. Returns
    (entries, meta); (None, None) on I/O failure (caller records nothing);
    ([], meta) means 'nothing new to record'."""
    if not transcript_path or not os.path.isfile(transcript_path):
        return [], {"scope": "no_transcript", "bytes_read": 0, "lines_seen": 0,
                    "truncated_read": False, "reset": False, "path_tag": None,
                    "deduped": 0}
    offsets = load_offsets(state_dir)
    tag = path_tag(transcript_path)
    st = offsets.get(tag) or {}
    size = os.path.getsize(transcript_path)
    prev_size = st.get("size", 0)
    seen = set(st.get("seen") or [])
    if prev_size and size < prev_size:
        first_sight, reset = True, True         # truncated/rotated: re-tail, mark it
    else:
        first_sight, reset = (prev_size == 0), False
    raw_entries, next_offset, meta = harvest(
        transcript_path, st.get("offset", 0), first_sight=first_sight)
    if raw_entries is None:
        return None, None                       # I/O failure
    entries, new_fps, deduped = [], [], 0
    for e in raw_entries:
        fp = _entry_fingerprint(e)
        if fp in seen:
            deduped += 1                        # already in the ledger (reset overlap)
            continue
        seen.add(fp)
        new_fps.append(fp)
        entries.append(e)
    merged_seen = list(st.get("seen") or []) + new_fps
    offsets[tag] = {"size": next_offset, "offset": next_offset,
                    "updated_at": datetime.now().isoformat(timespec="seconds"),
                    "seen": merged_seen[-SEEN_FINGERPRINT_CAP:]}
    save_offsets(state_dir, offsets)
    meta = dict(meta)
    meta.update({"reset": reset, "path_tag": tag, "deduped": deduped})
    return entries, meta
