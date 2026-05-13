"""
Compactação unificada L1→L2→armazenamento (JSONL / SQLite) para menos bytes por linha.

Contrato mínimo para L3: ver ``docs/CANONICAL_EVENT_L1L2L3.md``.

Variáveis de ambiente:
  EVENT_SLIM_PAYLOAD=1 (padrão) — remove nulls aninhados, forensics duplicados, debug
  EVENT_INCLUDE_RAW_FORENSIC=0 — 1 mantém raw_original + raw_envelope
  EVENT_KEEP_DEBUG=0 — 1 mantém debug
  EVENT_MAX_CONTENT_SAMPLE_CHARS=160 — trunca amostras de texto em content/clipboard
"""
from __future__ import annotations

import os
from typing import Any, Dict, Set


SCHEMA_VERSION = 1

_REQUIRED_ROOT: Set[str] = {"event_id", "ts", "type", "source", "severity"}


def _slim_enabled() -> bool:
    return os.getenv("EVENT_SLIM_PAYLOAD", "1").strip().lower() in {"1", "true", "yes", "on"}


def _keep_forensic() -> bool:
    return os.getenv("EVENT_INCLUDE_RAW_FORENSIC", "0").strip().lower() in {"1", "true", "yes", "on"}


def _keep_debug() -> bool:
    return os.getenv("EVENT_KEEP_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}


def _max_content_sample_chars() -> int:
    try:
        return max(0, int(os.getenv("EVENT_MAX_CONTENT_SAMPLE_CHARS", "160")))
    except Exception:
        return 160


def _truncate_strings(obj: Any, max_chars: int) -> None:
    if max_chars <= 0:
        return
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if k in ("sample", "text_file", "content") and isinstance(v, str) and len(v) > max_chars:
                obj[k] = v[:max_chars]
            elif isinstance(v, (dict, list)):
                _truncate_strings(v, max_chars)
    elif isinstance(obj, list):
        for it in obj:
            _truncate_strings(it, max_chars)


def drop_none_values(obj: Any) -> Any:
    """Remove apenas chaves com valor None; omite dicts/listas vazias após limpeza."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if v is None:
                continue
            if isinstance(v, dict):
                nv = drop_none_values(v)
                if isinstance(nv, dict) and nv:
                    out[k] = nv
                continue
            if isinstance(v, list):
                nl = [drop_none_values(x) for x in v if x is not None]
                nl = [x for x in nl if x is not None and x != {} and x != []]
                if nl:
                    out[k] = nl
                continue
            if isinstance(v, str) and not v.strip():
                continue
            out[k] = v
        return out
    if isinstance(obj, list):
        nl = [drop_none_values(x) for x in obj if x is not None]
        return [x for x in nl if x is not None and x != {}]
    return obj


def finalize_storage_event(e: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(e, dict):
        return e

    d = dict(e)
    d["schema_ver"] = SCHEMA_VERSION

    if _slim_enabled():
        if not _keep_forensic():
            d.pop("raw_original", None)
            d.pop("raw_envelope", None)
        if not _keep_debug():
            schema_err = None
            dbg = d.get("debug")
            if isinstance(dbg, dict):
                schema_err = dbg.get("schema_error")
            d.pop("debug", None)
            if schema_err:
                d["debug"] = {"schema_error": schema_err}
        mc = _max_content_sample_chars()
        if mc > 0:
            if isinstance(d.get("content"), dict):
                _truncate_strings(d["content"], mc)
            if isinstance(d.get("clipboard"), dict):
                _truncate_strings(d["clipboard"], mc)

    out = drop_none_values(d)
    if not isinstance(out, dict):
        out = d

    for req in _REQUIRED_ROOT:
        if req not in out or out[req] is None:
            if req in e:
                out[req] = e[req]
    if "severity" not in out:
        out["severity"] = int(e.get("severity") or 0)

    if "tags" in e and isinstance(e["tags"], list) and not e["tags"]:
        out.setdefault("tags", [])
    if "ioc_hits" in e and isinstance(e["ioc_hits"], list) and not e["ioc_hits"]:
        out.setdefault("ioc_hits", [])

    return out
