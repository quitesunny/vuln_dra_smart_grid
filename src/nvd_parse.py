import re

NVD_SOURCE = "nvd@nist.gov"
HIST_TYPE_TO_VERSION = {
    "CVSS V2": "2.0", "CVSS V2.0": "2.0",
    "CVSS V3": "3.0", "CVSS V3.0": "3.0",
    "CVSS V3.1": "3.1",
    "CVSS V4": "4.0", "CVSS V4.0": "4.0",
}
METRIC_KEYS = {"cvssMetricV2": "2.0", "cvssMetricV30": "3.0", "cvssMetricV31": "3.1", "cvssMetricV40": "4.0"}
_VEC_RE = re.compile(r"((?:CVSS:\d\.\d/)?[A-Za-z]{1,3}:[A-Za-z]{1,2}(?:/[A-Za-z]{1,3}:[A-Za-z]{1,2})+)")
_SCORE_TYPE_RE = re.compile(r"^CVSS V\d(?:\.\d)?$")
_PREFIX_RE = re.compile(r"^(.*?)\s*\(?(?:CVSS:\d\.\d/)?[A-Za-z]{1,3}:[A-Za-z]{1,2}/")
NVD_VALUE_PREFIXES = {"", "NIST"}


def value_prefix(value):
    if value is None:
        return None
    m = _PREFIX_RE.match(str(value))
    return m.group(1).strip() if m else None


def norm_vector(value):
    if value is None:
        return None
    m = _VEC_RE.search(str(value))
    if not m:
        return None
    v = m.group(1)
    return re.sub(r"^CVSS:\d\.\d/", "", v)


def cvss_events(history_pages):
    out = []
    seq = 0
    ev_seq = 0
    for page in history_pages:
        for ch in page.get("cveChanges", []):
            c = ch.get("change", {})
            ev_seq += 1
            for d in c.get("details", []) or []:
                t = (d.get("type") or "").strip()
                if not _SCORE_TYPE_RE.match(t):
                    continue
                val = d.get("newValue") if d.get("newValue") is not None else d.get("oldValue")
                pre = value_prefix(val)
                src = c.get("sourceIdentifier")
                out.append({
                    "seq": seq, "event_seq": ev_seq, "created": c.get("created"), "eventName": c.get("eventName"),
                    "source": src, "cveChangeId": c.get("cveChangeId"),
                    "version": HIST_TYPE_TO_VERSION.get(t), "type": t, "action": d.get("action"),
                    "old_raw": d.get("oldValue"), "new_raw": d.get("newValue"),
                    "old_vector": norm_vector(d.get("oldValue")), "new_vector": norm_vector(d.get("newValue")),
                    "value_prefix": pre,
                    "is_nvd": src == NVD_SOURCE and pre in NVD_VALUE_PREFIXES,
                })
                seq += 1
    rank = {"Removed": 0, "Changed": 1, "Added": 2}
    out.sort(key=lambda e: (e["created"] or "", e["event_seq"], rank.get(e["action"], 3), e["seq"]))
    return out


def current_metrics(cve):
    out = []
    for key, ver in METRIC_KEYS.items():
        for m in cve.get("metrics", {}).get(key, []):
            cd = m.get("cvssData", {})
            out.append({"version": cd.get("version") or ver, "metric_key": key, "source": m.get("source"),
                        "type": m.get("type"), "vector": norm_vector(cd.get("vectorString")),
                        "baseScore": cd.get("baseScore")})
    return out


def nvd_primary(cve, version):
    for m in current_metrics(cve):
        if m["version"] == version and m["source"] == NVD_SOURCE and m["type"] == "Primary":
            return m
    return None


def history_change_count(history_pages):
    return sum(len(p.get("cveChanges", [])) for p in history_pages)
