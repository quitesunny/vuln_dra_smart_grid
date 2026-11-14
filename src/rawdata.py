import json
import os

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def safe(s):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in s)


def member_key(cpe):
    p = cpe.split(":")
    return p[2], p[3], p[4]


def load(fetch_date):
    raw = os.path.join(ROOT, "data", "raw", fetch_date)
    devices = yaml.safe_load(open(os.path.join(ROOT, "config", "devices.yaml"), encoding="utf8"))["devices"]
    pages_dir = os.path.join(raw, "cves_pages")
    page_files = sorted(os.listdir(pages_dir))
    cves = {}
    dev_match = {}
    for d in devices:
        members = {member_key(c) for c in d["cpe_match_strings"]}
        dm = dev_match.setdefault(d["device_id"], {})
        for fn in page_files:
            if not fn.startswith(safe(d["device_id"]) + "__") or not fn.endswith(".json"):
                continue
            for v in json.loads(open(os.path.join(pages_dir, fn), "rb").read()).get("vulnerabilities", []):
                cve = v["cve"]
                old = cves.get(cve["id"])
                if old is None or (cve.get("lastModified") or "") > (old.get("lastModified") or ""):
                    cves[cve["id"]] = cve
                for conf in cve.get("configurations", []):
                    for node in conf.get("nodes", []):
                        for m in node.get("cpeMatch", []):
                            if member_key(m["criteria"]) in members:
                                dm.setdefault(cve["id"], []).append((m["criteria"], bool(m.get("vulnerable"))))
    dev_cves = {k: sorted(c for c, ms in v.items() if any(x[1] for x in ms)) for k, v in dev_match.items()}
    hist_dir = os.path.join(raw, "cvehistory")
    hist = {}
    for fn in sorted(os.listdir(hist_dir)):
        if not fn.endswith(".json"):
            continue
        cid = fn.split("__")[0]
        hist.setdefault(cid, []).append(json.loads(open(os.path.join(hist_dir, fn), "rb").read()))
    h404 = set()
    p404 = os.path.join(raw, "cvehistory_404.txt")
    if os.path.exists(p404):
        h404 = {x.strip() for x in open(p404, encoding="utf8") if x.strip()}
    return {"raw": raw, "devices": devices, "cves": cves, "dev_match": dev_match, "dev_cves": dev_cves,
            "hist": hist, "hist_404": h404}
