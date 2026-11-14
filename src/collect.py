import csv
import datetime as dt
import json
import os
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "https://services.nvd.nist.gov/rest/json"
WINDOW_S, MAX_IN_WINDOW = 30.0, 40
RETRY = {403, 429, 500, 502, 503, 504, 520, 522, 524}
MAX_TRIES = 8
TIMEOUT = (10, 60)
CVE_PAGE = 500
HIST_PAGE = 5000


class NVDUnavailable(RuntimeError):
    pass


class Limiter:
    def __init__(self):
        self.lock = threading.Lock()
        self.t = deque()

    def wait(self):
        while True:
            with self.lock:
                now = time.monotonic()
                while self.t and now - self.t[0] > WINDOW_S:
                    self.t.popleft()
                if len(self.t) < MAX_IN_WINDOW:
                    self.t.append(now)
                    return
                w = WINDOW_S - (now - self.t[0]) + 0.2
            time.sleep(max(w, 0.05))


class Fetcher:
    def __init__(self, log_path):
        key = os.environ.get("NVD_API_KEY")
        if not key:
            raise RuntimeError("NVD_API_KEY tanımlı değil")
        self.headers = {"apiKey": key, "User-Agent": "nvd-research-client"}
        self.lim = Limiter()
        self.log_lock = threading.Lock()
        self.log_path = log_path
        self.local = threading.local()
        new = not os.path.exists(log_path)
        with open(log_path, "a", newline="", encoding="utf8") as f:
            if new:
                csv.writer(f).writerow(["endpoint", "params", "utc_time", "duration_ms", "http_status", "attempt"])

    def _session(self):
        if not hasattr(self.local, "s"):
            self.local.s = requests.Session()
            self.local.s.headers.update(self.headers)
        return self.local.s

    def _log(self, endpoint, params, t0, ms, status, attempt):
        p = "&".join(f"{k}={v}" for k, v in params.items())
        with self.log_lock, open(self.log_path, "a", newline="", encoding="utf8") as f:
            csv.writer(f).writerow([endpoint, p, t0, ms, status, attempt])

    def get(self, endpoint, params):
        delay = 6.0
        last = None
        for attempt in range(1, MAX_TRIES + 1):
            self.lim.wait()
            t0 = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
            s = time.perf_counter()
            status = "EXC"
            try:
                r = self._session().get(f"{BASE}/{endpoint}", params=params, timeout=TIMEOUT)
                status = r.status_code
                ms = int((time.perf_counter() - s) * 1000)
                self._log(endpoint, params, t0, ms, status, attempt)
                if status == 200:
                    json.loads(r.content)
                    return r.content
                if status == 404:
                    return None
                last = f"HTTP {status}"
                if status not in RETRY:
                    raise NVDUnavailable(f"{endpoint} {params}: {last}")
            except (requests.ConnectionError, requests.Timeout, ValueError) as e:
                ms = int((time.perf_counter() - s) * 1000)
                self._log(endpoint, params, t0, ms, f"EXC:{type(e).__name__}", attempt)
                last = repr(e)[:150]
            time.sleep(delay)
            delay = min(delay * 2, 120)
        raise NVDUnavailable(f"{endpoint} {params}: {MAX_TRIES} denemede başarısız ({last})")


def atomic_write(path, data: bytes):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def safe(s):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in s)


def member_key(cpe):
    p = cpe.split(":")
    return p[2], p[3], p[4]


def main():
    fetch_date = os.environ.get("FETCH_DATE") or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    raw = os.path.join(ROOT, "data", "raw", fetch_date)
    pages_dir = os.path.join(raw, "cves_pages")
    hist_dir = os.path.join(raw, "cvehistory")
    os.makedirs(pages_dir, exist_ok=True)
    os.makedirs(hist_dir, exist_ok=True)
    state_path = os.path.join(raw, "collect_state.json")
    state = json.load(open(state_path, encoding="utf8")) if os.path.exists(state_path) else {}
    state.setdefault("started_utc", dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
    json.dump(state, open(state_path, "w", encoding="utf8"), indent=1)

    fx = Fetcher(os.path.join(ROOT, "data", "raw", "request_log.csv"))
    devices = yaml.safe_load(open(os.path.join(ROOT, "config", "devices.yaml"), encoding="utf8"))["devices"]
    progress = os.path.join(ROOT, "results", "PROGRESS.md")

    def prog(msg):
        line = f"- {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')} {msg}\n"
        with open(progress, "a", encoding="utf8") as f:
            f.write(line)
        print(line, end="", flush=True)

    if not os.path.exists(progress):
        open(progress, "w", encoding="utf8").write(f"# Veri toplama ilerlemesi (çekim: {fetch_date})\n\n")

    for d in devices:
        for cms in d["cpe_match_strings"]:
            base = safe(f"{d['device_id']}__{cms.split(':')[2]}_{cms.split(':')[4]}")
            idx = 0
            while True:
                fn = os.path.join(pages_dir, f"{base}__start{idx:05d}.json")
                if os.path.exists(fn):
                    data = open(fn, "rb").read()
                else:
                    data = fx.get("cves/2.0", {"virtualMatchString": cms, "noRejected": "",
                                               "resultsPerPage": CVE_PAGE, "startIndex": idx})
                    if data is None:
                        raise NVDUnavailable(f"404: {cms}")
                    atomic_write(fn, data)
                j = json.loads(data)
                n = len(j.get("vulnerabilities", []))
                idx += n
                if n == 0 or idx >= j.get("totalResults", 0):
                    break
            prog(f"faz1 {d['device_id']} {cms}: totalResults={j.get('totalResults')}")

    dev_cves = {}
    for d in devices:
        members = {member_key(c) for c in d["cpe_match_strings"]}
        s = set()
        for fn in sorted(os.listdir(pages_dir)):
            if not fn.startswith(safe(d["device_id"]) + "__"):
                continue
            for v in json.loads(open(os.path.join(pages_dir, fn), "rb").read()).get("vulnerabilities", []):
                cve = v["cve"]
                for conf in cve.get("configurations", []):
                    for node in conf.get("nodes", []):
                        for m in node.get("cpeMatch", []):
                            if m.get("vulnerable") and member_key(m["criteria"]) in members:
                                s.add(cve["id"])
        dev_cves[d["device_id"]] = sorted(s)
    all_cves = sorted({c for v in dev_cves.values() for c in v})
    json.dump(dev_cves, open(os.path.join(raw, "device_cve_lists.json"), "w", encoding="utf8"), indent=1)
    prog(f"faz1 bitti: {len(all_cves)} tekil CVE; cihaz başına: " +
         ", ".join(f"{k}={len(v)}" for k, v in dev_cves.items()))

    def hist(cid):
        fn0 = os.path.join(hist_dir, f"{cid}__start00000.json")
        if os.path.exists(fn0):
            j = json.loads(open(fn0, "rb").read())
            tot = j.get("totalResults", 0)
            idx = len(j.get("cveChanges", []))
            if idx >= tot:
                return cid, "cached"
        idx = 0
        while True:
            fn = os.path.join(hist_dir, f"{cid}__start{idx:05d}.json")
            if os.path.exists(fn):
                data = open(fn, "rb").read()
            else:
                data = fx.get("cvehistory/2.0", {"cveId": cid, "resultsPerPage": HIST_PAGE, "startIndex": idx})
                if data is None:
                    with open(os.path.join(raw, "cvehistory_404.txt"), "a", encoding="utf8") as f:
                        f.write(cid + "\n")
                    return cid, "404"
                atomic_write(fn, data)
            j = json.loads(data)
            n = len(j.get("cveChanges", []))
            idx += n
            if n == 0 or idx >= j.get("totalResults", 0):
                return cid, "fetched"

    done = 0
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = [ex.submit(hist, c) for c in all_cves]
        for f in as_completed(futs):
            f.result()
            done += 1
            if done % 100 == 0 or done == len(all_cves):
                prog(f"faz2 cvehistory: {done}/{len(all_cves)}")

    state["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    state["fetch_date"] = fetch_date
    state["n_cves"] = len(all_cves)
    json.dump(state, open(state_path, "w", encoding="utf8"), indent=1)
    prog("TAMAMLANDI")


if __name__ == "__main__":
    main()
