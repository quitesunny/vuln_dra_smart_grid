import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(__file__))
import build_pairs as BP
import graph
import nvd_parse as P
import rawdata
import timeline as TL

ROOT = rawdata.ROOT
CONFIG = os.path.join(ROOT, "config", "model.yaml")
TOL = 1e-9
COMPONENTS = [("katki_yeni", "yeni CVE"), ("katki_revize", "revizyon"), ("katki_kaldirilan", "kaldırılan")]


def load_config(path=CONFIG):
    with open(path, encoding="utf8") as f:
        cfg = yaml.safe_load(f)
    cfg["t_x"], cfg["t_y"], cfg["cvss_version"] = str(cfg["t_x"]), str(cfg["t_y"]), str(cfg["cvss_version"])
    if cfg["cvss_version"] not in ("2.0", "3.0", "3.1"):
        raise ValueError(f"desteklenmeyen sürüm: {cfg['cvss_version']}")
    if not cfg["t_x"] < cfg["t_y"]:
        raise ValueError("t_x, t_y'den önce olmalı")
    return cfg


def load_data(fetch_date):
    D = rawdata.load(fetch_date)
    lookup, _ = BP.build_lookup(D["cves"])
    return D, TL.Timeline(D["cves"], D["hist"], lookup)


def nvd_metric_not_primary(cve, version):
    if P.nvd_primary(cve, version) is not None:
        return False
    return any(m["version"] == version and m["source"] == P.NVD_SOURCE for m in P.current_metrics(cve))


def scores_at(D, tl, cves, date, version):
    when = date + "T23:59:59.999"
    scores, skipped = {}, []
    for c in sorted(cves):
        if c not in D["hist"]:
            skipped.append((c, "change history yok"))
            continue
        if nvd_metric_not_primary(D["cves"].get(c, {}), version):
            skipped.append((c, "çekim anında NVD metriği Primary değil"))
            continue
        r = tl.score_at(c, when, version)
        if r["state"] != "scored":
            continue
        if r["score"] is None:
            skipped.append((c, "skorlu ama vektörün skoru ham tabloda yok"))
            continue
        scores[c] = float(r["score"])
    return scores, skipped


def mean(values):
    values = list(values)
    return sum(values) / len(values) if values else None


def decompose(s_x, s_y):
    common = sorted(set(s_x) & set(s_y))
    n_x, n_y = mean(s_x.values()), mean(s_y.values())
    diff = None if n_x is None or n_y is None else n_y - n_x
    out = {"N_x": n_x, "N_y": n_y, "fark": diff, "n_cve_x": len(s_x), "n_cve_y": len(s_y),
           "n_ortak": len(common), "n_yeni": len(set(s_y) - set(s_x)), "n_kaldirilan": len(set(s_x) - set(s_y)),
           "n_revize": sum(1 for c in common if abs(s_y[c] - s_x[c]) > TOL),
           "katki_yeni": None, "katki_revize": None, "katki_kaldirilan": None}
    if not common:
        return out
    cx, cy = mean(s_x[c] for c in common), mean(s_y[c] for c in common)
    out["katki_kaldirilan"] = cx - n_x
    out["katki_revize"] = cy - cx
    out["katki_yeni"] = n_y - cy
    total = out["katki_yeni"] + out["katki_revize"] + out["katki_kaldirilan"]
    if abs(total - diff) > TOL:
        raise ValueError(f"bileşen toplamı ({total}) farka ({diff}) eşit değil")
    return out


def label(diff, threshold):
    if diff > threshold:
        return "artan"
    if diff < -threshold:
        return "azalan"
    return "değişmedi"


def undefined_label(n_x, n_y, what="skorlu CVE yok"):
    if n_x is None and n_y is None:
        return f"t_x'te tanımsız (t_x'te ve t_y'de {what})"
    if n_x is None:
        return f"t_x'te tanımsız (t_x'te {what})"
    return f"t_y'de tanımsız (t_y'de {what})"


def dominant_reason(row):
    vals = [(name, row[key]) for key, name in COMPONENTS]
    if any(v is None for _, v in vals):
        return "" if row["fark"] is None else "belirlenemedi (t_x ve t_y'de ortak CVE yok)"
    name, v = max(vals, key=lambda kv: abs(kv[1]))
    return name if abs(v) > TOL else "yok (fark 0)"


def device_changes(D, tl, cfg):
    v, thr = cfg["cvss_version"], cfg["değişim_etiketi_eşiği"]
    rows, detail = [], {}
    for d in [x["device_id"] for x in D["devices"]]:
        s_x, skip_x = scores_at(D, tl, D["dev_cves"][d], cfg["t_x"], v)
        s_y, skip_y = scores_at(D, tl, D["dev_cves"][d], cfg["t_y"], v)
        r = decompose(s_x, s_y)
        r["etiket"] = undefined_label(r["N_x"], r["N_y"]) if r["fark"] is None else label(r["fark"], thr)
        r["baskin_neden"] = dominant_reason(r)
        rows.append({"device_id": d, **r})
        detail[d] = {"s_x": s_x, "s_y": s_y, "skip_x": skip_x, "skip_y": skip_y}
    return rows, detail


def path_changes(path_rows, dev_rows, threshold):
    by = {r["device_id"]: r for r in dev_rows}
    out = []
    for p in path_rows:
        seq = p["nodes"].split(graph.NODE_SEP)
        nx_, ny_ = [by[d]["N_x"] for d in seq], [by[d]["N_y"] for d in seq]
        p_x = None if None in nx_ else mean(nx_)
        p_y = None if None in ny_ else mean(ny_)
        diff = None if p_x is None or p_y is None else p_y - p_x
        if diff is None:
            bad = [d for d in seq if by[d]["N_x"] is None or by[d]["N_y"] is None]
            et = undefined_label(p_x, p_y, "skorlu CVE yok: " + ", ".join(bad))
            most = ""
        else:
            et = label(diff, threshold)
            d_best = max(seq, key=lambda d: abs(by[d]["fark"]))
            most = d_best if abs(by[d_best]["fark"]) > TOL else "yok (tüm düğümlerde fark 0)"
        out.append({"path_id": p["path_id"], "düğümler": p["nodes"], "P_x": p_x, "P_y": p_y, "fark": diff,
                    "etiket": et, "en_cok_degisen_dugum": most})
    return out


def monthly_device_severity(D, tl, cfg):
    out = []
    months = [m.isoformat() for m in TL.month_ends(cfg["t_x"], cfg["t_y"])]
    for d in [x["device_id"] for x in D["devices"]]:
        for m in months:
            s, _ = scores_at(D, tl, D["dev_cves"][d], m, cfg["cvss_version"])
            out.append({"device_id": d, "ay": m[:7], "N_d": mean(s.values()), "skorlu_cve_sayisi": len(s)})
    return out
