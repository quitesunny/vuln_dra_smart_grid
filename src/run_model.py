import calendar
import csv
import datetime as dt
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
import graph
import model as M

ROOT = M.ROOT
PALETTE = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
GRAY, INK, INK2, GRID = "#c9c8c3", "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                     "grid.color": GRID, "grid.linewidth": 0.6, "axes.edgecolor": "#9b9a95", "text.color": INK,
                     "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2, "legend.frameon": False})


def f4(x):
    if x is None:
        return ""
    return f"{0.0 if round(x, 4) == 0 else x:.4f}"


def write_csv(path, rows, cols):
    with open(path, "w", newline="", encoding="utf8") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([f4(r[c]) if isinstance(r[c], float) or (r[c] is None) else r[c] for c in cols])


def month_end(ay):
    y, m = map(int, ay.split("-"))
    return dt.date(y, m, calendar.monthrange(y, m)[1])


def figure1(dev_rows, cfg, out):
    n = len(dev_rows)
    fig, ax = plt.subplots(figsize=(8, 0.42 * n + 1.2))
    h = 0.36
    for i, r in enumerate(dev_rows):
        y = n - 1 - i
        if r["N_x"] is not None:
            ax.barh(y + h / 2 + 0.01, r["N_x"], height=h, color=PALETTE[0], label="N_x" if i == 0 else None)
        if r["N_y"] is not None:
            ax.barh(y - h / 2 - 0.01, r["N_y"], height=h, color=PALETTE[1], label="N_y" if i == 0 else None)
        top = max(v for v in (r["N_x"], r["N_y"], 0) if v is not None)
        txt = f"fark {r['fark']:+.4f} ({r['etiket']})" if r["fark"] is not None else r["etiket"]
        ax.text(top + 0.15, y, txt, va="center", fontsize=7, color=INK)
    ax.set_yticks(range(n))
    ax.set_yticklabels([r["device_id"] for r in reversed(dev_rows)], fontsize=7)
    ax.set_xlim(0, 15.5)
    ax.set_xticks(range(0, 11))
    ax.set_xlabel(f"N_d: ortalama CVSS v{cfg['cvss_version']} temel skoru (NVD Primary)")
    ax.grid(axis="y", visible=False)
    ax.set_axisbelow(True)
    h1 = plt.Rectangle((0, 0), 1, 1, color=PALETTE[0])
    h2 = plt.Rectangle((0, 0), 1, 1, color=PALETTE[1])
    ax.legend([h1, h2], [f"N_x ({cfg['t_x']})", f"N_y ({cfg['t_y']})"], loc="lower right", fontsize=7)
    ax.set_title(f"Şekil 1. Cihaz başına düğüm şiddeti N_d: t_x = {cfg['t_x']} ve t_y = {cfg['t_y']}\n"
                 f"CVSS v{cfg['cvss_version']} NVD Primary; etiket eşiği ±{cfg['değişim_etiketi_eşiği']}",
                 loc="left", fontsize=8.5)
    fig.tight_layout()
    fig.savefig(out, dpi=300, metadata={"Software": None})
    plt.close(fig)


def figure2(monthly, dev_rows, cfg, out):
    ranked = sorted([r for r in dev_rows if r["fark"] is not None], key=lambda r: -abs(r["fark"]))
    top = [r["device_id"] for r in ranked[:5]]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    by = {}
    for r in monthly:
        by.setdefault(r["device_id"], []).append(r)
    for d, rs in by.items():
        if d in top:
            continue
        x = [month_end(r["ay"]) for r in rs]
        ax.plot(x, [float("nan") if r["N_d"] is None else r["N_d"] for r in rs], color=GRAY, lw=0.9, zorder=1)
    ends = []
    for k, d in enumerate(top):
        rs = by[d]
        x = [month_end(r["ay"]) for r in rs]
        y = [float("nan") if r["N_d"] is None else r["N_d"] for r in rs]
        ax.plot(x, y, color=PALETTE[k], lw=2, zorder=3, label=d)
        last = [(a, b) for a, b in zip(x, y) if b == b]
        if last:
            ends.append([last[-1][1], last[-1][0], d])
    lo, hi = ax.get_ylim()
    gap = 0.045 * (hi - lo)
    ends.sort()
    for i in range(1, len(ends)):
        ends[i][0] = max(ends[i][0], ends[i - 1][0] + gap)
    for ylab, x_end, d in ends:
        ax.annotate(d, (x_end, ylab), xytext=(5, 0), textcoords="offset points", va="center", fontsize=6.5,
                    color=INK, annotation_clip=False)
    ax.xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 4, 7, 10)))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    ax.set_xlabel("ay (ay sonu anlık görüntüsü)")
    ax.set_ylabel(f"N_d (ortalama CVSS v{cfg['cvss_version']})")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), fontsize=6.5, ncol=3,
              title="renkli: |fark| en büyük 5 cihaz; gri: diğer cihazlar (fark tanımsız olanlar dahil)",
              title_fontsize=6.5)
    ax.set_title(f"Şekil 2. Aylık düğüm şiddeti N_d (CVSS v{cfg['cvss_version']} NVD Primary), "
                 f"{cfg['t_x']} – {cfg['t_y']}\n"
                 "skorlu CVE'si olmayan aylar boş bırakıldı", loc="left", fontsize=8.5)
    x0, x1 = ax.get_xlim()
    ax.set_xlim(x0, x1 + 0.22 * (x1 - x0))
    end = mdates.date2num(dt.date.fromisoformat(cfg["t_y"]))
    ax.set_xticks([t for t in ax.get_xticks() if t <= end])
    fig.tight_layout()
    fig.savefig(out, dpi=300, metadata={"Software": None})
    plt.close(fig)


def worked_example(D, tl, cfg, dev_rows, detail, path_out):
    v, thr = cfg["cvss_version"], cfg["değişim_etiketi_eşiği"]
    L = [f"# Worked example (CVSS v{v}, NVD Primary; t_x = {cfg['t_x']}, t_y = {cfg['t_y']})", ""]
    cand = [r for r in dev_rows if r["fark"] is not None and abs(r["fark"]) > M.TOL]
    if not cand:
        L.append("Farkı tanımlı ve sıfırdan farklı cihaz yok; cihaz örneği üretilmedi.")
        return "\n".join(L) + "\n"
    dev = min(cand, key=lambda r: r["n_cve_y"])
    d = dev["device_id"]
    s_x, s_y = detail[d]["s_x"], detail[d]["s_y"]
    common = sorted(set(s_x) & set(s_y))
    L += [f"## 1. Cihaz: {d}", "",
          "Seçim kuralı: farkı tanımlı ve sıfırdan farklı cihazlar arasında t_y'de en az skorlu CVE'si olan.", "",
          "| CVE | skor t_x | skor t_y | grup |", "|---|---|---|---|"]
    for c in sorted(set(s_x) | set(s_y)):
        g = "ortak" if c in common else ("yeni (t_y'de skorlu, t_x'te değil)" if c in s_y else "kaldırılan")
        if c in common and abs(s_x[c] - s_y[c]) > M.TOL:
            g = "ortak, revize"
        L.append(f"| {c} | {s_x.get(c, '—')} | {s_y.get(c, '—')} | {g} |")
    sk_x, sk_y = dict(detail[d]["skip_x"]), dict(detail[d]["skip_y"])
    for c in sorted(set(sk_x) | set(sk_y)):
        if sk_x.get(c) == sk_y.get(c):
            when = "t_x ve t_y'de"
        else:
            when = "t_x'te" if c in sk_x else "t_y'de"
        L.append(f"| {c} | — | — | {when} dışlandı: {sk_x.get(c) or sk_y.get(c)} |")
    sx, sy = sum(s_x.values()), sum(s_y.values())
    cx = sum(s_x[c] for c in common)
    cy = sum(s_y[c] for c in common)
    L += ["",
          f"- N_x = {sx:.1f} / {len(s_x)} = **{dev['N_x']:.4f}**",
          f"- N_y = {sy:.1f} / {len(s_y)} = **{dev['N_y']:.4f}**",
          f"- fark = N_y − N_x = {dev['N_y']:.4f} − {dev['N_x']:.4f} = **{dev['fark']:+.4f}**",
          f"- ortak CVE: {len(common)}; ortak ortalama t_x = {cx:.1f} / {len(common)} = {cx / len(common):.4f}; "
          f"t_y = {cy:.1f} / {len(common)} = {cy / len(common):.4f}",
          f"- kaldırılan katkısı = ort_ortak(t_x) − N_x = {cx / len(common):.4f} − {dev['N_x']:.4f} = **{dev['katki_kaldirilan']:+.4f}**",
          f"- revize katkısı = ort_ortak(t_y) − ort_ortak(t_x) = {cy / len(common):.4f} − {cx / len(common):.4f} = **{dev['katki_revize']:+.4f}**",
          f"- yeni CVE katkısı = N_y − ort_ortak(t_y) = {dev['N_y']:.4f} − {cy / len(common):.4f} = **{dev['katki_yeni']:+.4f}**",
          f"- bileşen toplamı = {dev['katki_yeni'] + dev['katki_revize'] + dev['katki_kaldirilan']:+.4f} = fark",
          f"- etiket: fark {dev['fark']:+.4f}, eşik ±{thr} → **{dev['etiket']}**; baskın neden: **{dev['baskin_neden']}**", ""]
    by = {r["device_id"]: r for r in dev_rows}
    p = next((r for r in path_out if d in r["düğümler"].split(graph.NODE_SEP) and r["fark"] is not None), None)
    if p:
        seq = p["düğümler"].split(graph.NODE_SEP)
        L += [f"## 2. Yol: {p['path_id']}", "",
              f"Seçim kuralı: {d} düğümünü içeren ve farkı tanımlı ilk path_id.", "",
              "| düğüm | N_x | N_y | fark |", "|---|---|---|---|"]
        L += [f"| {n} | {by[n]['N_x']:.4f} | {by[n]['N_y']:.4f} | {by[n]['fark']:+.4f} |" for n in seq]
        terms_x = " + ".join(f"{by[n]['N_x']:.4f}" for n in seq)
        terms_y = " + ".join(f"{by[n]['N_y']:.4f}" for n in seq)
        L += ["",
              f"- P_x = ({terms_x}) / {len(seq)} = **{p['P_x']:.4f}**",
              f"- P_y = ({terms_y}) / {len(seq)} = **{p['P_y']:.4f}**",
              f"- fark = **{p['fark']:+.4f}**; etiket (eşik ±{thr}): **{p['etiket']}**; "
              f"en çok değişen düğüm: **{p['en_cok_degisen_dugum']}**", ""]
    L += independent_check(D, tl, cfg, dev_rows, detail)
    return "\n".join(L) + "\n"


def independent_check(D, tl, cfg, dev_rows, detail):
    v = cfg["cvss_version"]
    with open(os.path.join(ROOT, "data", "processed", "cve_pairs.csv"), encoding="utf8") as f:
        cur = {r["cve_id"]: float(r["current_score"]) for r in csv.DictReader(f) if r["cvss_version"] == v}
    with open(os.path.join(ROOT, "data", "processed", "excluded.csv"), encoding="utf8") as f:
        excl = {}
        for r in csv.DictReader(f):
            excl.setdefault((r["cve_id"], r["cvss_version"]), []).append(r["reason"])
    L = ["## 3. Bağımsız kontrol: N_y vs data/processed/cve_pairs.csv güncel skorları", "",
         f"cve_pairs.csv güncel skoru = çekim anı ({cfg['fetch_date']}); model N_y = t_y ({cfg['t_y']}) anı, score_at ile.", "",
         "| device_id | N_y (model) | N_y (cve_pairs) | fark | n (model) | n (cve_pairs) |", "|---|---|---|---|---|---|"]
    diffs = []
    for r in dev_rows:
        d = r["device_id"]
        pv = {c: cur[c] for c in sorted(D["dev_cves"][d]) if c in cur}
        alt = M.mean(pv.values())
        dd = None if alt is None or r["N_y"] is None else alt - r["N_y"]
        L.append(f"| {d} | {f4(r['N_y'])} | {f4(alt)} | {'' if dd is None else f'{dd:+.4f}'} | {r['n_cve_y']} | {len(pv)} |")
        s_y = detail[d]["s_y"]
        for c in sorted(set(s_y) | set(pv)):
            if c in s_y and c in pv:
                if abs(s_y[c] - pv[c]) > M.TOL:
                    diffs.append((d, c, f"skor farklı: t_y {s_y[c]}, çekim anı {pv[c]} (t_y sonrası revizyon)"))
            elif c in s_y:
                diffs.append((d, c, f"t_y'de skorlu ({s_y[c]}) ama cve_pairs.csv'de çifti yok; excluded.csv nedeni: "
                                    + ";".join(excl.get((c, v), ["kayıt yok"]))))
            else:
                st = tl.score_at(c, cfg["t_y"] + "T23:59:59.999", v)["state"]
                why = dict(detail[d]["skip_y"]).get(c, f"t_y'de durum: {st}")
                diffs.append((d, c, f"cve_pairs.csv'de var (güncel {pv[c]}) ama t_y'de N_d'ye girmedi: {why}"))
    L += ["", f"CVE düzeyinde farklar: {len(diffs)}", ""]
    if diffs:
        L += ["| device_id | CVE | neden |", "|---|---|---|"] + [f"| {a} | {b} | {c} |" for a, b, c in diffs]
    L.append("")
    return L


def main():
    cfg = M.load_config()
    out = os.path.join(ROOT, cfg.get("output_dir", "results"))
    os.makedirs(out, exist_ok=True)
    D, tl = M.load_data(cfg["fetch_date"])
    _, _, path_rows = graph.load_paths()
    dev_rows, detail = M.device_changes(D, tl, cfg)
    path_out = M.path_changes(path_rows, dev_rows, cfg["değişim_etiketi_eşiği"])
    monthly = M.monthly_device_severity(D, tl, cfg)
    write_csv(os.path.join(out, "device_changes.csv"), dev_rows,
              ["device_id", "N_x", "N_y", "fark", "n_cve_x", "n_cve_y", "katki_yeni", "katki_revize",
               "katki_kaldirilan", "etiket", "baskin_neden"])
    write_csv(os.path.join(out, "path_changes.csv"), path_out,
              ["path_id", "düğümler", "P_x", "P_y", "fark", "etiket", "en_cok_degisen_dugum"])
    write_csv(os.path.join(out, "monthly_device_severity.csv"), monthly, ["device_id", "ay", "N_d", "skorlu_cve_sayisi"])
    figure1(dev_rows, cfg, os.path.join(out, "sekil1_cihaz_x_y.png"))
    figure2(monthly, dev_rows, cfg, os.path.join(out, "sekil2_aylik_N_d.png"))
    with open(os.path.join(out, "worked_example.md"), "w", encoding="utf8") as f:
        f.write(worked_example(D, tl, cfg, dev_rows, detail, path_out))
    print(f"v{cfg['cvss_version']} {cfg['t_x']} -> {cfg['t_y']}: {len(dev_rows)} cihaz, {len(path_out)} yol, "
          f"{len(monthly)} aylık satır -> {out}")


if __name__ == "__main__":
    main()
