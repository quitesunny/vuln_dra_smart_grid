import math
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import graph

TOL = 1e-9
TIE = 1e-12


def node_p(dev_rows):
    def p(v):
        return None if v is None or v <= 0 else v / 10.0
    return {r["device_id"]: (p(r["N_x"]), p(r["N_y"])) for r in dev_rows}


def path_R(seq, p, k):
    vals = [p[d][k] for d in seq]
    return None if any(v is None for v in vals) else math.prod(vals)


def argmax_path(cands, k):
    best = max(c[2][k] for c in cands)
    return next(c for c in cands if c[2][k] >= best - TIE)


def target_risk(path_rows, dev_rows, targets):
    p = node_p(dev_rows)
    out = []
    for tgt in targets:
        allp = [r for r in path_rows if r["target"] == tgt]
        cands = []
        for r in allp:
            seq = r["nodes"].split(graph.NODE_SEP)
            rx, ry = path_R(seq, p, 0), path_R(seq, p, 1)
            if rx is not None and ry is not None:
                cands.append((r["path_id"], seq, (rx, ry)))
        row = {"hedef": tgt, "n_yol": len(allp), "n_yol_tanimsiz": len(allp) - len(cands), "R_x": None,
               "R_y": None, "ln_fark": None, "en_olasi_yol_x": "", "en_olasi_yol_y": "", "ayni_yol": "",
               "dugum_katkilari": "", "yol_degisimi_katkisi": None, "katki_toplami": None, "_katki": {}}
        if cands:
            px, py = argmax_path(cands, 0), argmax_path(cands, 1)
            rx, ry = px[2][0], py[2][1]
            ln_fark = math.log(ry) - math.log(rx)
            contrib = {d: math.log(p[d][1] / p[d][0]) for d in px[1]}
            switch = math.log(ry) - math.log(px[2][1])
            total = sum(contrib.values()) + switch
            if abs(total - ln_fark) > TOL:
                raise ValueError(f"{tgt}: katkı toplamı ({total}) ln farka ({ln_fark}) eşit değil")
            row.update({"R_x": rx, "R_y": ry, "ln_fark": ln_fark, "en_olasi_yol_x": px[0], "en_olasi_yol_y": py[0],
                        "ayni_yol": "evet" if px[0] == py[0] else "hayır",
                        "dugum_katkilari": "; ".join(f"{d}:{contrib[d]:+.6f}" for d in px[1]),
                        "yol_degisimi_katkisi": switch, "katki_toplami": total, "_katki": contrib})
        out.append(row)
    return out
