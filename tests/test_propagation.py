import math
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import graph
import model as M
import propagation as PR
from run_main import MAIN_T_X


def dev(d, nx, ny):
    return {"device_id": d, "N_x": nx, "N_y": ny}


def path(pid, *nodes):
    return {"path_id": pid, "target": nodes[-1], "nodes": graph.NODE_SEP.join(nodes)}


def test_same_path_contributions_sum_to_ln_diff():
    devs = [dev("A", 8.0, 8.0), dev("B", 5.0, 6.0), dev("C", 9.0, 4.0), dev("T", 7.0, 7.5)]
    paths = [path("P1", "A", "B", "T"), path("P2", "A", "C", "T")]
    (r,) = PR.target_risk(paths, devs, ["T"])
    assert r["en_olasi_yol_x"] == "P2" and r["en_olasi_yol_y"] == "P1" and r["ayni_yol"] == "hayır"
    assert r["R_x"] == pytest.approx(0.504) and r["R_y"] == pytest.approx(0.36)
    assert r["ln_fark"] == pytest.approx(math.log(0.36 / 0.504))
    assert sum(r["_katki"].values()) + r["yol_degisimi_katkisi"] == pytest.approx(r["ln_fark"], abs=1e-12)
    assert r["_katki"]["C"] == pytest.approx(math.log(0.4 / 0.9))


def test_undefined_node_leaves_path_undefined_no_fill():
    devs = [dev("A", 8.0, 8.0), dev("B", None, 6.0), dev("T", 7.0, 7.0)]
    paths = [path("P1", "A", "B", "T"), path("P2", "A", "T")]
    (r,) = PR.target_risk(paths, devs, ["T"])
    assert r["n_yol"] == 2 and r["n_yol_tanimsiz"] == 1
    assert r["en_olasi_yol_x"] == "P2" and r["en_olasi_yol_y"] == "P2"
    (r2,) = PR.target_risk([path("P1", "A", "B", "T")], devs, ["T"])
    assert r2["R_x"] is None and r2["ln_fark"] is None and r2["en_olasi_yol_x"] == ""


@pytest.fixture(scope="module")
def data():
    cfg = M.load_config()
    D, tl = M.load_data(cfg["fetch_date"])
    topo, _, paths = graph.load_paths()
    return cfg, D, tl, topo, paths


def test_real_data_total_equals_ln_diff_all_horizons(data):
    cfg, D, tl, topo, paths = data
    for tx in [str(t) for t in cfg["horizon_t_x"]] + [MAIN_T_X]:
        devs, _ = M.device_changes(D, tl, dict(cfg, t_x=tx))
        for r in PR.target_risk(paths, devs, topo["targets"]):
            if r["ln_fark"] is None:
                continue
            assert sum(r["_katki"].values()) + r["yol_degisimi_katkisi"] == pytest.approx(r["ln_fark"], abs=1e-9)
            assert r["ln_fark"] == pytest.approx(math.log(r["R_y"]) - math.log(r["R_x"]), abs=1e-12)
            if r["ayni_yol"] == "evet":
                assert r["yol_degisimi_katkisi"] == 0.0
