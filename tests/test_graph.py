import os
import sys

import networkx as nx
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import graph

SMALL = {"entry_points": ["A"], "targets": ["D", "E"],
         "edges": [{"source": u, "target": v} for u, v in
                   [("A", "B"), ("A", "C"), ("B", "D"), ("C", "D"), ("D", "E"), ("B", "E")]],
         "path_rule": {"max_hops": 3}}


def test_small_graph_paths_by_hand():
    G = graph.build_dag(SMALL, set("ABCDE"))
    paths = graph.enumerate_paths(G, ["A"], ["D", "E"], 3)
    assert paths == [("A", "B", "D"), ("A", "C", "D"), ("A", "B", "D", "E"), ("A", "B", "E"), ("A", "C", "D", "E")]


def test_max_hops_cuts_paths():
    G = graph.build_dag(SMALL, set("ABCDE"))
    paths = graph.enumerate_paths(G, ["A"], ["D", "E"], 2)
    assert paths == [("A", "B", "D"), ("A", "C", "D"), ("A", "B", "E")]


def test_paths_table_ids_and_hops():
    rows = graph.paths_table([("A", "B", "D"), ("A", "B", "D", "E")])
    assert rows[0] == {"path_id": "P01", "entry": "A", "target": "D", "nodes": "A>B>D", "hops": 2}
    assert rows[1]["hops"] == 3 and rows[1]["path_id"] == "P02"


def test_cycle_reverse_and_unknown_rejected():
    cyc = dict(SMALL, edges=SMALL["edges"] + [{"source": "E", "target": "A"}])
    with pytest.raises(ValueError):
        graph.build_dag(cyc, set("ABCDE"))
    rev = dict(SMALL, edges=SMALL["edges"] + [{"source": "B", "target": "A"}])
    with pytest.raises(ValueError):
        graph.build_dag(rev, set("ABCDE"))
    with pytest.raises(ValueError):
        graph.build_dag(SMALL, set("ABCD"))


def test_project_topology_matches_networkx():
    topo, G, rows = graph.load_paths()
    assert G.number_of_nodes() == 13 and G.number_of_edges() == 21
    assert nx.is_directed_acyclic_graph(G)
    assert all(not G.has_edge(v, u) for u, v in G.edges)
    ref = set()
    for s in topo["entry_points"]:
        for t in topo["targets"]:
            ref |= {tuple(p) for p in nx.all_simple_paths(G, s, t, cutoff=topo["path_rule"]["max_hops"])}
    own = {tuple(r["nodes"].split(">")) for r in rows}
    assert own == ref
    assert all(1 <= r["hops"] <= 6 for r in rows)
    assert all(r["entry"] in topo["entry_points"] and r["target"] in topo["targets"] for r in rows)
