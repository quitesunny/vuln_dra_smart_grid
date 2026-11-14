import csv
import os

import networkx as nx
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOPOLOGY = os.path.join(ROOT, "config", "topology.yaml")
DEVICES = os.path.join(ROOT, "config", "devices.yaml")
NODE_SEP = ">"


def load_topology(path=TOPOLOGY):
    with open(path, encoding="utf8") as f:
        return yaml.safe_load(f)


def device_ids(path=DEVICES):
    with open(path, encoding="utf8") as f:
        return [d["device_id"] for d in yaml.safe_load(f)["devices"]]


def build_dag(topo, known_nodes=None):
    G = nx.DiGraph()
    if known_nodes is not None:
        G.add_nodes_from(known_nodes)
    for e in topo["edges"]:
        u, v = e["source"], e["target"]
        if known_nodes is not None and (u not in known_nodes or v not in known_nodes):
            raise ValueError(f"bilinmeyen düğüm: {u} -> {v}")
        if G.has_edge(v, u):
            raise ValueError(f"ters yön kopyası: {u} <-> {v}")
        G.add_edge(u, v, rationale=e.get("rationale", ""))
    for n in list(topo.get("entry_points", [])) + list(topo.get("targets", [])):
        if known_nodes is not None and n not in known_nodes:
            raise ValueError(f"bilinmeyen giriş/hedef: {n}")
        G.add_node(n)
    if not nx.is_directed_acyclic_graph(G):
        raise ValueError("graf döngüsüz değil")
    return G


def simple_paths(G, source, target, max_hops):
    out = []

    def dfs(node, path):
        if node == target:
            out.append(tuple(path))
            return
        if len(path) - 1 >= max_hops:
            return
        for nxt in sorted(G.successors(node)):
            if nxt in path:
                continue
            path.append(nxt)
            dfs(nxt, path)
            path.pop()

    if source == target:
        return [(source,)]
    dfs(source, [source])
    return out


def enumerate_paths(G, entries, targets, max_hops):
    paths = []
    for s in entries:
        for t in targets:
            if s == t:
                continue
            paths.extend(sorted(simple_paths(G, s, t, max_hops)))
    return paths


def paths_table(paths):
    w = max(2, len(str(len(paths))))
    return [{"path_id": f"P{i:0{w}d}", "entry": p[0], "target": p[-1], "nodes": NODE_SEP.join(p),
             "hops": len(p) - 1} for i, p in enumerate(paths, 1)]


def load_paths(topo_path=TOPOLOGY, devices_path=DEVICES):
    topo = load_topology(topo_path)
    G = build_dag(topo, set(device_ids(devices_path)))
    rule = topo["path_rule"]
    paths = enumerate_paths(G, topo["entry_points"], topo["targets"], rule["max_hops"])
    return topo, G, paths_table(paths)


def write_paths_csv(rows, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf8") as f:
        w = csv.DictWriter(f, fieldnames=["path_id", "entry", "target", "nodes", "hops"])
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    _, _, rows = load_paths()
    write_paths_csv(rows, os.path.join(ROOT, "results", "tables", "paths.csv"))
    print(f"yol sayısı {len(rows)}")
