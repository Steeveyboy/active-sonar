"""Minimal network mapping and visualization helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str


def discover_hosts(
    cidr: str,
    timeout: int = 2,
    srp_func: Callable | None = None,
) -> list[Host]:
    """Discover hosts in a CIDR range using ARP sweep via Scapy."""
    if srp_func is None:
        try:
            from scapy.all import ARP, Ether, srp
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is required for active scanning. Install with `pip install scapy`."
            ) from exc
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(request, timeout=timeout, verbose=False)
    else:
        answered, _ = srp_func(cidr, timeout)

    hosts: list[Host] = []
    for _, response in answered:
        ip = getattr(response, "psrc", None)
        mac = getattr(response, "hwsrc", None)
        if ip and mac:
            hosts.append(Host(ip=ip, mac=mac))

    unique_hosts = {(host.ip, host.mac): host for host in hosts}
    return sorted(unique_hosts.values(), key=lambda host: tuple(int(x) for x in host.ip.split(".")))


def build_topology(hosts: Iterable[Host], center_label: str = "network") -> dict:
    """Build a basic graph topology from discovered hosts."""
    host_list = list(hosts)
    nodes = [{"id": center_label, "label": center_label, "group": "center"}]
    edges = []

    for host in host_list:
        node_id = host.ip
        nodes.append({"id": node_id, "label": f"{host.ip}\n{host.mac}", "group": "host"})
        edges.append({"source": center_label, "target": node_id})

    return {"nodes": nodes, "edges": edges}


def write_topology_html(topology: dict, output_path: str | Path) -> None:
    """Write a small standalone D3 force-graph HTML page."""
    graph_json = json.dumps(topology)
    html = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>active-sonar topology</title>
  <script src=\"https://d3js.org/d3.v7.min.js\"></script>
</head>
<body>
  <h1>active-sonar topology</h1>
  <svg id=\"graph\" width=\"1000\" height=\"700\"></svg>
  <script>
    const graph = {graph_json};
    const svg = d3.select("#graph");
    const width = +svg.attr("width");
    const height = +svg.attr("height");

    const simulation = d3.forceSimulation(graph.nodes)
      .force("link", d3.forceLink(graph.edges).id(d => d.id).distance(130))
      .force("charge", d3.forceManyBody().strength(-320))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const links = svg.append("g")
      .selectAll("line")
      .data(graph.edges)
      .join("line")
      .attr("stroke", "#999")
      .attr("stroke-opacity", 0.6);

    const nodes = svg.append("g")
      .selectAll("circle")
      .data(graph.nodes)
      .join("circle")
      .attr("r", d => d.group === "center" ? 12 : 8)
      .attr("fill", d => d.group === "center" ? "#0d6efd" : "#20c997")
      .call(d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended));

    const labels = svg.append("g")
      .selectAll("text")
      .data(graph.nodes)
      .join("text")
      .text(d => d.label)
      .attr("font-size", 11)
      .attr("dx", 12)
      .attr("dy", 4);

    simulation.on("tick", () => {{
      links
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      nodes
        .attr("cx", d => d.x)
        .attr("cy", d => d.y);

      labels
        .attr("x", d => d.x)
        .attr("y", d => d.y);
    }});

    function dragstarted(event, d) {{
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }}

    function dragged(event, d) {{
      d.fx = event.x;
      d.fy = event.y;
    }}

    function dragended(event, d) {{
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }}
  </script>
</body>
</html>
"""
    Path(output_path).write_text(html, encoding="utf-8")
