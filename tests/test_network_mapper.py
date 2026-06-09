import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.active_sonar.network_mapper import Host, build_topology, discover_hosts, write_topology_html


class NetworkMapperTests(unittest.TestCase):
    def test_discover_hosts_with_injected_srp(self):
        responses = [
            (None, SimpleNamespace(psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:01")),
            (None, SimpleNamespace(psrc="192.168.1.2", hwsrc="aa:bb:cc:dd:ee:02")),
            (None, SimpleNamespace(psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:01")),
        ]

        def fake_srp(cidr: str, timeout: int):
            self.assertEqual(cidr, "192.168.1.0/24")
            self.assertEqual(timeout, 2)
            return responses, []

        hosts = discover_hosts("192.168.1.0/24", srp_func=fake_srp)

        self.assertEqual(
            hosts,
            [
                Host(ip="192.168.1.2", mac="aa:bb:cc:dd:ee:02"),
                Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01"),
            ],
        )

    def test_build_topology_creates_center_and_edges(self):
        topology = build_topology([Host(ip="10.0.0.2", mac="00:11"), Host(ip="10.0.0.3", mac="00:22")])

        self.assertEqual(topology["nodes"][0]["id"], "network")
        self.assertEqual(len(topology["nodes"]), 3)
        self.assertEqual(
            topology["edges"],
            [
                {"source": "network", "target": "10.0.0.2"},
                {"source": "network", "target": "10.0.0.3"},
            ],
        )

    def test_write_topology_html_writes_d3_graph(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "map.html"
            topology = {"nodes": [{"id": "network", "label": "network", "group": "center"}], "edges": []}

            write_topology_html(topology, output)

            content = output.read_text(encoding="utf-8")
            self.assertIn("d3.v7.min.js", content)
            self.assertIn('"id": "network"', content)


if __name__ == "__main__":
    unittest.main()
