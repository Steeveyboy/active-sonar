# active-sonar
An active network sonar engine. Uses Scapy to emit custom packet sweeps and renders live local subnet topologies through a force-directed D3.js graph.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Scan and generate topology output

```bash
python -m src.active_sonar 192.168.1.0/24 --json topology.json --html topology.html
```

- `--json`: writes discovered hosts and graph edges to JSON
- `--html`: writes a D3 force-graph HTML visualization
- If no output flags are provided, JSON is printed to stdout

## Testing

```bash
python -m unittest discover -s tests -p 'test_*.py'
```
