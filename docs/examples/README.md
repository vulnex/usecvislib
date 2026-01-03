# USecVisLib Examples

This directory contains example configuration files for the various visualization modules.

## Custom Diagrams

Located in `custom-diagrams/`:

| Example | Description |
|---------|-------------|
| `simple-flowchart.toml` | Basic login process flowchart |
| `network-topology.toml` | Three-tier network architecture |

### Usage

#### Python

```python
from usecvislib import CustomDiagrams

cd = CustomDiagrams()
cd.load("docs/examples/custom-diagrams/simple-flowchart.toml")
cd.BuildCustomDiagram(output="flowchart", format="png")
```

#### CLI

```bash
usecvis -m 4 -i docs/examples/custom-diagrams/simple-flowchart.toml -o flowchart -f png
usecvis -m 4 -i docs/examples/custom-diagrams/network-topology.toml -o network -f png -s cd_corporate
```

## More Examples

For more comprehensive examples, see the `templates/` directory:

- `templates/attack-trees/` - Attack tree configurations
- `templates/attack-graphs/` - Attack graph configurations
- `templates/threat-models/` - Threat model configurations
- `templates/custom-diagrams/` - Custom diagram templates

## Documentation

- [Custom Diagrams Guide](../CUSTOM_DIAGRAMS_GUIDE.md)
- [CLI Guide](../CLI_GUIDE.md)
- [Python API Guide](../PYTHON_API.md)
