#!/usr/bin/env python3
"""
Custom Diagram Example - Basic (No Icons)

This example demonstrates how to create custom diagrams
using the USecVisLib Python API without icons.

Custom diagrams support:
- User-defined node types with custom shapes and styles
- User-defined edge types with custom styles
- Schema validation
- Clusters/subgraphs
"""

import os
import sys

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import CustomDiagrams


def example_flowchart():
    """Create a simple flowchart diagram."""

    print("=== Custom Flowchart Diagram ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'custom-diagrams', 'general', 'flowchart.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'custom_flowchart'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        cd = CustomDiagrams()
        cd.load(template_path)

        # Validate
        result = cd.validate(raise_on_error=False)
        if result.get('valid', True) and not result.get('errors'):
            print("Validation passed!")
        else:
            print(f"Validation errors: {result.get('errors')}")

        # Get stats
        stats = cd.get_stats()
        print(f"Nodes: {stats.get('total_nodes')}")
        print(f"Edges: {stats.get('total_edges')}")

        # Build the diagram
        result = cd.BuildCustomDiagram(output=output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_network_topology():
    """Create a network topology diagram."""

    print("\n=== Custom Network Topology ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'custom-diagrams', 'network', 'topology.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'custom_network'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        cd = CustomDiagrams()
        cd.load(template_path)

        result = cd.validate(raise_on_error=False)
        if result.get('valid', True):
            print("Validation passed!")
            stats = cd.get_stats()
            print(f"Nodes: {stats.get('total_nodes')}")
            print(f"Edges: {stats.get('total_edges')}")

        result = cd.BuildCustomDiagram(output=output_path, format="png")
        print(f"Output saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")


def example_programmatic():
    """Create a custom diagram programmatically."""

    print("\n=== Programmatic Custom Diagram ===\n")

    import tempfile

    # Define a custom diagram configuration
    config = """
[diagram]
title = "Software Architecture"
description = "Custom software architecture diagram"
layout = "hierarchical"
direction = "TB"
style = "cd_default"
splines = "ortho"
nodesep = 0.8
ranksep = 1.0

# Define node types with custom styles
[schema.nodes.frontend]
shape = "rectangle"
required_fields = ["name"]
optional_fields = ["technology"]
style = { fillcolor = "#3498DB", fontcolor = "white", style = "filled,rounded" }
label_template = "{name}\\n({technology})"

[schema.nodes.backend]
shape = "rectangle"
required_fields = ["name"]
optional_fields = ["language"]
style = { fillcolor = "#27AE60", fontcolor = "white", style = "filled" }
label_template = "{name}\\n[{language}]"

[schema.nodes.database]
shape = "cylinder"
required_fields = ["name"]
optional_fields = ["engine"]
style = { fillcolor = "#9B59B6", fontcolor = "white", style = "filled" }
label_template = "{name}\\n{engine}"

[schema.nodes.queue]
shape = "parallelogram"
required_fields = ["name"]
style = { fillcolor = "#F39C12", fontcolor = "white", style = "filled" }
label_template = "{name}"

[schema.nodes.external]
shape = "ellipse"
required_fields = ["name"]
style = { fillcolor = "#E74C3C", fontcolor = "white", style = "filled" }
label_template = "{name}"

# Define edge types
[schema.edges.http]
style = "solid"
color = "#3498DB"
arrowhead = "normal"
label_field = "protocol"

[schema.edges.async]
style = "dashed"
color = "#F39C12"
arrowhead = "vee"
label_field = "protocol"

[schema.edges.database]
style = "solid"
color = "#9B59B6"
arrowhead = "normal"
label_field = "protocol"

# Nodes
[[nodes]]
id = "web"
type = "frontend"
name = "Web UI"
technology = "React"

[[nodes]]
id = "mobile"
type = "frontend"
name = "Mobile App"
technology = "React Native"

[[nodes]]
id = "api"
type = "backend"
name = "API Server"
language = "Python"

[[nodes]]
id = "worker"
type = "backend"
name = "Worker Service"
language = "Python"

[[nodes]]
id = "postgres"
type = "database"
name = "PostgreSQL"
engine = "PostgreSQL 15"

[[nodes]]
id = "redis"
type = "database"
name = "Redis"
engine = "Redis 7"

[[nodes]]
id = "rabbitmq"
type = "queue"
name = "RabbitMQ"

[[nodes]]
id = "stripe"
type = "external"
name = "Stripe API"

# Edges
[[edges]]
from = "web"
to = "api"
type = "http"
protocol = "REST"

[[edges]]
from = "mobile"
to = "api"
type = "http"
protocol = "REST"

[[edges]]
from = "api"
to = "postgres"
type = "database"
protocol = "SQL"

[[edges]]
from = "api"
to = "redis"
type = "database"
protocol = "Redis"

[[edges]]
from = "api"
to = "rabbitmq"
type = "async"
protocol = "AMQP"

[[edges]]
from = "rabbitmq"
to = "worker"
type = "async"
protocol = "AMQP"

[[edges]]
from = "worker"
to = "postgres"
type = "database"
protocol = "SQL"

[[edges]]
from = "api"
to = "stripe"
type = "http"
protocol = "HTTPS"

# Clusters
[[clusters]]
id = "frontend_cluster"
label = "Frontend Layer"
nodes = ["web", "mobile"]
style = { color = "#3498DB", style = "dashed" }

[[clusters]]
id = "backend_cluster"
label = "Backend Layer"
nodes = ["api", "worker", "rabbitmq"]
style = { color = "#27AE60", style = "dashed" }

[[clusters]]
id = "data_cluster"
label = "Data Layer"
nodes = ["postgres", "redis"]
style = { color = "#9B59B6", style = "dashed" }
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'custom_programmatic')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        cd = CustomDiagrams()
        cd.load(temp_path)

        result = cd.validate(raise_on_error=False)
        if result.get('valid', True):
            print("Validation passed!")
            stats = cd.get_stats()
            print(f"Nodes: {stats.get('total_nodes')}")
            print(f"Edges: {stats.get('total_edges')}")
            print(f"Node types: {stats.get('node_types')}")
            print(f"Edge types: {stats.get('edge_types')}")

        result = cd.BuildCustomDiagram(output=output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def example_all_templates():
    """List and summarize all available custom diagram templates."""

    print("\n=== Available Custom Diagram Templates ===\n")

    import glob

    templates_dir = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'custom-diagrams'
    )

    templates = glob.glob(os.path.join(templates_dir, '**', '*.toml'), recursive=True)

    for template_path in sorted(templates):
        rel_path = os.path.relpath(template_path, templates_dir)

        try:
            cd = CustomDiagrams()
            cd.load(template_path)

            result = cd.validate(raise_on_error=False)
            stats = cd.get_stats()

            status = "VALID" if result.get('valid', True) else "INVALID"

            print(f"{rel_path}:")
            print(f"  Status: {status}")
            print(f"  Nodes: {stats.get('total_nodes')}, Edges: {stats.get('total_edges')}")
            print()

        except Exception as e:
            print(f"{rel_path}: Error - {e}")


if __name__ == "__main__":
    example_flowchart()
    example_network_topology()
    example_programmatic()
    example_all_templates()
