#!/usr/bin/env python3
"""
Utility Examples

This example demonstrates various utility features of the
USecVisLib Python API including:
- Export to different formats
- Batch processing
- Validation
- Statistics and analysis
- Mermaid diagram generation
"""

import os
import sys
import json

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import AttackTrees, AttackGraphs, ThreatModeling
from usecvislib.builders import AttackTreeBuilder


def example_export_formats():
    """Demonstrate exporting to different output formats."""

    print("=== Export to Different Formats ===\n")

    # Create a simple attack tree
    builder = (
        AttackTreeBuilder("Export Demo", "Goal")
        .add_node("Goal", fillcolor="#E74C3C", fontcolor="white")
        .add_node("Path A", fillcolor="#3498DB", fontcolor="white")
        .add_node("Path B", fillcolor="#3498DB", fontcolor="white")
        .add_edge("Goal", "Path A", label="OR")
        .add_edge("Goal", "Path B", label="OR")
    )

    output_dir = os.path.join(os.path.dirname(__file__), 'output', 'formats')
    os.makedirs(output_dir, exist_ok=True)

    formats = ['png', 'svg', 'pdf', 'dot']

    for fmt in formats:
        output_path = os.path.join(output_dir, f'export_demo')
        try:
            at = builder.to_attack_tree(output_path, format=fmt)
            at.load().render().draw()
            print(f"  {fmt.upper()}: {output_path}.{fmt}")
        except Exception as e:
            print(f"  {fmt.upper()}: Failed - {e}")


def example_validation():
    """Demonstrate validation features."""

    print("\n=== Validation Examples ===\n")

    # Valid tree
    print("Testing valid attack tree...")
    valid_builder = (
        AttackTreeBuilder("Valid Tree", "Root")
        .add_node("Root", fillcolor="#E74C3C")
        .add_node("Child", fillcolor="#3498DB")
        .add_edge("Root", "Child")
    )

    try:
        at = valid_builder.to_attack_tree('/tmp/valid_test', format='png')
        at.load()
        errors = at.validate()
        print(f"  Valid tree errors: {errors if errors else 'None (valid)'}")
    except Exception as e:
        print(f"  Error: {e}")

    # Invalid tree (missing root)
    print("\nTesting invalid attack tree (orphan node)...")
    invalid_data = {
        "tree": {"name": "Invalid", "root": "NonExistent"},
        "nodes": {"Orphan": {"label": "Orphan Node"}},
        "edges": {}
    }

    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(invalid_data, f)
        temp_path = f.name

    try:
        at = AttackTrees(temp_path, '/tmp/invalid_test')
        at.load()
        errors = at.validate()
        print(f"  Invalid tree errors: {errors}")
    except Exception as e:
        print(f"  Expected error caught: {type(e).__name__}")
    finally:
        os.unlink(temp_path)


def example_statistics():
    """Demonstrate getting statistics from visualizations."""

    print("\n=== Statistics Examples ===\n")

    # Attack Tree stats
    print("Attack Tree Statistics:")
    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'attack-trees', 'insider_threat.tml'
    )

    try:
        at = AttackTrees(template_path, '/tmp/stats_test', validate_paths=True)
        at.load()
        stats = at.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
    except Exception as e:
        print(f"  Error: {e}")

    # Attack Graph stats
    print("\nAttack Graph Statistics:")
    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'attack-graphs', 'simple_network.tml'
    )

    try:
        ag = AttackGraphs(template_path, '/tmp/stats_test', validate_paths=True)
        ag.load()
        stats = ag.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
    except Exception as e:
        print(f"  Error: {e}")


def example_mermaid_export():
    """Demonstrate Mermaid diagram generation."""

    print("\n=== Mermaid Export Example ===\n")

    try:
        from usecvislib.mermaid import MermaidExporter

        # Create a simple attack tree
        builder = (
            AttackTreeBuilder("Mermaid Demo", "Compromise System")
            .add_node("Compromise System", fillcolor="#E74C3C")
            .add_node("Network Attack", fillcolor="#3498DB", gate="OR")
            .add_node("Social Engineering", fillcolor="#3498DB", gate="OR")
            .add_node("Exploit CVE", fillcolor="#F39C12", cvss=9.8)
            .add_node("Phishing", fillcolor="#F39C12", cvss=7.5)
            .add_edge("Compromise System", "Network Attack")
            .add_edge("Compromise System", "Social Engineering")
            .add_edge("Network Attack", "Exploit CVE")
            .add_edge("Social Engineering", "Phishing")
        )

        at = builder.to_attack_tree('/tmp/mermaid_test', format='png')
        at.load()

        # Export to Mermaid
        exporter = MermaidExporter()
        mermaid_code = exporter.export_attack_tree(at)

        print("Generated Mermaid code:")
        print("-" * 40)
        print(mermaid_code)
        print("-" * 40)

        # Save to file
        output_path = os.path.join(os.path.dirname(__file__), 'output', 'mermaid_demo.md')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, 'w') as f:
            f.write("# Attack Tree Diagram\n\n")
            f.write("```mermaid\n")
            f.write(mermaid_code)
            f.write("\n```\n")

        print(f"\nSaved to: {output_path}")

    except ImportError:
        print("  MermaidExporter not available")
    except Exception as e:
        print(f"  Error: {e}")


def example_json_export():
    """Demonstrate JSON export for data interchange."""

    print("\n=== JSON Export Example ===\n")

    builder = (
        AttackTreeBuilder("JSON Export Demo", "Goal")
        .add_node("Goal", fillcolor="#E74C3C", fontcolor="white")
        .add_node("Attack 1", fillcolor="#3498DB", cvss=8.5)
        .add_node("Attack 2", fillcolor="#3498DB", cvss=7.0)
        .add_edge("Goal", "Attack 1", label="HIGH")
        .add_edge("Goal", "Attack 2", label="MEDIUM")
    )

    # Export as JSON
    json_data = builder.to_json(pretty=True)
    print("Generated JSON:")
    print(json_data[:500])
    print("...")

    # Save to file
    output_path = os.path.join(os.path.dirname(__file__), 'output', 'export_demo.json')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'w') as f:
        f.write(json_data)

    print(f"\nSaved to: {output_path}")


def example_available_styles():
    """List available styles for each visualization type."""

    print("\n=== Available Styles ===\n")

    # This would normally read from the config files
    styles = {
        "Attack Trees": [
            "at_default", "at_classic", "at_dark", "at_minimal",
            "at_colorful", "at_corporate", "at_security"
        ],
        "Attack Graphs": [
            "ag_default", "ag_network", "ag_dark", "ag_security",
            "ag_minimal", "ag_colorful"
        ],
        "Threat Models": [
            "tm_default", "tm_dfd", "tm_dark", "tm_stride",
            "tm_minimal", "tm_corporate"
        ],
        "Custom Diagrams": [
            "cd_default", "cd_blueprint", "cd_dark", "cd_minimal",
            "cd_colorful", "cd_corporate"
        ]
    }

    for viz_type, style_list in styles.items():
        print(f"{viz_type}:")
        for style in style_list:
            print(f"  - {style}")
        print()


def example_cvss_features():
    """Demonstrate CVSS-related features."""

    print("\n=== CVSS Features ===\n")

    try:
        from usecvislib.cvss import parse_cvss_vector, calculate_cvss_score
        from usecvislib.constants import cvss_to_color, cvss_to_severity_label

        # Parse a CVSS vector
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        print(f"Vector: {vector}")

        parsed = parse_cvss_vector(vector)
        print(f"Parsed components: {parsed}")

        score = calculate_cvss_score(parsed)
        print(f"Calculated score: {score}")

        severity = cvss_to_severity_label(score)
        color = cvss_to_color(score)
        print(f"Severity: {severity}")
        print(f"Color code: {color}")

        # Show severity scale
        print("\nCVSS Severity Scale:")
        test_scores = [0.0, 2.5, 5.0, 7.0, 9.0, 10.0]
        for s in test_scores:
            sev = cvss_to_severity_label(s)
            col = cvss_to_color(s)
            print(f"  {s:.1f}: {sev} ({col})")

    except ImportError as e:
        print(f"  CVSS module not available: {e}")
    except Exception as e:
        print(f"  Error: {e}")


if __name__ == "__main__":
    example_export_formats()
    example_validation()
    example_statistics()
    example_mermaid_export()
    example_json_export()
    example_available_styles()
    example_cvss_features()
