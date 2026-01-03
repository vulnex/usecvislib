#!/usr/bin/env python3
"""
Attack Tree Example - Basic (No Icons)

This example demonstrates how to create an attack tree visualization
using the USecVisLib Python API without icons.

Two approaches are shown:
1. Using the AttackTreeBuilder for programmatic creation
2. Using AttackTrees directly with a template file
"""

import os
import sys

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import AttackTrees
from usecvislib.builders import AttackTreeBuilder


def example_with_builder():
    """Create an attack tree programmatically using the builder pattern."""

    print("=== Attack Tree with Builder (No Icons) ===\n")

    # Create the builder with tree name and root node
    builder = (
        AttackTreeBuilder("Web Application Attack", "Compromise Web App")

        # Add root node (goal)
        .add_node(
            "Compromise Web App",
            style="filled",
            fillcolor="#E74C3C",
            fontcolor="white",
            shape="box"
        )

        # Add intermediate nodes (attack vectors)
        .add_node(
            "Exploit Input Validation",
            style="filled",
            fillcolor="#3498DB",
            fontcolor="white",
            gate="OR"
        )
        .add_node(
            "Exploit Authentication",
            style="filled",
            fillcolor="#3498DB",
            fontcolor="white",
            gate="OR"
        )
        .add_node(
            "Exploit Session Management",
            style="filled",
            fillcolor="#3498DB",
            fontcolor="white",
            gate="OR"
        )

        # Add leaf nodes (specific attacks) with CVSS scores
        .add_node("SQL Injection", style="filled", fillcolor="#F39C12", cvss=9.8)
        .add_node("XSS Attack", style="filled", fillcolor="#F39C12", cvss=6.1)
        .add_node("Command Injection", style="filled", fillcolor="#F39C12", cvss=9.8)
        .add_node("Brute Force", style="filled", fillcolor="#9B59B6", cvss=7.5)
        .add_node("Credential Stuffing", style="filled", fillcolor="#9B59B6", cvss=8.1)
        .add_node("Session Hijacking", style="filled", fillcolor="#27AE60", cvss=7.5)
        .add_node("Session Fixation", style="filled", fillcolor="#27AE60", cvss=6.5)

        # Add edges from root to intermediate nodes
        .add_edge("Compromise Web App", "Exploit Input Validation", label="OR")
        .add_edge("Compromise Web App", "Exploit Authentication", label="OR")
        .add_edge("Compromise Web App", "Exploit Session Management", label="OR")

        # Add edges from intermediate to leaf nodes
        .add_edge("Exploit Input Validation", "SQL Injection", label="HIGH")
        .add_edge("Exploit Input Validation", "XSS Attack", label="MEDIUM")
        .add_edge("Exploit Input Validation", "Command Injection", label="HIGH")
        .add_edge("Exploit Authentication", "Brute Force", label="MEDIUM")
        .add_edge("Exploit Authentication", "Credential Stuffing", label="HIGH")
        .add_edge("Exploit Session Management", "Session Hijacking", label="HIGH")
        .add_edge("Exploit Session Management", "Session Fixation", label="MEDIUM")
    )

    # Get the data as JSON (useful for debugging or saving)
    print("Generated JSON configuration:")
    print(builder.to_json())
    print()

    # Convert to AttackTrees instance and render
    # Note: Requires graphviz to be installed for actual rendering
    try:
        output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_tree_basic_builder')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        attack_tree = builder.to_attack_tree(output_path, format="png")
        attack_tree.load()

        # Validate the tree
        errors = attack_tree.validate()
        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")

        # Get statistics
        stats = attack_tree.get_stats()
        print(f"Tree stats: {stats}")

        # Render (requires graphviz)
        attack_tree.render()
        attack_tree.draw()
        print(f"Output saved to: {output_path}.png")

    except Exception as e:
        print(f"Rendering failed (graphviz may not be installed): {e}")


def example_with_template():
    """Create an attack tree using a template file."""

    print("\n=== Attack Tree with Template File (No Icons) ===\n")

    # Use an existing template without icons
    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'attack-trees', 'insider_threat.tml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'attack_tree_template'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        # Create AttackTrees instance
        at = AttackTrees(
            inputfile=template_path,
            outputfile=output_path,
            format="png",
            styleid="at_default"
        )

        # Load and validate
        at.load()
        errors = at.validate()

        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")

        # Get statistics
        stats = at.get_stats()
        print(f"Tree name: {stats.get('name', 'Unknown')}")
        print(f"Total nodes: {stats.get('total_nodes', 0)}")
        print(f"Total edges: {stats.get('total_edges', 0)}")

        # Render
        at.render()
        at.draw()
        print(f"Output saved to: {output_path}.png")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_fluent_chain():
    """Demonstrate the fluent API with method chaining."""

    print("\n=== Fluent API Chain Example ===\n")

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_tree_fluent')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        # Complete fluent chain
        result = (
            AttackTreeBuilder("Simple Attack", "Goal")
            .add_node("Goal", fillcolor="#E74C3C", fontcolor="white")
            .add_node("Path A", fillcolor="#3498DB", fontcolor="white")
            .add_node("Path B", fillcolor="#3498DB", fontcolor="white")
            .add_edge("Goal", "Path A", label="OR")
            .add_edge("Goal", "Path B", label="OR")
            .to_attack_tree(output_path, format="png")
            .load()
            .render()
            .draw()
        )
        print(f"Fluent chain completed! Output: {output_path}.png")

    except Exception as e:
        print(f"Fluent chain failed: {e}")


if __name__ == "__main__":
    example_with_builder()
    example_with_template()
    example_fluent_chain()
