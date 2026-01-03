#!/usr/bin/env python3
"""
Attack Tree Example - With Icons

This example demonstrates how to create an attack tree visualization
using the USecVisLib Python API with bundled icons.

Icons can be referenced using:
- "bundled:aws/Category/IconName" for AWS icons
- "bundled:azure/Category/IconName" for Azure icons
- "bundled:bootstrap/icons/icons/icon-name" for Bootstrap icons
"""

import os
import sys

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import AttackTrees
from usecvislib.builders import AttackTreeBuilder


def example_with_aws_icons():
    """Create an attack tree with AWS bundled icons."""

    print("=== Attack Tree with AWS Icons ===\n")

    builder = (
        AttackTreeBuilder("AWS Cloud Attack", "Compromise AWS Infrastructure")

        # Root node with AWS icon
        .add_node(
            "Compromise AWS Infrastructure",
            shape="none",  # Use shape="none" for icon-only nodes
            image="bundled:aws/Security-Identity-Compliance/Shield"
        )

        # Attack vectors with AWS service icons
        .add_node(
            "Attack IAM",
            shape="none",
            gate="OR",
            image="bundled:aws/Security-Identity-Compliance/Identity-and-Access-Management"
        )
        .add_node(
            "Attack S3",
            shape="none",
            gate="OR",
            image="bundled:aws/Storage/Simple-Storage-Service"
        )
        .add_node(
            "Attack EC2",
            shape="none",
            gate="OR",
            image="bundled:aws/Compute/EC2"
        )

        # Leaf nodes with CVSS scores
        .add_node(
            "Credential Theft",
            shape="none",
            cvss=8.5,
            image="bundled:aws/Security-Identity-Compliance/Secrets-Manager"
        )
        .add_node(
            "Privilege Escalation",
            shape="none",
            cvss=8.8,
            image="bundled:aws/Security-Identity-Compliance/IAM-Identity-Center"
        )
        .add_node(
            "Bucket Misconfiguration",
            shape="none",
            cvss=9.0,
            image="bundled:aws/Storage/Simple-Storage-Service"
        )
        .add_node(
            "Public Bucket Access",
            shape="none",
            cvss=9.1,
            image="bundled:aws/Storage/Simple-Storage-Service"
        )
        .add_node(
            "Instance Metadata Attack",
            shape="none",
            cvss=7.5,
            image="bundled:aws/Compute/EC2"
        )
        .add_node(
            "SSH Key Compromise",
            shape="none",
            cvss=8.0,
            image="bundled:aws/Compute/EC2"
        )

        # Edges
        .add_edge("Compromise AWS Infrastructure", "Attack IAM", label="OR")
        .add_edge("Compromise AWS Infrastructure", "Attack S3", label="OR")
        .add_edge("Compromise AWS Infrastructure", "Attack EC2", label="OR")
        .add_edge("Attack IAM", "Credential Theft", label="HIGH")
        .add_edge("Attack IAM", "Privilege Escalation", label="CRITICAL")
        .add_edge("Attack S3", "Bucket Misconfiguration", label="CRITICAL")
        .add_edge("Attack S3", "Public Bucket Access", label="CRITICAL")
        .add_edge("Attack EC2", "Instance Metadata Attack", label="HIGH")
        .add_edge("Attack EC2", "SSH Key Compromise", label="HIGH")
    )

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_tree_aws_icons')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        at = builder.to_attack_tree(output_path, format="png")
        at.load()

        errors = at.validate()
        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")
            stats = at.get_stats()
            print(f"Nodes: {stats.get('total_nodes')}, Edges: {stats.get('total_edges')}")

        at.render().draw()
        print(f"Output saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")


def example_with_bootstrap_icons():
    """Create an attack tree with Bootstrap bundled icons."""

    print("\n=== Attack Tree with Bootstrap Icons ===\n")

    builder = (
        AttackTreeBuilder("Network Attack", "Compromise Network")

        # Root with warning icon
        .add_node(
            "Compromise Network",
            shape="none",
            image="bundled:bootstrap/icons/icons/exclamation-triangle-fill"
        )

        # Attack categories with Bootstrap icons
        .add_node(
            "Attack Web Layer",
            shape="none",
            gate="OR",
            image="bundled:bootstrap/icons/icons/globe"
        )
        .add_node(
            "Attack Database",
            shape="none",
            gate="OR",
            image="bundled:bootstrap/icons/icons/database"
        )
        .add_node(
            "Attack Users",
            shape="none",
            gate="OR",
            image="bundled:bootstrap/icons/icons/people-fill"
        )

        # Specific attacks
        .add_node(
            "SQL Injection",
            shape="none",
            cvss=9.8,
            image="bundled:bootstrap/icons/icons/code-slash"
        )
        .add_node(
            "XSS",
            shape="none",
            cvss=6.1,
            image="bundled:bootstrap/icons/icons/filetype-html"
        )
        .add_node(
            "Data Exfiltration",
            shape="none",
            cvss=8.5,
            image="bundled:bootstrap/icons/icons/file-earmark-lock"
        )
        .add_node(
            "Phishing",
            shape="none",
            cvss=7.5,
            image="bundled:bootstrap/icons/icons/envelope-exclamation"
        )
        .add_node(
            "Social Engineering",
            shape="none",
            cvss=8.0,
            image="bundled:bootstrap/icons/icons/person-fill-exclamation"
        )

        # Edges
        .add_edge("Compromise Network", "Attack Web Layer", label="OR")
        .add_edge("Compromise Network", "Attack Database", label="OR")
        .add_edge("Compromise Network", "Attack Users", label="OR")
        .add_edge("Attack Web Layer", "SQL Injection", label="HIGH")
        .add_edge("Attack Web Layer", "XSS", label="MEDIUM")
        .add_edge("Attack Database", "Data Exfiltration", label="HIGH")
        .add_edge("Attack Users", "Phishing", label="MEDIUM")
        .add_edge("Attack Users", "Social Engineering", label="HIGH")
    )

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_tree_bootstrap_icons')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        at = builder.to_attack_tree(output_path, format="png")
        at.load()
        at.render().draw()
        print(f"Output saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")


def example_with_template_icons():
    """Use an existing template with icons."""

    print("\n=== Attack Tree from Template with Icons ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'attack-trees', 'aws_cloud_security_icons.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'attack_tree_template_icons'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        at = AttackTrees(
            inputfile=template_path,
            outputfile=output_path,
            format="png",
            styleid="at_default"
        )

        at.load()
        errors = at.validate()

        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")
            stats = at.get_stats()
            print(f"Tree: {stats.get('name')}")
            print(f"Nodes: {stats.get('total_nodes')}, Edges: {stats.get('total_edges')}")

        at.render().draw()
        print(f"Output saved to: {output_path}.png")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def list_available_icons():
    """Show how to list available bundled icons."""

    print("\n=== Available Icon Categories ===\n")

    # Icon paths are organized by provider
    icon_categories = {
        "AWS": [
            "bundled:aws/Compute/EC2",
            "bundled:aws/Compute/Lambda",
            "bundled:aws/Database/RDS",
            "bundled:aws/Database/DynamoDB",
            "bundled:aws/Storage/Simple-Storage-Service",
            "bundled:aws/Security-Identity-Compliance/IAM",
            "bundled:aws/Security-Identity-Compliance/WAF",
            "bundled:aws/Networking-Content-Delivery/VPC",
        ],
        "Azure": [
            "bundled:azure/Compute/Virtual-Machines",
            "bundled:azure/Databases/SQL-Database",
            "bundled:azure/Storage/Storage-Accounts",
        ],
        "Bootstrap": [
            "bundled:bootstrap/icons/icons/shield-fill",
            "bundled:bootstrap/icons/icons/database",
            "bundled:bootstrap/icons/icons/globe",
            "bundled:bootstrap/icons/icons/person-fill",
            "bundled:bootstrap/icons/icons/lock-fill",
            "bundled:bootstrap/icons/icons/exclamation-triangle-fill",
        ]
    }

    for provider, icons in icon_categories.items():
        print(f"{provider} Icons:")
        for icon in icons:
            print(f"  - {icon}")
        print()


if __name__ == "__main__":
    example_with_aws_icons()
    example_with_bootstrap_icons()
    example_with_template_icons()
    list_available_icons()
