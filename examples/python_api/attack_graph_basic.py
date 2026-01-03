#!/usr/bin/env python3
"""
Attack Graph Example - Basic (No Icons)

This example demonstrates how to create an attack graph visualization
using the USecVisLib Python API without icons.

Attack graphs model network attack paths including:
- Hosts (network machines)
- Vulnerabilities (with CVSS scores)
- Privileges (access levels)
- Services (ports/protocols)
- Exploits (how vulnerabilities lead to privileges)
- Network edges (connectivity)
"""

import os
import sys

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import AttackGraphs
from usecvislib.builders import AttackGraphBuilder


def example_with_builder():
    """Create an attack graph programmatically using the builder pattern."""

    print("=== Attack Graph with Builder (No Icons) ===\n")

    builder = (
        AttackGraphBuilder("Corporate Network Attack", "Network attack simulation")

        # Add hosts
        .add_host("attacker", "External Attacker", zone="external")
        .add_host("firewall", "Perimeter Firewall", ip="10.0.0.1", zone="dmz")
        .add_host("webserver", "Web Server", ip="10.0.1.10", zone="dmz", os="Ubuntu 22.04")
        .add_host("appserver", "Application Server", ip="10.0.2.10", zone="internal", os="CentOS 8")
        .add_host("database", "Database Server", ip="10.0.3.10", zone="secure", os="RHEL 8")

        # Add vulnerabilities with CVSS scores
        .add_vulnerability(
            "vuln_web_rce",
            "Remote Code Execution",
            cvss=9.8,
            affected_host="webserver",
            cve="CVE-2024-1234"
        )
        .add_vulnerability(
            "vuln_app_sqli",
            "SQL Injection",
            cvss=8.6,
            affected_host="appserver",
            cve="CVE-2024-5678"
        )
        .add_vulnerability(
            "vuln_db_priv_esc",
            "Privilege Escalation",
            cvss=7.8,
            affected_host="database"
        )

        # Add services
        .add_service("svc_http", "HTTP", host="webserver", port=80)
        .add_service("svc_https", "HTTPS", host="webserver", port=443)
        .add_service("svc_api", "REST API", host="appserver", port=8080)
        .add_service("svc_postgres", "PostgreSQL", host="database", port=5432)

        # Add privileges
        .add_privilege("priv_web_user", "Web User Shell", host="webserver", level="user")
        .add_privilege("priv_web_root", "Web Root Access", host="webserver", level="root")
        .add_privilege("priv_app_user", "App User Access", host="appserver", level="user")
        .add_privilege("priv_db_read", "DB Read Access", host="database", level="read")
        .add_privilege("priv_db_admin", "DB Admin Access", host="database", level="admin")

        # Add exploits (vulnerability -> privilege)
        .add_exploit(
            "exploit_rce",
            "Exploit RCE",
            vulnerability="vuln_web_rce",
            precondition="attacker",
            postcondition="priv_web_user"
        )
        .add_exploit(
            "exploit_priv_esc_web",
            "Local Privilege Escalation",
            vulnerability="vuln_web_rce",
            precondition="priv_web_user",
            postcondition="priv_web_root"
        )
        .add_exploit(
            "exploit_sqli",
            "SQL Injection Attack",
            vulnerability="vuln_app_sqli",
            precondition="priv_web_root",
            postcondition="priv_app_user"
        )
        .add_exploit(
            "exploit_db_access",
            "Database Access via App",
            vulnerability="vuln_app_sqli",
            precondition="priv_app_user",
            postcondition="priv_db_read"
        )
        .add_exploit(
            "exploit_db_priv_esc",
            "Database Privilege Escalation",
            vulnerability="vuln_db_priv_esc",
            precondition="priv_db_read",
            postcondition="priv_db_admin"
        )

        # Add network edges (connectivity)
        .add_network_edge("attacker", "firewall", label="Internet")
        .add_network_edge("firewall", "webserver", label="HTTP/HTTPS")
        .add_network_edge("webserver", "appserver", label="Internal API")
        .add_network_edge("appserver", "database", label="PostgreSQL")
    )

    # Display JSON configuration
    print("Generated configuration:")
    print(builder.to_json()[:500] + "...\n")

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_graph_basic')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        ag = builder.to_attack_graph(output_path, format="png")
        ag.load()

        # Validate
        errors = ag.validate()
        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")

        # Get statistics
        stats = ag.get_stats()
        print(f"Graph: {stats.get('name')}")
        print(f"Hosts: {stats.get('total_hosts')}")
        print(f"Vulnerabilities: {stats.get('total_vulnerabilities')}")
        print(f"Exploits: {stats.get('total_exploits')}")
        print(f"Average CVSS: {stats.get('average_cvss')}")

        # Render
        ag.render().draw()
        print(f"\nOutput saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")


def example_with_template():
    """Use an existing template file."""

    print("\n=== Attack Graph from Template (No Icons) ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'attack-graphs', 'simple_network.tml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'attack_graph_template'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        ag = AttackGraphs(
            inputfile=template_path,
            outputfile=output_path,
            format="png",
            styleid="ag_default"
        )

        ag.load()
        errors = ag.validate()

        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")
            stats = ag.get_stats()
            print(f"Graph: {stats.get('name')}")
            print(f"Hosts: {stats.get('total_hosts')}")
            print(f"Vulnerabilities: {stats.get('total_vulnerabilities')}")

        ag.render().draw()
        print(f"Output saved to: {output_path}.png")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_path_analysis():
    """Demonstrate attack path analysis capabilities."""

    print("\n=== Attack Path Analysis ===\n")

    builder = (
        AttackGraphBuilder("Path Analysis Demo", "Demo for path finding")
        .add_host("start", "Entry Point", zone="external")
        .add_host("h1", "Host 1", zone="dmz")
        .add_host("h2", "Host 2", zone="dmz")
        .add_host("h3", "Host 3", zone="internal")
        .add_host("target", "Target Server", zone="secure")

        .add_vulnerability("v1", "Vuln 1", cvss=7.0, affected_host="h1")
        .add_vulnerability("v2", "Vuln 2", cvss=8.0, affected_host="h2")
        .add_vulnerability("v3", "Vuln 3", cvss=9.0, affected_host="h3")

        .add_privilege("p1", "Access H1", host="h1", level="user")
        .add_privilege("p2", "Access H2", host="h2", level="user")
        .add_privilege("p3", "Access H3", host="h3", level="user")
        .add_privilege("p_target", "Target Access", host="target", level="admin")

        .add_exploit("e1", "Exploit 1", vulnerability="v1", precondition="start", postcondition="p1")
        .add_exploit("e2", "Exploit 2", vulnerability="v2", precondition="p1", postcondition="p2")
        .add_exploit("e3", "Exploit 3", vulnerability="v3", precondition="p2", postcondition="p3")
        .add_exploit("e4", "Final Exploit", vulnerability="v3", precondition="p3", postcondition="p_target")

        .add_network_edge("start", "h1")
        .add_network_edge("h1", "h2")
        .add_network_edge("h2", "h3")
        .add_network_edge("h3", "target")
    )

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_graph_paths')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        ag = builder.to_attack_graph(output_path, format="png")
        ag.load()

        # Find attack paths
        print("Finding attack paths from 'start' to 'p_target'...")
        paths = ag.find_attack_paths("start", "p_target", max_paths=5)
        print(f"Found {len(paths)} paths:")
        for i, path in enumerate(paths, 1):
            print(f"  Path {i}: {' -> '.join(path)}")

        # Find shortest path
        shortest = ag.shortest_path("start", "p_target")
        if shortest:
            print(f"\nShortest path: {' -> '.join(shortest)}")

        # Analyze critical nodes
        print("\nCritical nodes (by connectivity):")
        critical = ag.analyze_critical_nodes(top_n=5)
        for node in critical:
            print(f"  {node['id']}: degree={node['total_degree']}")

        ag.render().draw()
        print(f"\nOutput saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    example_with_builder()
    example_with_template()
    example_path_analysis()
