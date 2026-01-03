#!/usr/bin/env python3
"""
Attack Graph Example - With Icons

This example demonstrates how to create an attack graph visualization
using the USecVisLib Python API with bundled icons.

Hosts in attack graphs can have icons to represent different
infrastructure components (servers, firewalls, databases, etc.)
"""

import os
import sys

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import AttackGraphs
from usecvislib.builders import AttackGraphBuilder


def example_with_aws_icons():
    """Create an attack graph with AWS infrastructure icons."""

    print("=== Attack Graph with AWS Icons ===\n")

    builder = (
        AttackGraphBuilder("AWS Infrastructure Attack", "Cloud attack simulation")

        # Add hosts with AWS icons
        .add_host(
            "attacker",
            "External Attacker",
            zone="external",
            image="bundled:bootstrap/icons/icons/person-fill-exclamation"
        )
        .add_host(
            "waf",
            "AWS WAF",
            ip="10.0.0.1",
            zone="edge",
            image="bundled:aws/Security-Identity-Compliance/WAF"
        )
        .add_host(
            "alb",
            "Application Load Balancer",
            ip="10.0.1.1",
            zone="dmz",
            image="bundled:aws/Networking-Content-Delivery/Elastic-Load-Balancing"
        )
        .add_host(
            "ec2_web",
            "EC2 Web Server",
            ip="10.0.2.10",
            zone="web",
            os="Amazon Linux 2",
            image="bundled:aws/Compute/EC2"
        )
        .add_host(
            "lambda_api",
            "Lambda API",
            zone="api",
            image="bundled:aws/Compute/Lambda"
        )
        .add_host(
            "rds",
            "RDS PostgreSQL",
            ip="10.0.4.10",
            zone="data",
            os="PostgreSQL 15",
            image="bundled:aws/Database/RDS"
        )
        .add_host(
            "secrets",
            "Secrets Manager",
            zone="secure",
            image="bundled:aws/Security-Identity-Compliance/Secrets-Manager"
        )

        # Add vulnerabilities with CVSS vectors
        .add_vulnerability(
            "vuln_waf_bypass",
            "WAF Rule Bypass",
            cvss=5.3,
            affected_host="waf"
        )
        .add_vulnerability(
            "vuln_ssrf",
            "SSRF Vulnerability",
            cvss=9.1,
            affected_host="ec2_web",
            cve="CVE-2024-1111"
        )
        .add_vulnerability(
            "vuln_rce",
            "Lambda RCE",
            cvss=9.8,
            affected_host="lambda_api",
            cve="CVE-2024-2222"
        )
        .add_vulnerability(
            "vuln_sqli",
            "SQL Injection",
            cvss=8.6,
            affected_host="rds"
        )
        .add_vulnerability(
            "vuln_iam",
            "IAM Misconfiguration",
            cvss=8.1,
            affected_host="secrets"
        )

        # Add services
        .add_service("svc_https", "HTTPS", host="waf", port=443)
        .add_service("svc_http", "HTTP", host="ec2_web", port=80)
        .add_service("svc_api", "API Gateway", host="lambda_api", port=443)
        .add_service("svc_postgres", "PostgreSQL", host="rds", port=5432)

        # Add privileges
        .add_privilege("priv_waf_bypass", "WAF Bypass", host="waf", level="bypass")
        .add_privilege("priv_web_shell", "Web Shell", host="ec2_web", level="user")
        .add_privilege("priv_lambda_exec", "Lambda Execution", host="lambda_api", level="function")
        .add_privilege("priv_db_read", "DB Read", host="rds", level="read")
        .add_privilege("priv_secrets_read", "Secrets Read", host="secrets", level="read")

        # Add exploits
        .add_exploit("exp_waf", "WAF Bypass", vulnerability="vuln_waf_bypass",
                     precondition="attacker", postcondition="priv_waf_bypass")
        .add_exploit("exp_ssrf", "SSRF Attack", vulnerability="vuln_ssrf",
                     precondition="priv_waf_bypass", postcondition="priv_web_shell")
        .add_exploit("exp_rce", "Lambda RCE", vulnerability="vuln_rce",
                     precondition="priv_web_shell", postcondition="priv_lambda_exec")
        .add_exploit("exp_sqli", "SQL Injection", vulnerability="vuln_sqli",
                     precondition="priv_lambda_exec", postcondition="priv_db_read")
        .add_exploit("exp_iam", "IAM Abuse", vulnerability="vuln_iam",
                     precondition="priv_lambda_exec", postcondition="priv_secrets_read")

        # Add network edges
        .add_network_edge("attacker", "waf", label="Internet")
        .add_network_edge("waf", "alb", label="HTTPS")
        .add_network_edge("alb", "ec2_web", label="HTTP")
        .add_network_edge("ec2_web", "lambda_api", label="API Call")
        .add_network_edge("lambda_api", "rds", label="SQL")
        .add_network_edge("lambda_api", "secrets", label="Secrets API")
    )

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_graph_aws_icons')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        ag = builder.to_attack_graph(output_path, format="png")
        ag.load()

        errors = ag.validate()
        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")
            stats = ag.get_stats()
            print(f"Hosts: {stats.get('total_hosts')}")
            print(f"Vulnerabilities: {stats.get('total_vulnerabilities')}")
            print(f"Critical vulns (CVSS >= 9.0): {stats.get('critical_vulnerabilities')}")

        ag.render().draw()
        print(f"\nOutput saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")


def example_with_template_icons():
    """Use the cloud_icons template."""

    print("\n=== Attack Graph from Template with Icons ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'attack-graphs', 'cloud_icons.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'attack_graph_template_icons'
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
            print(f"Average CVSS: {stats.get('average_cvss')}")

        ag.render().draw()
        print(f"Output saved to: {output_path}.png")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_mixed_icons():
    """Mix different icon providers in one graph."""

    print("\n=== Attack Graph with Mixed Icons ===\n")

    builder = (
        AttackGraphBuilder("Hybrid Cloud Attack", "Multi-cloud attack simulation")

        # External attacker with Bootstrap icon
        .add_host(
            "attacker",
            "Attacker",
            zone="external",
            image="bundled:bootstrap/icons/icons/incognito"
        )

        # AWS components
        .add_host(
            "aws_gateway",
            "AWS API Gateway",
            zone="aws",
            image="bundled:aws/App-Integration/API-Gateway"
        )
        .add_host(
            "aws_lambda",
            "AWS Lambda",
            zone="aws",
            image="bundled:aws/Compute/Lambda"
        )

        # Azure components (using bootstrap as placeholder)
        .add_host(
            "azure_app",
            "Azure App Service",
            zone="azure",
            image="bundled:bootstrap/icons/icons/cloud"
        )
        .add_host(
            "azure_db",
            "Azure SQL",
            zone="azure",
            image="bundled:bootstrap/icons/icons/database-fill"
        )

        # Shared resources
        .add_host(
            "shared_secrets",
            "HashiCorp Vault",
            zone="shared",
            image="bundled:bootstrap/icons/icons/key-fill"
        )

        .add_vulnerability("v1", "API Vuln", cvss=7.5, affected_host="aws_gateway")
        .add_vulnerability("v2", "Lambda Vuln", cvss=8.5, affected_host="aws_lambda")
        .add_vulnerability("v3", "App Vuln", cvss=9.0, affected_host="azure_app")

        .add_privilege("p1", "API Access", host="aws_gateway", level="user")
        .add_privilege("p2", "Lambda Exec", host="aws_lambda", level="function")
        .add_privilege("p3", "App Access", host="azure_app", level="user")

        .add_exploit("e1", "Exp 1", vulnerability="v1", precondition="attacker", postcondition="p1")
        .add_exploit("e2", "Exp 2", vulnerability="v2", precondition="p1", postcondition="p2")
        .add_exploit("e3", "Exp 3", vulnerability="v3", precondition="p2", postcondition="p3")

        .add_network_edge("attacker", "aws_gateway", label="HTTPS")
        .add_network_edge("aws_gateway", "aws_lambda")
        .add_network_edge("aws_lambda", "azure_app", label="Cross-cloud")
        .add_network_edge("azure_app", "azure_db")
        .add_network_edge("aws_lambda", "shared_secrets")
        .add_network_edge("azure_app", "shared_secrets")
    )

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'attack_graph_mixed_icons')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        ag = builder.to_attack_graph(output_path, format="png")
        ag.load()
        ag.render().draw()
        print(f"Output saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    example_with_aws_icons()
    example_with_template_icons()
    example_mixed_icons()
