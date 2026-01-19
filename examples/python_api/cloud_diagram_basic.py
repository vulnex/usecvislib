#!/usr/bin/env python3
"""
Cloud Diagram Examples

This example demonstrates how to create cloud architecture diagrams
using the USecVisLib Python API.

Cloud diagrams support:
- AWS, Azure, GCP, Kubernetes icons
- Node clusters for grouping components
- Edge labels for connections
- Python code generation

Requirements:
- diagrams library must be installed: pip install diagrams
- Graphviz must be installed
"""

import os
import sys
import tempfile

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import CloudDiagrams


def example_aws_web_app():
    """Create an AWS web application architecture diagram."""

    print("=== AWS Web Application Architecture ===\n")

    config = """
[diagram]
title = "AWS Web Application"
direction = "LR"
outformat = "png"

[[nodes]]
id = "users"
icon = "aws.general.Users"
label = "Users"

[[clusters]]
id = "vpc"
label = "VPC"

    [[clusters.nodes]]
    id = "alb"
    icon = "aws.network.ElasticLoadBalancing"
    label = "Application Load Balancer"

    [[clusters.nodes]]
    id = "ec2_1"
    icon = "aws.compute.EC2"
    label = "Web Server 1"

    [[clusters.nodes]]
    id = "ec2_2"
    icon = "aws.compute.EC2"
    label = "Web Server 2"

[[nodes]]
id = "rds"
icon = "aws.database.RDS"
label = "PostgreSQL RDS"

[[nodes]]
id = "s3"
icon = "aws.storage.S3"
label = "Static Assets"

[[nodes]]
id = "cloudfront"
icon = "aws.network.CloudFront"
label = "CloudFront CDN"

[[edges]]
from = "users"
to = "cloudfront"

[[edges]]
from = "cloudfront"
to = "s3"

[[edges]]
from = "cloudfront"
to = "alb"

[[edges]]
from = "alb"
to = "ec2_1"

[[edges]]
from = "alb"
to = "ec2_2"

[[edges]]
from = "ec2_1"
to = "rds"
label = "SQL"

[[edges]]
from = "ec2_2"
to = "rds"
label = "SQL"
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'cloud_aws_webapp'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    try:
        cd = CloudDiagrams()
        cd.load(temp_path)

        print(f"Title: {cd.config.title}")
        print(f"Direction: {cd.config.direction}")
        print(f"Nodes: {len(cd.nodes)}")
        print(f"Clusters: {len(cd.clusters)}")
        print(f"Edges: {len(cd.edges)}")

        result = cd.render(output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")
        print("Note: 'diagrams' library must be installed (pip install diagrams)")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def example_kubernetes_deployment():
    """Create a Kubernetes deployment architecture diagram."""

    print("\n=== Kubernetes Deployment Architecture ===\n")

    config = """
[diagram]
title = "Kubernetes Microservices"
direction = "TB"
outformat = "png"

[[clusters]]
id = "k8s_cluster"
label = "Kubernetes Cluster"

    [[clusters.clusters]]
    id = "frontend_ns"
    label = "Frontend Namespace"

        [[clusters.clusters.nodes]]
        id = "ingress"
        icon = "k8s.network.Ingress"
        label = "Ingress"

        [[clusters.clusters.nodes]]
        id = "frontend_svc"
        icon = "k8s.network.Service"
        label = "Frontend Service"

        [[clusters.clusters.nodes]]
        id = "frontend_deploy"
        icon = "k8s.compute.Deployment"
        label = "Frontend Pods"

    [[clusters.clusters]]
    id = "backend_ns"
    label = "Backend Namespace"

        [[clusters.clusters.nodes]]
        id = "api_svc"
        icon = "k8s.network.Service"
        label = "API Service"

        [[clusters.clusters.nodes]]
        id = "api_deploy"
        icon = "k8s.compute.Deployment"
        label = "API Pods"

        [[clusters.clusters.nodes]]
        id = "configmap"
        icon = "k8s.storage.ConfigMap"
        label = "ConfigMap"

        [[clusters.clusters.nodes]]
        id = "secret"
        icon = "k8s.storage.Secret"
        label = "Secrets"

[[nodes]]
id = "users"
icon = "generic.network.Switch"
label = "External Traffic"

[[nodes]]
id = "db"
icon = "generic.database.SQL"
label = "Database"

[[edges]]
from = "users"
to = "ingress"

[[edges]]
from = "ingress"
to = "frontend_svc"

[[edges]]
from = "frontend_svc"
to = "frontend_deploy"

[[edges]]
from = "frontend_deploy"
to = "api_svc"

[[edges]]
from = "api_svc"
to = "api_deploy"

[[edges]]
from = "api_deploy"
to = "configmap"

[[edges]]
from = "api_deploy"
to = "secret"

[[edges]]
from = "api_deploy"
to = "db"
label = "PostgreSQL"
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'cloud_k8s_deployment'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    try:
        cd = CloudDiagrams()
        cd.load(temp_path)

        print(f"Title: {cd.config.title}")
        print(f"Nodes: {len(cd.nodes)}")
        print(f"Clusters: {len(cd.clusters)}")
        print(f"Edges: {len(cd.edges)}")

        result = cd.render(output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def example_from_template():
    """Load a cloud diagram from a template file."""

    print("\n=== Cloud Diagram from Template ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'cloud', 'security', 'zero-trust-architecture.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'cloud_zero_trust'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        cd = CloudDiagrams()
        cd.load(template_path)

        print(f"Title: {cd.config.title}")
        print(f"Direction: {cd.config.direction}")
        print(f"Nodes: {len(cd.nodes)}")
        print(f"Clusters: {len(cd.clusters)}")
        print(f"Edges: {len(cd.edges)}")

        result = cd.render(output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_multi_cloud():
    """Create a multi-cloud architecture diagram."""

    print("\n=== Multi-Cloud Architecture ===\n")

    config = """
[diagram]
title = "Multi-Cloud Data Pipeline"
direction = "LR"
outformat = "png"

[[clusters]]
id = "aws_region"
label = "AWS us-east-1"

    [[clusters.nodes]]
    id = "kinesis"
    icon = "aws.analytics.Kinesis"
    label = "Kinesis Stream"

    [[clusters.nodes]]
    id = "lambda"
    icon = "aws.compute.Lambda"
    label = "Lambda Transform"

    [[clusters.nodes]]
    id = "s3_raw"
    icon = "aws.storage.S3"
    label = "S3 Raw Data"

[[clusters]]
id = "gcp_region"
label = "GCP us-central1"

    [[clusters.nodes]]
    id = "pubsub"
    icon = "gcp.analytics.PubSub"
    label = "Pub/Sub"

    [[clusters.nodes]]
    id = "dataflow"
    icon = "gcp.analytics.Dataflow"
    label = "Dataflow"

    [[clusters.nodes]]
    id = "bigquery"
    icon = "gcp.analytics.BigQuery"
    label = "BigQuery"

[[nodes]]
id = "sources"
icon = "generic.network.Switch"
label = "Data Sources"

[[nodes]]
id = "dashboard"
icon = "saas.analytics.Snowflake"
label = "Analytics Dashboard"

[[edges]]
from = "sources"
to = "kinesis"

[[edges]]
from = "kinesis"
to = "lambda"

[[edges]]
from = "lambda"
to = "s3_raw"

[[edges]]
from = "lambda"
to = "pubsub"
label = "Cross-Cloud"

[[edges]]
from = "pubsub"
to = "dataflow"

[[edges]]
from = "dataflow"
to = "bigquery"

[[edges]]
from = "bigquery"
to = "dashboard"
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'cloud_multi_cloud'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    try:
        cd = CloudDiagrams()
        cd.load(temp_path)

        print(f"Title: {cd.config.title}")
        print(f"Nodes: {len(cd.nodes)}")
        print(f"Clusters: {len(cd.clusters)}")
        print(f"Edges: {len(cd.edges)}")

        result = cd.render(output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def example_generate_python_code():
    """Generate Python code from a cloud diagram configuration."""

    print("\n=== Generate Python Code ===\n")

    config = """
[diagram]
title = "Simple AWS Architecture"
direction = "LR"

[[nodes]]
id = "user"
icon = "aws.general.User"
label = "User"

[[nodes]]
id = "api"
icon = "aws.compute.Lambda"
label = "API Lambda"

[[nodes]]
id = "db"
icon = "aws.database.DynamoDB"
label = "DynamoDB"

[[edges]]
from = "user"
to = "api"

[[edges]]
from = "api"
to = "db"
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    try:
        cd = CloudDiagrams()
        cd.load(temp_path)

        # Generate Python code
        python_code = cd.to_python_code()

        print("Generated Python code:")
        print("-" * 40)
        print(python_code[:500] + "..." if len(python_code) > 500 else python_code)
        print("-" * 40)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def example_search_icons():
    """Search for available cloud icons."""

    print("\n=== Search Cloud Icons ===\n")

    try:
        # Search for database icons
        print("Database icons:")
        icons = CloudDiagrams.search_icons("database")
        for icon in icons[:10]:
            print(f"  {icon}")

        print("\nCompute icons:")
        icons = CloudDiagrams.search_icons("compute")
        for icon in icons[:10]:
            print(f"  {icon}")

        print("\nSecurity icons:")
        icons = CloudDiagrams.search_icons("security")
        for icon in icons[:10]:
            print(f"  {icon}")

    except Exception as e:
        print(f"Error: {e}")


def example_list_providers():
    """List supported cloud providers."""

    print("\n=== Supported Cloud Providers ===\n")

    providers = CloudDiagrams.PROVIDERS

    for provider_id, provider_name in providers.items():
        print(f"  {provider_id}: {provider_name}")


def example_list_templates():
    """List all available cloud diagram templates."""

    print("\n=== Available Cloud Templates ===\n")

    import glob

    templates_dir = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'cloud'
    )

    templates = glob.glob(os.path.join(templates_dir, '**', '*.toml'), recursive=True)

    for template_path in sorted(templates):
        rel_path = os.path.relpath(template_path, templates_dir)

        try:
            cd = CloudDiagrams()
            cd.load(template_path)

            print(f"{rel_path}:")
            print(f"  Title: {cd.config.title}")
            print(f"  Direction: {cd.config.direction}")
            print(f"  Nodes: {len(cd.nodes)}, Clusters: {len(cd.clusters)}, Edges: {len(cd.edges)}")
            print()

        except Exception as e:
            print(f"{rel_path}: Error - {e}")


if __name__ == "__main__":
    example_aws_web_app()
    example_kubernetes_deployment()
    example_from_template()
    example_multi_cloud()
    example_generate_python_code()
    example_search_icons()
    example_list_providers()
    example_list_templates()
