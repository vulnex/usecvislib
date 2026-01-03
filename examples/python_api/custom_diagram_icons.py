#!/usr/bin/env python3
"""
Custom Diagram Example - With Icons

This example demonstrates how to create custom diagrams
using the USecVisLib Python API with bundled icons.

Icons can be added to any node type in custom diagrams
using the 'image' attribute.
"""

import os
import sys
import tempfile

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import CustomDiagrams


def example_with_template_icons():
    """Use the deployment-diagram_icons template."""

    print("=== Custom Diagram from Template with Icons ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'custom-diagrams', 'software', 'deployment-diagram_icons.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'custom_deployment_icons'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        cd = CustomDiagrams()
        cd.load(template_path)

        result = cd.validate(raise_on_error=False)
        if result.get('valid', True) and not result.get('errors'):
            print("Validation passed!")
            stats = cd.get_stats()
            print(f"Nodes: {stats.get('total_nodes')}")
            print(f"Edges: {stats.get('total_edges')}")

        result = cd.BuildCustomDiagram(output=output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_aws_architecture():
    """Create an AWS architecture diagram with icons."""

    print("\n=== AWS Architecture Diagram with Icons ===\n")

    config = """
[diagram]
title = "AWS Serverless Architecture"
description = "Serverless architecture with AWS icons"
layout = "hierarchical"
direction = "LR"
style = "cd_default"
splines = "ortho"
nodesep = 1.0
ranksep = 1.2

# Node types
[schema.nodes.user]
shape = "ellipse"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#95A5A6", fontcolor = "white", style = "filled" }

[schema.nodes.gateway]
shape = "rectangle"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#FF9900", fontcolor = "white", style = "filled,rounded" }

[schema.nodes.compute]
shape = "rectangle"
required_fields = ["name"]
optional_fields = ["runtime", "image"]
style = { fillcolor = "#FF9900", fontcolor = "white", style = "filled" }
label_template = "{name}\\n({runtime})"

[schema.nodes.storage]
shape = "cylinder"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#3F8624", fontcolor = "white", style = "filled" }

[schema.nodes.database]
shape = "cylinder"
required_fields = ["name"]
optional_fields = ["engine", "image"]
style = { fillcolor = "#3B48CC", fontcolor = "white", style = "filled" }
label_template = "{name}\\n[{engine}]"

[schema.nodes.cache]
shape = "cylinder"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#C925D1", fontcolor = "white", style = "filled" }

[schema.nodes.queue]
shape = "parallelogram"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#FF4F8B", fontcolor = "white", style = "filled" }

[schema.nodes.notification]
shape = "hexagon"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#FF4F8B", fontcolor = "white", style = "filled" }

# Edge types
[schema.edges.sync]
style = "solid"
color = "#232F3E"
arrowhead = "normal"
label_field = "protocol"

[schema.edges.async]
style = "dashed"
color = "#FF4F8B"
arrowhead = "vee"
label_field = "protocol"

# Nodes with AWS icons
[[nodes]]
id = "users"
type = "user"
name = "Users"
image = "bundled:bootstrap/icons/icons/people-fill"

[[nodes]]
id = "api_gateway"
type = "gateway"
name = "API Gateway"
image = "bundled:aws/App-Integration/API-Gateway"

[[nodes]]
id = "cloudfront"
type = "gateway"
name = "CloudFront"
image = "bundled:aws/Networking-Content-Delivery/CloudFront"

[[nodes]]
id = "lambda_api"
type = "compute"
name = "API Handler"
runtime = "Python 3.11"
image = "bundled:aws/Compute/Lambda"

[[nodes]]
id = "lambda_worker"
type = "compute"
name = "Worker"
runtime = "Python 3.11"
image = "bundled:aws/Compute/Lambda"

[[nodes]]
id = "s3_static"
type = "storage"
name = "Static Assets"
image = "bundled:aws/Storage/Simple-Storage-Service"

[[nodes]]
id = "s3_uploads"
type = "storage"
name = "User Uploads"
image = "bundled:aws/Storage/Simple-Storage-Service"

[[nodes]]
id = "dynamodb"
type = "database"
name = "DynamoDB"
engine = "NoSQL"
image = "bundled:aws/Database/DynamoDB"

[[nodes]]
id = "rds"
type = "database"
name = "RDS"
engine = "PostgreSQL"
image = "bundled:aws/Database/RDS"

[[nodes]]
id = "elasticache"
type = "cache"
name = "ElastiCache"
image = "bundled:aws/Database/ElastiCache"

[[nodes]]
id = "sqs"
type = "queue"
name = "SQS Queue"
image = "bundled:aws/App-Integration/Simple-Queue-Service"

[[nodes]]
id = "sns"
type = "notification"
name = "SNS Topic"
image = "bundled:aws/App-Integration/Simple-Notification-Service"

# Edges
[[edges]]
from = "users"
to = "cloudfront"
type = "sync"
protocol = "HTTPS"

[[edges]]
from = "cloudfront"
to = "s3_static"
type = "sync"
protocol = "S3"

[[edges]]
from = "cloudfront"
to = "api_gateway"
type = "sync"
protocol = "HTTPS"

[[edges]]
from = "api_gateway"
to = "lambda_api"
type = "sync"
protocol = "Invoke"

[[edges]]
from = "lambda_api"
to = "dynamodb"
type = "sync"
protocol = "SDK"

[[edges]]
from = "lambda_api"
to = "rds"
type = "sync"
protocol = "SQL"

[[edges]]
from = "lambda_api"
to = "elasticache"
type = "sync"
protocol = "Redis"

[[edges]]
from = "lambda_api"
to = "s3_uploads"
type = "sync"
protocol = "S3"

[[edges]]
from = "lambda_api"
to = "sqs"
type = "async"
protocol = "SQS"

[[edges]]
from = "sqs"
to = "lambda_worker"
type = "async"
protocol = "Trigger"

[[edges]]
from = "lambda_worker"
to = "dynamodb"
type = "sync"
protocol = "SDK"

[[edges]]
from = "lambda_worker"
to = "sns"
type = "async"
protocol = "Publish"

# Clusters
[[clusters]]
id = "edge"
label = "Edge / CDN"
nodes = ["cloudfront", "s3_static"]
style = { color = "#FF9900", style = "dashed" }

[[clusters]]
id = "api"
label = "API Layer"
nodes = ["api_gateway", "lambda_api"]
style = { color = "#FF9900", style = "dashed" }

[[clusters]]
id = "data"
label = "Data Layer"
nodes = ["dynamodb", "rds", "elasticache", "s3_uploads"]
style = { color = "#3B48CC", style = "dashed" }

[[clusters]]
id = "async"
label = "Async Processing"
nodes = ["sqs", "lambda_worker", "sns"]
style = { color = "#FF4F8B", style = "dashed" }
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'custom_aws_arch_icons')
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

        result = cd.BuildCustomDiagram(output=output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def example_security_diagram():
    """Create a security architecture diagram with icons."""

    print("\n=== Security Architecture with Icons ===\n")

    config = """
[diagram]
title = "Zero Trust Architecture"
description = "Zero trust security architecture"
layout = "hierarchical"
direction = "TB"
style = "cd_default"
splines = "ortho"
nodesep = 0.8
ranksep = 1.0

[schema.nodes.user]
shape = "ellipse"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#3498DB", fontcolor = "white", style = "filled" }

[schema.nodes.security]
shape = "hexagon"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#E74C3C", fontcolor = "white", style = "filled" }

[schema.nodes.service]
shape = "rectangle"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#27AE60", fontcolor = "white", style = "filled,rounded" }

[schema.nodes.data]
shape = "cylinder"
required_fields = ["name"]
optional_fields = ["image"]
style = { fillcolor = "#9B59B6", fontcolor = "white", style = "filled" }

[schema.edges.secured]
style = "solid"
color = "#27AE60"
arrowhead = "normal"

[schema.edges.verified]
style = "dashed"
color = "#3498DB"
arrowhead = "vee"

# Users
[[nodes]]
id = "employee"
type = "user"
name = "Employee"
image = "bundled:bootstrap/icons/icons/person-badge"

[[nodes]]
id = "contractor"
type = "user"
name = "Contractor"
image = "bundled:bootstrap/icons/icons/person"

# Security controls
[[nodes]]
id = "idp"
type = "security"
name = "Identity Provider"
image = "bundled:bootstrap/icons/icons/key"

[[nodes]]
id = "mfa"
type = "security"
name = "MFA"
image = "bundled:bootstrap/icons/icons/shield-lock"

[[nodes]]
id = "waf"
type = "security"
name = "WAF"
image = "bundled:bootstrap/icons/icons/shield-check"

[[nodes]]
id = "siem"
type = "security"
name = "SIEM"
image = "bundled:bootstrap/icons/icons/eye"

# Services
[[nodes]]
id = "app"
type = "service"
name = "Application"
image = "bundled:bootstrap/icons/icons/window"

[[nodes]]
id = "api"
type = "service"
name = "API"
image = "bundled:bootstrap/icons/icons/gear"

# Data
[[nodes]]
id = "secrets"
type = "data"
name = "Secrets"
image = "bundled:bootstrap/icons/icons/lock-fill"

[[nodes]]
id = "database"
type = "data"
name = "Database"
image = "bundled:bootstrap/icons/icons/database"

# Security flow
[[edges]]
from = "employee"
to = "idp"
type = "verified"

[[edges]]
from = "contractor"
to = "idp"
type = "verified"

[[edges]]
from = "idp"
to = "mfa"
type = "secured"

[[edges]]
from = "mfa"
to = "waf"
type = "secured"

[[edges]]
from = "waf"
to = "app"
type = "secured"

[[edges]]
from = "app"
to = "api"
type = "secured"

[[edges]]
from = "api"
to = "secrets"
type = "secured"

[[edges]]
from = "api"
to = "database"
type = "secured"

[[edges]]
from = "siem"
to = "waf"
type = "verified"

[[edges]]
from = "siem"
to = "idp"
type = "verified"

# Clusters
[[clusters]]
id = "identity"
label = "Identity & Access"
nodes = ["idp", "mfa"]
style = { color = "#E74C3C", style = "dashed" }

[[clusters]]
id = "perimeter"
label = "Perimeter Security"
nodes = ["waf", "siem"]
style = { color = "#F39C12", style = "dashed" }

[[clusters]]
id = "application"
label = "Application Layer"
nodes = ["app", "api"]
style = { color = "#27AE60", style = "dashed" }

[[clusters]]
id = "data_layer"
label = "Data Layer"
nodes = ["secrets", "database"]
style = { color = "#9B59B6", style = "dashed" }
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'custom_security_icons')
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

        result = cd.BuildCustomDiagram(output=output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


if __name__ == "__main__":
    example_with_template_icons()
    example_aws_architecture()
    example_security_diagram()
