#!/usr/bin/env python3
"""
Threat Model Example - With Icons

This example demonstrates how to create a STRIDE threat model
using the USecVisLib Python API with bundled icons.

Icons can be added to:
- External entities
- Processes
- Data stores
"""

import os
import sys
import tempfile

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import ThreatModeling


def example_with_template_icons():
    """Use the web_app_icons template."""

    print("=== Threat Model from Template with Icons ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'threat-models', 'web_app_icons.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'threat_model_template_icons'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        tm = ThreatModeling(
            inputfile=template_path,
            outputfile=output_path,
            format="png",
            styleid="tm_default"
        )

        tm.load()
        errors = tm.validate()

        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")
            stats = tm.get_stats()
            print(f"Model: {stats.get('name')}")
            print(f"Externals: {stats.get('externals', 0)}")
            print(f"Processes: {stats.get('processes', 0)}")
            print(f"Data Stores: {stats.get('datastores', 0)}")

        tm.render().draw()
        print(f"\nOutput saved to: {output_path}.png")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_aws_architecture_icons():
    """Create a threat model with AWS architecture icons."""

    print("\n=== Threat Model with AWS Icons ===\n")

    config = """
[model]
name = "AWS Microservices Threat Model"
description = "Threat model for AWS-based microservices architecture"
engineversion = "0.3.1"
version = "1.0.0"
type = "Threat Model"
date = "2025-01-01"
author = "Security Team"

[externals]

[externals.user]
label = "End User"
description = "Application user"
isTrusted = false
image = "bundled:bootstrap/icons/icons/person-fill"

[externals.attacker]
label = "Threat Actor"
description = "Potential attacker"
isTrusted = false
image = "bundled:bootstrap/icons/icons/person-fill-exclamation"

[externals.third_party]
label = "Third Party API"
description = "External service integration"
isTrusted = false
image = "bundled:bootstrap/icons/icons/cloud"

[processes]

[processes.cloudfront]
label = "CloudFront"
description = "CDN and edge caching"
isServer = true
isHardened = true
image = "bundled:aws/Networking-Content-Delivery/CloudFront"

[processes.api_gateway]
label = "API Gateway"
description = "REST API endpoint"
isServer = true
hasAccessControl = true
sanitizesInput = true
image = "bundled:aws/App-Integration/API-Gateway"

[processes.lambda_auth]
label = "Auth Lambda"
description = "Authentication function"
isServer = true
hasAccessControl = true
image = "bundled:aws/Compute/Lambda"

[processes.lambda_api]
label = "API Lambda"
description = "Business logic function"
isServer = true
sanitizesInput = true
checksInputBounds = true
image = "bundled:aws/Compute/Lambda"

[processes.ecs_worker]
label = "ECS Worker"
description = "Background processing"
isServer = true
image = "bundled:aws/Containers/Elastic-Container-Service"

[datastores]

[datastores.dynamodb]
label = "DynamoDB"
description = "NoSQL database"
isSQL = false
isEncrypted = true
hasAccessControl = true
image = "bundled:aws/Database/DynamoDB"

[datastores.rds]
label = "RDS PostgreSQL"
description = "Relational database"
isSQL = true
isEncrypted = true
hasAccessControl = true
storesPII = true
image = "bundled:aws/Database/RDS"

[datastores.s3]
label = "S3 Bucket"
description = "Object storage"
isEncrypted = true
hasAccessControl = true
image = "bundled:aws/Storage/Simple-Storage-Service"

[datastores.secrets]
label = "Secrets Manager"
description = "Credentials storage"
isEncrypted = true
hasAccessControl = true
storesCredentials = true
image = "bundled:aws/Security-Identity-Compliance/Secrets-Manager"

[datastores.elasticache]
label = "ElastiCache"
description = "Redis cache"
isEncrypted = true
image = "bundled:aws/Database/ElastiCache"

[dataflows]

[dataflows.user_to_cf]
from = "user"
to = "cloudfront"
label = "HTTPS"
protocol = "HTTPS"
isEncrypted = true

[dataflows.attacker_to_cf]
from = "attacker"
to = "cloudfront"
label = "Attack Traffic"
protocol = "HTTPS"
isEncrypted = true

[dataflows.cf_to_api]
from = "cloudfront"
to = "api_gateway"
label = "Cached Request"
protocol = "HTTPS"
isEncrypted = true

[dataflows.api_to_auth]
from = "api_gateway"
to = "lambda_auth"
label = "Auth Check"
protocol = "Lambda Invoke"
isEncrypted = true

[dataflows.auth_to_secrets]
from = "lambda_auth"
to = "secrets"
label = "Get Secrets"
protocol = "AWS SDK"
isEncrypted = true
isCredentials = true

[dataflows.api_to_lambda]
from = "api_gateway"
to = "lambda_api"
label = "API Request"
protocol = "Lambda Invoke"
isEncrypted = true

[dataflows.lambda_to_dynamodb]
from = "lambda_api"
to = "dynamodb"
label = "NoSQL Query"
protocol = "AWS SDK"
isEncrypted = true

[dataflows.lambda_to_rds]
from = "lambda_api"
to = "rds"
label = "SQL Query"
protocol = "PostgreSQL"
isEncrypted = true
data = "CONFIDENTIAL"

[dataflows.lambda_to_cache]
from = "lambda_api"
to = "elasticache"
label = "Cache Ops"
protocol = "Redis"
isEncrypted = true

[dataflows.lambda_to_s3]
from = "lambda_api"
to = "s3"
label = "File Storage"
protocol = "AWS SDK"
isEncrypted = true

[dataflows.lambda_to_third]
from = "lambda_api"
to = "third_party"
label = "External API"
protocol = "HTTPS"
isEncrypted = true

[dataflows.ecs_to_dynamodb]
from = "ecs_worker"
to = "dynamodb"
label = "Background Jobs"
protocol = "AWS SDK"
isEncrypted = true

[threats]

[threats.ddos]
target = "cloudfront"
category = "Denial of Service"
description = "DDoS attack against CDN"
likelihood = "medium"
impact = "high"
mitigation = "AWS Shield, WAF rules, rate limiting"

[threats.injection]
target = "lambda_api"
category = "Tampering"
description = "Code injection via API input"
likelihood = "medium"
impact = "critical"
mitigation = "Input validation, parameterized queries"

[threats.data_breach]
target = "rds"
category = "Information Disclosure"
description = "Unauthorized access to PII"
likelihood = "low"
impact = "critical"
mitigation = "Encryption, IAM policies, VPC isolation"

[threats.credential_theft]
target = "secrets"
category = "Information Disclosure"
description = "Secrets exfiltration"
likelihood = "low"
impact = "critical"
mitigation = "Rotation, IAM least privilege, audit logging"

[threats.s3_exposure]
target = "s3"
category = "Information Disclosure"
description = "S3 bucket misconfiguration"
likelihood = "medium"
impact = "high"
mitigation = "Block public access, bucket policies"
"""

    # Write config to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'threat_model_aws_icons')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        tm = ThreatModeling(
            inputfile=temp_path,
            outputfile=output_path,
            format="png"
        )

        tm.load()
        errors = tm.validate()

        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")
            stats = tm.get_stats()
            print(f"Model: {stats.get('name')}")
            print(f"Externals: {stats.get('externals', 0)}")
            print(f"Processes: {stats.get('processes', 0)}")
            print(f"Data Stores: {stats.get('datastores', 0)}")
            print(f"Data Flows: {stats.get('dataflows', 0)}")

        tm.render().draw()
        print(f"\nOutput saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def example_bootstrap_icons():
    """Create a simple threat model with Bootstrap icons."""

    print("\n=== Threat Model with Bootstrap Icons ===\n")

    config = """
[model]
name = "Simple Web App"
description = "Basic web application threat model"
engineversion = "0.3.1"
version = "1.0.0"

[externals]

[externals.user]
label = "User"
isTrusted = false
image = "bundled:bootstrap/icons/icons/person-circle"

[externals.admin]
label = "Administrator"
isTrusted = true
image = "bundled:bootstrap/icons/icons/person-badge"

[processes]

[processes.webserver]
label = "Web Server"
isServer = true
image = "bundled:bootstrap/icons/icons/globe"

[processes.api]
label = "REST API"
isServer = true
hasAccessControl = true
image = "bundled:bootstrap/icons/icons/gear"

[datastores]

[datastores.database]
label = "Database"
isSQL = true
isEncrypted = true
image = "bundled:bootstrap/icons/icons/database"

[datastores.files]
label = "File Storage"
isEncrypted = true
image = "bundled:bootstrap/icons/icons/folder"

[dataflows]

[dataflows.user_to_web]
from = "user"
to = "webserver"
label = "HTTP"
protocol = "HTTPS"
isEncrypted = true

[dataflows.admin_to_web]
from = "admin"
to = "webserver"
label = "Admin"
protocol = "HTTPS"
isEncrypted = true

[dataflows.web_to_api]
from = "webserver"
to = "api"
label = "API Call"
protocol = "REST"
isEncrypted = true

[dataflows.api_to_db]
from = "api"
to = "database"
label = "Query"
protocol = "SQL"
isEncrypted = true

[dataflows.api_to_files]
from = "api"
to = "files"
label = "Read/Write"
protocol = "NFS"
isEncrypted = true
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'threat_model_bootstrap_icons')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        tm = ThreatModeling(temp_path, output_path, format="png")
        tm.load()
        tm.render().draw()
        print(f"Output saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


if __name__ == "__main__":
    example_with_template_icons()
    example_aws_architecture_icons()
    example_bootstrap_icons()
