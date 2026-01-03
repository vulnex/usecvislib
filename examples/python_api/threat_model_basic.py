#!/usr/bin/env python3
"""
Threat Model Example - Basic (No Icons)

This example demonstrates how to create a STRIDE threat model
using the USecVisLib Python API without icons.

Threat models include:
- External entities (users, systems)
- Processes (services, applications)
- Data stores (databases, files)
- Data flows (connections between elements)
- Trust boundaries
"""

import os
import sys

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import ThreatModeling


def example_with_template():
    """Create a threat model using a template file."""

    print("=== Threat Model from Template (No Icons) ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'threat-models', 'banking_api.tml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'threat_model_basic'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        tm = ThreatModeling(
            inputfile=template_path,
            outputfile=output_path,
            format="png",
            styleid="tm_default"
        )

        # Load and validate
        tm.load()
        errors = tm.validate()

        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")

        # Get statistics
        stats = tm.get_stats()
        print(f"Model: {stats.get('name', 'Unknown')}")
        print(f"Externals: {stats.get('externals', 0)}")
        print(f"Processes: {stats.get('processes', 0)}")
        print(f"Data Stores: {stats.get('datastores', 0)}")
        print(f"Data Flows: {stats.get('dataflows', 0)}")

        # Render
        tm.render().draw()
        print(f"\nOutput saved to: {output_path}.png")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_programmatic():
    """Create a threat model programmatically using TOML data."""

    print("\n=== Threat Model Programmatic (No Icons) ===\n")

    # Create a TOML configuration string
    import tempfile
    import os as _os

    config = """
[model]
name = "E-Commerce API"
description = "Threat model for e-commerce REST API"
engineversion = "0.3.1"
version = "1.0.0"
type = "Threat Model"
date = "2025-01-01"
author = "Security Team"

[externals]

[externals.customer]
label = "Customer"
description = "Web/mobile application user"
isTrusted = false

[externals.admin]
label = "Admin"
description = "Internal administrator"
isTrusted = true

[externals.payment_provider]
label = "Payment Gateway"
description = "External payment processor"
isTrusted = false

[processes]

[processes.web_app]
label = "Web Application"
description = "Frontend web application"
isServer = true
sanitizesInput = true
encodesOutput = true

[processes.api_gateway]
label = "API Gateway"
description = "REST API gateway"
isServer = true
hasAccessControl = true
sanitizesInput = true

[processes.auth_service]
label = "Auth Service"
description = "Authentication microservice"
isServer = true
hasAccessControl = true

[processes.order_service]
label = "Order Service"
description = "Order processing microservice"
isServer = true
hasAccessControl = true

[datastores]

[datastores.user_db]
label = "User Database"
description = "PostgreSQL user database"
isSQL = true
isEncrypted = true
hasAccessControl = true
storesPII = true

[datastores.order_db]
label = "Order Database"
description = "PostgreSQL order database"
isSQL = true
isEncrypted = true
hasAccessControl = true

[datastores.cache]
label = "Redis Cache"
description = "Session and data cache"
isSQL = false
isEncrypted = true

[dataflows]

[dataflows.customer_to_web]
from = "customer"
to = "web_app"
label = "HTTPS Request"
protocol = "HTTPS"
isEncrypted = true

[dataflows.web_to_api]
from = "web_app"
to = "api_gateway"
label = "API Call"
protocol = "HTTPS"
isEncrypted = true
authenticatesSource = true

[dataflows.api_to_auth]
from = "api_gateway"
to = "auth_service"
label = "Auth Request"
protocol = "gRPC"
isEncrypted = true

[dataflows.auth_to_userdb]
from = "auth_service"
to = "user_db"
label = "User Query"
protocol = "PostgreSQL"
isEncrypted = true
data = "CREDENTIALS"

[dataflows.api_to_order]
from = "api_gateway"
to = "order_service"
label = "Order Request"
protocol = "gRPC"
isEncrypted = true
authenticatesSource = true

[dataflows.order_to_orderdb]
from = "order_service"
to = "order_db"
label = "Order Data"
protocol = "PostgreSQL"
isEncrypted = true
data = "CONFIDENTIAL"

[dataflows.order_to_payment]
from = "order_service"
to = "payment_provider"
label = "Payment Request"
protocol = "HTTPS"
isEncrypted = true
data = "PAYMENT_DATA"

[dataflows.api_to_cache]
from = "api_gateway"
to = "cache"
label = "Cache Operations"
protocol = "Redis"
isEncrypted = true

[dataflows.admin_to_web]
from = "admin"
to = "web_app"
label = "Admin Access"
protocol = "HTTPS"
isEncrypted = true
authenticatesSource = true

[threats]

[threats.sqli]
target = "user_db"
category = "Tampering"
description = "SQL Injection attacks against user database"
likelihood = "medium"
impact = "critical"
mitigation = "Use parameterized queries, input validation"

[threats.session_hijack]
target = "cache"
category = "Spoofing"
description = "Session token theft from cache"
likelihood = "low"
impact = "high"
mitigation = "Secure session management, short TTL"

[threats.payment_tampering]
target = "order_service"
category = "Tampering"
description = "Modification of payment amounts"
likelihood = "medium"
impact = "critical"
mitigation = "Server-side validation, digital signatures"

[threats.data_leak]
target = "order_db"
category = "Information Disclosure"
description = "Unauthorized access to order data"
likelihood = "low"
impact = "high"
mitigation = "Encryption, access controls, audit logging"
"""

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(config)
        temp_path = f.name

    output_path = os.path.join(os.path.dirname(__file__), 'output', 'threat_model_programmatic')
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
            print(f"Elements: {stats.get('externals', 0) + stats.get('processes', 0) + stats.get('datastores', 0)}")
            print(f"Data Flows: {stats.get('dataflows', 0)}")

        tm.render().draw()
        print(f"\nOutput saved to: {output_path}.png")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Cleanup temp file
        if _os.path.exists(temp_path):
            _os.unlink(temp_path)


def example_different_templates():
    """Load and compare different threat model templates."""

    print("\n=== Comparing Threat Model Templates ===\n")

    templates = [
        ('banking_api.tml', 'Banking API'),
        ('ecommerce_platform.tml', 'E-Commerce'),
        ('healthcare_system.tml', 'Healthcare'),
        ('iot_system.tml', 'IoT System'),
    ]

    for template_name, description in templates:
        template_path = os.path.join(
            os.path.dirname(__file__), '..', '..',
            'templates', 'threat-models', template_name
        )

        try:
            tm = ThreatModeling(
                inputfile=template_path,
                outputfile='/tmp/test',
                validate_paths=True
            )
            tm.load()
            errors = tm.validate()

            stats = tm.get_stats()
            status = "VALID" if not errors else f"INVALID ({len(errors)} errors)"

            print(f"{description} ({template_name}):")
            print(f"  Status: {status}")
            print(f"  Externals: {stats.get('externals', 0)}")
            print(f"  Processes: {stats.get('processes', 0)}")
            print(f"  Data Stores: {stats.get('datastores', 0)}")
            print(f"  Data Flows: {stats.get('dataflows', 0)}")
            print()

        except FileNotFoundError:
            print(f"{description}: Template not found")
        except Exception as e:
            print(f"{description}: Error - {e}")


if __name__ == "__main__":
    example_with_template()
    example_programmatic()
    example_different_templates()
