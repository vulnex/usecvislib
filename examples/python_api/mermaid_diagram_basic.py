#!/usr/bin/env python3
"""
Mermaid Diagram Examples

This example demonstrates how to create Mermaid diagrams
using the USecVisLib Python API.

Mermaid diagrams support:
- Flowcharts, sequence diagrams, class diagrams
- State diagrams, ER diagrams, Gantt charts
- Pie charts, mindmaps, timelines, and more
- Multiple themes (default, dark, forest, neutral)

Requirements:
- mermaid-cli must be installed: npm install -g @mermaid-js/mermaid-cli
"""

import os
import sys

# Add the src directory to the path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from usecvislib import MermaidDiagrams


def example_flowchart_from_string():
    """Create a flowchart from a Mermaid string."""

    print("=== Mermaid Flowchart (from string) ===\n")

    mermaid_syntax = """
flowchart TD
    A[Start] --> B{Is it valid?}
    B -->|Yes| C[Process Data]
    B -->|No| D[Show Error]
    C --> E[Save Results]
    D --> F[Log Error]
    E --> G[End]
    F --> G
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_flowchart'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load_from_string(mermaid_syntax)

        print(f"Diagram type: {md.diagram_type}")
        print(f"Source length: {len(md.source)} characters")

        result = md.render(output_path, format="png", theme="default")
        print(f"\nOutput saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")
        print("Note: mermaid-cli must be installed (npm install -g @mermaid-js/mermaid-cli)")


def example_sequence_diagram():
    """Create a sequence diagram from a Mermaid string."""

    print("\n=== Mermaid Sequence Diagram ===\n")

    mermaid_syntax = """
sequenceDiagram
    participant User
    participant Frontend
    participant API
    participant Database

    User->>Frontend: Login Request
    Frontend->>API: POST /auth/login
    API->>Database: Query User
    Database-->>API: User Data
    API->>API: Validate Password
    alt Password Valid
        API-->>Frontend: JWT Token
        Frontend-->>User: Login Success
    else Password Invalid
        API-->>Frontend: 401 Unauthorized
        Frontend-->>User: Show Error
    end
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_sequence'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load_from_string(mermaid_syntax)

        print(f"Diagram type: {md.diagram_type}")

        # Render with dark theme
        result = md.render(output_path, format="png", theme="dark")
        print(f"Output saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")


def example_from_template():
    """Load a Mermaid diagram from a template file."""

    print("\n=== Mermaid Diagram from Template ===\n")

    template_path = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'mermaid', 'security', 'attack-flow.toml'
    )
    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_attack_flow'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load(template_path)

        print(f"Title: {md.config.title}")
        print(f"Theme: {md.config.theme}")
        print(f"Diagram type: {md.diagram_type}")

        result = md.render(output_path, format="png")
        print(f"\nOutput saved to: {result.output_path}")

    except FileNotFoundError:
        print(f"Template not found: {template_path}")
    except Exception as e:
        print(f"Error: {e}")


def example_er_diagram():
    """Create an Entity-Relationship diagram."""

    print("\n=== Mermaid ER Diagram ===\n")

    mermaid_syntax = """
erDiagram
    USER ||--o{ ORDER : places
    USER {
        int id PK
        string username
        string email
        datetime created_at
    }
    ORDER ||--|{ ORDER_ITEM : contains
    ORDER {
        int id PK
        int user_id FK
        datetime order_date
        string status
    }
    ORDER_ITEM }|--|| PRODUCT : references
    ORDER_ITEM {
        int id PK
        int order_id FK
        int product_id FK
        int quantity
    }
    PRODUCT {
        int id PK
        string name
        decimal price
        int stock
    }
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_er'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load_from_string(mermaid_syntax)

        print(f"Diagram type: {md.diagram_type}")

        result = md.render(output_path, format="png", theme="forest")
        print(f"Output saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")


def example_state_diagram():
    """Create a state diagram for a security workflow."""

    print("\n=== Mermaid State Diagram ===\n")

    mermaid_syntax = """
stateDiagram-v2
    [*] --> Idle
    Idle --> Authenticating: Login Request
    Authenticating --> Authenticated: Valid Credentials
    Authenticating --> Failed: Invalid Credentials
    Failed --> Idle: Retry
    Failed --> Locked: Max Attempts
    Authenticated --> Active: Session Start
    Active --> Idle: Logout
    Active --> Expired: Timeout
    Expired --> Idle: Session Cleared
    Locked --> Idle: Admin Unlock
    Locked --> [*]: Account Disabled
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_state'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load_from_string(mermaid_syntax)

        print(f"Diagram type: {md.diagram_type}")

        result = md.render(output_path, format="png", theme="neutral")
        print(f"Output saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")


def example_mindmap():
    """Create a security domains mindmap."""

    print("\n=== Mermaid Mindmap ===\n")

    mermaid_syntax = """
mindmap
    root((Security Domains))
        Network Security
            Firewalls
            IDS/IPS
            VPN
            Segmentation
        Application Security
            SAST
            DAST
            Code Review
            Dependency Scanning
        Identity & Access
            Authentication
            Authorization
            MFA
            SSO
        Data Security
            Encryption
            DLP
            Backup
            Classification
        Cloud Security
            IAM
            Container Security
            Serverless Security
            CSPM
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_mindmap'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load_from_string(mermaid_syntax)

        print(f"Diagram type: {md.diagram_type}")

        result = md.render(output_path, format="png")
        print(f"Output saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")


def example_gantt_chart():
    """Create a Gantt chart for a security project."""

    print("\n=== Mermaid Gantt Chart ===\n")

    mermaid_syntax = """
gantt
    title Security Assessment Timeline
    dateFormat  YYYY-MM-DD
    section Planning
    Scope Definition      :a1, 2025-01-01, 5d
    Resource Allocation   :a2, after a1, 3d
    section Assessment
    Vulnerability Scan    :b1, after a2, 7d
    Penetration Testing   :b2, after b1, 10d
    Code Review           :b3, after a2, 14d
    section Reporting
    Analysis              :c1, after b2, 5d
    Report Writing        :c2, after c1, 5d
    Presentation          :c3, after c2, 2d
    section Remediation
    Fix Critical Issues   :d1, after c3, 14d
    Retest                :d2, after d1, 5d
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_gantt'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load_from_string(mermaid_syntax)

        print(f"Diagram type: {md.diagram_type}")

        result = md.render(output_path, format="png")
        print(f"Output saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")


def example_class_diagram():
    """Create a class diagram for a security system."""

    print("\n=== Mermaid Class Diagram ===\n")

    mermaid_syntax = """
classDiagram
    class User {
        +int id
        +string username
        +string email
        +authenticate()
        +logout()
    }
    class Role {
        +int id
        +string name
        +List~Permission~ permissions
        +hasPermission(string)
    }
    class Permission {
        +int id
        +string resource
        +string action
    }
    class Session {
        +string token
        +datetime expires
        +bool isValid()
        +refresh()
    }
    class AuditLog {
        +int id
        +datetime timestamp
        +string action
        +string details
        +log(action, details)
    }

    User "1" --> "*" Role : has
    Role "1" --> "*" Permission : contains
    User "1" --> "0..1" Session : owns
    User "1" --> "*" AuditLog : generates
"""

    output_path = os.path.join(
        os.path.dirname(__file__), 'output', 'mermaid_class'
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        md = MermaidDiagrams()
        md.load_from_string(mermaid_syntax)

        print(f"Diagram type: {md.diagram_type}")

        result = md.render(output_path, format="png", theme="default")
        print(f"Output saved to: {result.output_path}")

    except Exception as e:
        print(f"Error: {e}")


def example_list_templates():
    """List all available Mermaid templates."""

    print("\n=== Available Mermaid Templates ===\n")

    import glob

    templates_dir = os.path.join(
        os.path.dirname(__file__), '..', '..',
        'templates', 'mermaid'
    )

    templates = glob.glob(os.path.join(templates_dir, '**', '*.toml'), recursive=True)

    for template_path in sorted(templates):
        rel_path = os.path.relpath(template_path, templates_dir)

        try:
            md = MermaidDiagrams()
            md.load(template_path)

            print(f"{rel_path}:")
            print(f"  Title: {md.config.title or 'N/A'}")
            print(f"  Type: {md.diagram_type}")
            print(f"  Theme: {md.config.theme}")
            print()

        except Exception as e:
            print(f"{rel_path}: Error - {e}")


if __name__ == "__main__":
    example_flowchart_from_string()
    example_sequence_diagram()
    example_from_template()
    example_er_diagram()
    example_state_diagram()
    example_mindmap()
    example_gantt_chart()
    example_class_diagram()
    example_list_templates()
