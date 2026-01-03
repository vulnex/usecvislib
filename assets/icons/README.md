# Bundled Icon Library

This directory contains bundled icons for use in USecVisLib visualizations.

## Using Icons in Templates

Icons can be referenced in node definitions using the `image` attribute with three formats:

### 1. Bundled Icons (Recommended)

Use the `bundled:` prefix followed by the icon path:

```toml
[nodes]
"Web Server" = {
    label = "Web Server"
    image = "bundled:aws/Compute/EC2"
}

"Database" = {
    label = "Database"
    image = "bundled:aws/Database/RDS"
}

"Security" = {
    label = "Security Check"
    image = "bundled:bootstrap/icons/icons/shield-lock"
}
```

### 2. Uploaded Images (via API/Frontend)

Use the `uploaded:` prefix followed by the image UUID:

```toml
[nodes]
"Custom Logo" = {
    label = "Company Logo"
    image = "uploaded:abc12345-6789-def0-1234-567890abcdef"
}
```

Upload images via:
- Frontend: ImageUploader component > Upload tab
- API: `POST /images/upload`

### 3. Local File Paths

Direct paths to local image files:

```toml
[nodes]
"Custom Icon" = {
    label = "Custom"
    image = "path/to/custom-icon.png"
}
```

## Directory Structure

```
icons/
├── aws/                    # Amazon Web Services icons
│   ├── Compute/           # EC2, Lambda, etc.
│   ├── Database/          # RDS, DynamoDB, etc.
│   ├── Security-Identity-Compliance/  # IAM, WAF, Shield, etc.
│   ├── Networking-Content-Delivery/   # VPC, CloudFront, etc.
│   └── ...
├── azure/                  # Microsoft Azure service icons
│   └── Azure_Public_Service_Icons/Icons/
│       ├── compute/
│       ├── databases/
│       └── ...
└── bootstrap/              # Bootstrap UI icons
    └── icons/icons/       # 2000+ general-purpose icons
```

## Finding Icon Paths

### Via API

```bash
# List all icons
curl http://localhost:8000/api/icons

# List by category
curl http://localhost:8000/api/icons?category=aws

# Search icons
curl http://localhost:8000/api/icons?search=database

# Get categories with counts
curl http://localhost:8000/api/icons/categories
```

### Via Frontend

1. Open any visualization panel (Attack Tree, Threat Model, etc.)
2. In the ImageUploader section, click the "Bundled Icons" tab
3. Browse categories, search, and click to select
4. The icon ID will be copied to the selected field

## Icon Path Examples

### AWS Icons
```
bundled:aws/Compute/EC2
bundled:aws/Compute/Lambda
bundled:aws/Database/RDS
bundled:aws/Database/DynamoDB
bundled:aws/Security-Identity-Compliance/Shield
bundled:aws/Security-Identity-Compliance/WAF
bundled:aws/Security-Identity-Compliance/Identity-and-Access-Management
bundled:aws/Security-Identity-Compliance/Secrets-Manager
bundled:aws/Networking-Content-Delivery/VPC
bundled:aws/App-Integration/API-Gateway
```

### Bootstrap Icons
```
bundled:bootstrap/icons/icons/shield-lock
bundled:bootstrap/icons/icons/database
bundled:bootstrap/icons/icons/server
bundled:bootstrap/icons/icons/cloud
bundled:bootstrap/icons/icons/globe
bundled:bootstrap/icons/icons/key
bundled:bootstrap/icons/icons/person-fill
bundled:bootstrap/icons/icons/exclamation-triangle-fill
bundled:bootstrap/icons/icons/bug
bundled:bootstrap/icons/icons/lock
```

### Azure Icons
```
bundled:azure/Azure_Public_Service_Icons/Icons/compute/10021-icon-service-Virtual-Machine
bundled:azure/Azure_Public_Service_Icons/Icons/databases/10132-icon-service-SQL-Database
```

## Supported Formats

- **PNG** (recommended) - Best compatibility with Graphviz
- **SVG** - Scalable, works with most renderers
- **JPEG/JPG** - Supported but not recommended (no transparency)
- **GIF** - Supported
- **BMP** - Supported

## Example Templates

See these templates for working examples:

- `templates/attack-trees/network_infrastructure_with_icons.toml` - Bootstrap icons
- `templates/attack-trees/aws_cloud_security.toml` - AWS icons
- `templates/threat-models/web_app_icons.toml` - Mixed icons in threat model

## Adding Custom Icons

1. Place icon files in the appropriate category directory
2. Use lowercase names with hyphens: `my-custom-icon.png`
3. Recommended sizes: 48x48 or 64x64 pixels for best results
4. Use PNG with transparent background for best appearance
5. Icons are automatically available via the `bundled:` prefix

## Icon Sources & Licenses

- **AWS**: [AWS Architecture Icons](https://aws.amazon.com/architecture/icons/) - AWS usage guidelines
- **Azure**: [Azure Architecture Icons](https://learn.microsoft.com/en-us/azure/architecture/icons/) - Microsoft usage terms
- **Bootstrap**: [Bootstrap Icons](https://icons.getbootstrap.com/) - MIT License

Ensure icons comply with their respective licenses when distributing.
