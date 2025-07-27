# ReactorCA JSON Schemas

This directory contains JSON Schema definitions for ReactorCA YAML configuration files.

## Available Schemas

- **`v1/ca.schema.json`** - Schema for `config/ca.yaml` (Certificate Authority configuration)
- **`v1/hosts.schema.json`** - Schema for `config/hosts.yaml` (Host certificate configurations)

## Editor Integration

### VS Code

The config YAML files already include schema references:

```yaml
# yaml-language-server: $schema=https://serpent213.github.io/reactor-ca/schemas/v1/ca.schema.json
```

This enables:
- **Auto-completion** for configuration keys
- **Validation** with error highlighting
- **Hover documentation** for configuration options
- **Type checking** for values

### Other Editors

Most modern editors with YAML support will recognize the `yaml-language-server` comment directive.
