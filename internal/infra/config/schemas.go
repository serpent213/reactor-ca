package config

//go:generate sh -c "mkdir -p ./schemas/v1 && cp ../../../schemas/v1/*.json ./schemas/v1/"

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed schemas/v1/ca.schema.json
var caSchemaJSON []byte

//go:embed schemas/v1/hosts.schema.json
var hostsSchemaJSON []byte

var (
	caSchema    *jsonschema.Schema
	hostsSchema *jsonschema.Schema
)

func init() {
	var err error

	compiler := jsonschema.NewCompiler()

	// Parse and add CA schema
	caSchemaData, err := jsonschema.UnmarshalJSON(strings.NewReader(string(caSchemaJSON)))
	if err != nil {
		panic("failed to unmarshal CA schema JSON: " + err.Error())
	}
	if err := compiler.AddResource("schema://ca", caSchemaData); err != nil {
		panic("failed to add CA schema resource: " + err.Error())
	}
	caSchema, err = compiler.Compile("schema://ca")
	if err != nil {
		panic("failed to compile CA schema: " + err.Error())
	}

	// Parse and add hosts schema
	hostsSchemaData, err := jsonschema.UnmarshalJSON(strings.NewReader(string(hostsSchemaJSON)))
	if err != nil {
		panic("failed to unmarshal hosts schema JSON: " + err.Error())
	}
	if err := compiler.AddResource("schema://hosts", hostsSchemaData); err != nil {
		panic("failed to add hosts schema resource: " + err.Error())
	}
	hostsSchema, err = compiler.Compile("schema://hosts")
	if err != nil {
		panic("failed to compile hosts schema: " + err.Error())
	}
}

func validateCAConfig(data []byte) error {
	// Convert YAML to JSON for schema validation
	var yamlData interface{}
	if err := yaml.Unmarshal(data, &yamlData); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	jsonData, err := json.Marshal(yamlData)
	if err != nil {
		return fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	var jsonInterface interface{}
	if err := json.Unmarshal(jsonData, &jsonInterface); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if err := caSchema.Validate(jsonInterface); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

func validateHostsConfig(data []byte) error {
	// Convert YAML to JSON for schema validation
	var yamlData interface{}
	if err := yaml.Unmarshal(data, &yamlData); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	jsonData, err := json.Marshal(yamlData)
	if err != nil {
		return fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	var jsonInterface interface{}
	if err := json.Unmarshal(jsonData, &jsonInterface); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if err := hostsSchema.Validate(jsonInterface); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}
