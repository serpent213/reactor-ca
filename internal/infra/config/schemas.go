package config

//go:generate sh -c "mkdir -p ./schemas/v1 && cp ../../../schemas/v1/*.json ./schemas/v1/"

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

//go:embed schemas/v1/ca.schema.json
var caSchemaJSON []byte

//go:embed schemas/v1/hosts.schema.json
var hostsSchemaJSON []byte

var (
	caSchema    *gojsonschema.Schema
	hostsSchema *gojsonschema.Schema
)

func init() {
	var err error

	caSchema, err = gojsonschema.NewSchema(gojsonschema.NewBytesLoader(caSchemaJSON))
	if err != nil {
		panic("failed to load embedded CA schema: " + err.Error())
	}

	hostsSchema, err = gojsonschema.NewSchema(gojsonschema.NewBytesLoader(hostsSchemaJSON))
	if err != nil {
		panic("failed to load embedded hosts schema: " + err.Error())
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

	result, err := caSchema.Validate(gojsonschema.NewBytesLoader(jsonData))
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, desc.String())
		}
		return fmt.Errorf("configuration validation failed:\n%s", strings.Join(errors, "\n"))
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

	result, err := hostsSchema.Validate(gojsonschema.NewBytesLoader(jsonData))
	if err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, desc.String())
		}
		return fmt.Errorf("configuration validation failed:\n%s", strings.Join(errors, "\n"))
	}

	return nil
}
