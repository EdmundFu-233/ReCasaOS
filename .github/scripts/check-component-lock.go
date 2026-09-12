// check-component-lock validates the fail-closed ReCasaOS component inventory.
//
// Unresolved entries are deliberately not pins. This policy slice fixes the
// publication state at HOLD, so both GoReleaser configurations must keep
// publication disabled even if every component is structurally locked. A
// future locked entry must carry immutable source and artifact identifiers plus
// the release metadata required by Issue #9.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const (
	componentLockSchemaVersion    = 1
	componentLockPublicationState = "hold"
	maxPolicyFileBytes            = 1 << 20
)

var (
	requiredComponentNames = []string{
		"app-management",
		"gateway",
		"user-service",
		"message-bus",
		"administrative-ui",
		"installer",
	}
	immutableRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	sha256Pattern            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	manifestJSONKeys         = map[string]struct{}{
		"schema_version":    {},
		"publication_state": {},
		"components":        {},
	}
	componentJSONKeys = map[string]struct{}{
		"name":                 {},
		"state":                {},
		"reason":               {},
		"source_repository":    {},
		"source_revision":      {},
		"artifact_sha256":      {},
		"license":              {},
		"api_schema":           {},
		"compatibility_status": {},
	}
)

type componentLockManifest struct {
	SchemaVersion    int                          `json:"schema_version"`
	PublicationState string                       `json:"publication_state"`
	Components       []componentLockManifestEntry `json:"components"`
}

type componentLockManifestEntry struct {
	Name                string  `json:"name"`
	State               string  `json:"state"`
	Reason              *string `json:"reason,omitempty"`
	SourceRepository    *string `json:"source_repository,omitempty"`
	SourceRevision      *string `json:"source_revision,omitempty"`
	ArtifactSHA256      *string `json:"artifact_sha256,omitempty"`
	License             *string `json:"license,omitempty"`
	APISchema           *string `json:"api_schema,omitempty"`
	CompatibilityStatus *string `json:"compatibility_status,omitempty"`
}

func main() {
	manifestPath := flag.String("manifest", "release/components.lock.json", "component-lock manifest")
	goReleaserPath := flag.String("goreleaser", ".goreleaser.yaml", "primary GoReleaser configuration")
	goReleaserDebugPath := flag.String("goreleaser-debug", ".goreleaser.debug.yaml", "debug GoReleaser configuration")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected positional arguments: %s", strings.Join(flag.Args(), " ")))
	}

	manifest, err := readComponentLockManifest(*manifestPath)
	if err != nil {
		fail(err)
	}
	unresolved, err := validateComponentLockManifest(manifest)
	if err != nil {
		fail(err)
	}
	for _, path := range []string{*goReleaserPath, *goReleaserDebugPath} {
		if err := requireReleaseDisabled(path); err != nil {
			fail(err)
		}
	}
	fmt.Printf(
		"component lock publication HOLD: %d of %d required components are unresolved; both GoReleaser configurations remain disabled\n",
		unresolved,
		len(requiredComponentNames),
	)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "component lock policy violation: %v\n", err)
	os.Exit(1)
}

func readComponentLockManifest(path string) (componentLockManifest, error) {
	data, err := readRegularPolicyFile(path)
	if err != nil {
		return componentLockManifest{}, err
	}
	if err := validateComponentLockJSONKeys(data); err != nil {
		return componentLockManifest{}, fmt.Errorf("decode %s: %w", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest componentLockManifest
	if err := decoder.Decode(&manifest); err != nil {
		return componentLockManifest{}, fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return componentLockManifest{}, fmt.Errorf("decode %s: multiple JSON values", path)
		}
		return componentLockManifest{}, fmt.Errorf("decode trailing content in %s: %w", path, err)
	}
	return manifest, nil
}

func validateComponentLockJSONKeys(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("component lock must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('{') {
		return errors.New("component lock root must be a JSON object")
	}
	if err := walkJSONObject(decoder, "$", manifestJSONKeys, true); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode trailing JSON content: %w", err)
	}
	return nil
}

func walkJSONObject(
	decoder *json.Decoder,
	path string,
	allowedKeys map[string]struct{},
	isManifest bool,
) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("object at %s has a non-string key", path)
		}
		if _, ok := seen[key]; ok {
			return fmt.Errorf("object at %s has duplicate key %q", path, key)
		}
		seen[key] = struct{}{}
		if allowedKeys != nil {
			if _, ok := allowedKeys[key]; !ok {
				return fmt.Errorf("object at %s has unknown key %q", path, key)
			}
		}
		if isManifest && key == "components" {
			if err := walkComponentJSONArray(decoder, path+".components"); err != nil {
				return err
			}
			continue
		}
		if err := walkJSONValue(decoder, path+"."+key); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("object at %s has invalid closing delimiter", path)
	}
	return nil
}

func walkComponentJSONArray(decoder *json.Decoder, path string) error {
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening != json.Delim('[') {
		return fmt.Errorf("%s must be a JSON array", path)
	}
	for index := 0; decoder.More(); index++ {
		opening, err := decoder.Token()
		if err != nil {
			return err
		}
		if opening != json.Delim('{') {
			return fmt.Errorf("%s[%d] must be a JSON object", path, index)
		}
		if err := walkJSONObject(
			decoder,
			fmt.Sprintf("%s[%d]", path, index),
			componentJSONKeys,
			false,
		); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(']') {
		return fmt.Errorf("%s has invalid closing delimiter", path)
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		return walkJSONObject(decoder, path, nil, false)
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := walkJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("array at %s has invalid closing delimiter", path)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, path)
	}
	return nil
}

func readRegularPolicyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxPolicyFileBytes {
		return nil, fmt.Errorf("%s exceeds the %d-byte policy limit", path, maxPolicyFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func validateComponentLockManifest(manifest componentLockManifest) (int, error) {
	if manifest.SchemaVersion != componentLockSchemaVersion {
		return 0, fmt.Errorf(
			"schema_version is %d, want %d",
			manifest.SchemaVersion,
			componentLockSchemaVersion,
		)
	}
	if manifest.PublicationState != componentLockPublicationState {
		return 0, fmt.Errorf(
			"publication_state is %q, want fixed state %q",
			manifest.PublicationState,
			componentLockPublicationState,
		)
	}
	if len(manifest.Components) != len(requiredComponentNames) {
		return 0, fmt.Errorf(
			"component count is %d, want exactly %d",
			len(manifest.Components),
			len(requiredComponentNames),
		)
	}

	required := make(map[string]struct{}, len(requiredComponentNames))
	for _, name := range requiredComponentNames {
		required[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(manifest.Components))
	unresolved := 0
	for index, component := range manifest.Components {
		if component.Name != strings.TrimSpace(component.Name) || component.Name == "" {
			return 0, fmt.Errorf("component %d has an empty or non-canonical name", index+1)
		}
		if _, ok := required[component.Name]; !ok {
			return 0, fmt.Errorf("component %q is not in the fixed required set", component.Name)
		}
		if _, ok := seen[component.Name]; ok {
			return 0, fmt.Errorf("component %q is duplicated", component.Name)
		}
		seen[component.Name] = struct{}{}
		if component.Name != requiredComponentNames[index] {
			return 0, fmt.Errorf(
				"component %d is %q, want canonical required component %q",
				index+1,
				component.Name,
				requiredComponentNames[index],
			)
		}

		switch component.State {
		case "unresolved":
			unresolved++
			if err := validateUnresolvedComponent(component); err != nil {
				return 0, err
			}
		case "locked":
			if err := validateLockedComponent(component); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf(
				"component %q has unsupported state %q",
				component.Name,
				component.State,
			)
		}
	}
	for _, name := range requiredComponentNames {
		if _, ok := seen[name]; !ok {
			return 0, fmt.Errorf("required component %q is missing", name)
		}
	}
	return unresolved, nil
}

func validateUnresolvedComponent(component componentLockManifestEntry) error {
	if component.Reason == nil || strings.TrimSpace(*component.Reason) == "" {
		return fmt.Errorf("unresolved component %q is missing its HOLD reason", component.Name)
	}
	for field, value := range map[string]*string{
		"source_repository":    component.SourceRepository,
		"source_revision":      component.SourceRevision,
		"artifact_sha256":      component.ArtifactSHA256,
		"license":              component.License,
		"api_schema":           component.APISchema,
		"compatibility_status": component.CompatibilityStatus,
	} {
		if value != nil {
			return fmt.Errorf(
				"unresolved component %q must not carry unreviewed %s",
				component.Name,
				field,
			)
		}
	}
	return nil
}

func validateLockedComponent(component componentLockManifestEntry) error {
	if component.Reason != nil {
		return fmt.Errorf("locked component %q must not retain an unresolved reason", component.Name)
	}
	repository, err := requiredMetadata(component.Name, "source_repository", component.SourceRepository)
	if err != nil {
		return err
	}
	parsedRepository, err := url.Parse(repository)
	if err != nil || parsedRepository.Scheme != "https" || parsedRepository.Host == "" ||
		parsedRepository.User != nil || parsedRepository.RawQuery != "" || parsedRepository.Fragment != "" ||
		parsedRepository.Path == "" || parsedRepository.Path == "/" {
		return fmt.Errorf("locked component %q has a non-canonical HTTPS source_repository", component.Name)
	}

	revision, err := requiredMetadata(component.Name, "source_revision", component.SourceRevision)
	if err != nil {
		return err
	}
	if !immutableRevisionPattern.MatchString(revision) || allZeroes(revision) {
		return fmt.Errorf(
			"locked component %q source_revision must be a non-zero 40- or 64-character lowercase hexadecimal commit",
			component.Name,
		)
	}

	artifactSHA256, err := requiredMetadata(component.Name, "artifact_sha256", component.ArtifactSHA256)
	if err != nil {
		return err
	}
	if !sha256Pattern.MatchString(artifactSHA256) || allZeroes(artifactSHA256) {
		return fmt.Errorf(
			"locked component %q artifact_sha256 must be a non-zero lowercase SHA-256",
			component.Name,
		)
	}

	license, err := requiredMetadata(component.Name, "license", component.License)
	if err != nil {
		return err
	}
	if err := rejectPlaceholderMetadata(component.Name, "license", license); err != nil {
		return err
	}
	apiSchema, err := requiredMetadata(component.Name, "api_schema", component.APISchema)
	if err != nil {
		return err
	}
	if err := rejectPlaceholderMetadata(component.Name, "api_schema", apiSchema); err != nil {
		return err
	}
	compatibility, err := requiredMetadata(
		component.Name,
		"compatibility_status",
		component.CompatibilityStatus,
	)
	if err != nil {
		return err
	}
	if compatibility != "passed" {
		return fmt.Errorf(
			"locked component %q compatibility_status is %q, want %q",
			component.Name,
			compatibility,
			"passed",
		)
	}
	return nil
}

func requiredMetadata(componentName, fieldName string, value *string) (string, error) {
	if value == nil {
		return "", fmt.Errorf("locked component %q is missing %s", componentName, fieldName)
	}
	canonical := strings.TrimSpace(*value)
	if canonical == "" || canonical != *value || strings.ContainsAny(canonical, "\r\n\x00") {
		return "", fmt.Errorf("locked component %q has empty or non-canonical %s", componentName, fieldName)
	}
	return canonical, nil
}

func rejectPlaceholderMetadata(componentName, fieldName, value string) error {
	switch strings.ToLower(value) {
	case "main", "master", "latest", "head", "todo", "tbd", "unknown", "unresolved":
		return fmt.Errorf(
			"locked component %q has moving or placeholder %s %q",
			componentName,
			fieldName,
			value,
		)
	default:
		return nil
	}
}

func allZeroes(value string) bool {
	return strings.Trim(value, "0") == ""
}

func requireReleaseDisabled(path string) error {
	data, err := readRegularPolicyFile(path)
	if err != nil {
		return err
	}
	if bytes.Contains(data, []byte{0xef, 0xbb, 0xbf}) {
		return fmt.Errorf("%s contains a forbidden UTF-8 byte-order mark", path)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode %s as YAML: %w", path, err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%s must contain exactly one YAML document", path)
		}
		return fmt.Errorf("decode trailing YAML content in %s: %w", path, err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return fmt.Errorf("%s must contain one non-empty YAML document", path)
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must have a top-level YAML mapping", path)
	}

	release, err := uniqueYAMLMappingValue(root, "release", "top-level")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if release == nil {
		return fmt.Errorf("%s is missing its explicit top-level release mapping", path)
	}
	if err := rejectYAMLIndirection(release, "release"); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if release.Kind != yaml.MappingNode {
		return fmt.Errorf("%s top-level release value must be an explicit mapping", path)
	}

	disable, err := uniqueYAMLMappingValue(release, "disable", "release")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if disable == nil {
		return fmt.Errorf("%s release mapping is missing its explicit disable field", path)
	}
	if disable.Kind != yaml.ScalarNode || disable.Tag != "!!bool" {
		return fmt.Errorf("%s release.disable must be an explicit YAML boolean true", path)
	}
	var disabled bool
	if err := disable.Decode(&disabled); err != nil || !disabled {
		return fmt.Errorf("%s release.disable must be an explicit YAML boolean true", path)
	}
	return nil
}

func uniqueYAMLMappingValue(mapping *yaml.Node, keyName, path string) (*yaml.Node, error) {
	if mapping.Kind != yaml.MappingNode || len(mapping.Content)%2 != 0 {
		return nil, fmt.Errorf("%s must be a well-formed YAML mapping", path)
	}
	var value *yaml.Node
	for index := 0; index < len(mapping.Content); index += 2 {
		key := mapping.Content[index]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, fmt.Errorf("%s contains a non-string mapping key", path)
		}
		if key.Value != keyName {
			continue
		}
		if value != nil {
			return nil, fmt.Errorf("%s contains duplicate %q keys", path, keyName)
		}
		value = mapping.Content[index+1]
	}
	return value, nil
}

func rejectYAMLIndirection(node *yaml.Node, path string) error {
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s contains a forbidden YAML alias", path)
	}
	if node.Anchor != "" {
		return fmt.Errorf("%s contains a forbidden YAML anchor", path)
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("%s must be a well-formed YAML mapping", path)
		}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Tag == "!!merge" || key.Value == "<<" {
				return fmt.Errorf("%s contains a forbidden YAML merge key", path)
			}
		}
	}
	for _, child := range node.Content {
		if err := rejectYAMLIndirection(child, path); err != nil {
			return err
		}
	}
	return nil
}
