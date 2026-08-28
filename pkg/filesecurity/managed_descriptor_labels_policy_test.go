package filesecurity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type managedDescriptorPolicyRule struct {
	value string
	uses  int
}

func TestManagedProductionDescriptorsUseApprovedOpaqueNames(t *testing.T) {
	rules := map[string]managedDescriptorPolicyRule{
		"managedRootDescriptorName":                         {value: "<managed-root>", uses: 1},
		"managedOpenedPathDescriptorName":                   {value: "<managed-opened-path>", uses: 1},
		"managedDirectoryEntryDescriptorName":               {value: "<managed-directory-entry>", uses: 1},
		"managedTemporaryDescriptorName":                    {value: "<managed-temporary>", uses: 1},
		"managedRemovalDirectoryDescriptorName":             {value: "<managed-removal-directory>", uses: 1},
		"managedTransferDestinationFileDescriptorName":      {value: "<managed-transfer-destination-file>", uses: 1},
		"managedTransferDestinationDirectoryDescriptorName": {value: "<managed-transfer-destination-directory>", uses: 1},
		"managedTransferChildDescriptorName":                {value: "<managed-transfer-child>", uses: 1},
		"managedTransferTransactionDescriptorName":          {value: "<managed-transfer-transaction>", uses: 1},
		"managedReplacementDirectoryDescriptorName":         {value: "<managed-replacement-directory>", uses: 1},
		"managedRecoveryTransactionDescriptorName":          {value: "<managed-recovery-transaction>", uses: 1},
	}
	if violations := managedDescriptorPolicyViolations(managedProductionSources(t), rules); len(violations) != 0 {
		t.Fatal(strings.Join(violations, "\n"))
	}
}

func TestManagedDescriptorPolicyRejectsBypasses(t *testing.T) {
	const allowedDeclaration = `const approvedDescriptorName = "<approved>"`
	rules := map[string]managedDescriptorPolicyRule{
		"approvedDescriptorName": {value: "<approved>", uses: 1},
	}
	tests := []struct {
		name   string
		source string
		match  string
	}{
		{
			name: "aliased os import with dynamic name",
			source: `package fixture
import fileos "os"
` + allowedDeclaration + `
func open(fd uintptr, userPath string) { _ = fileos.NewFile(fd, userPath) }
`,
			match: "not an approved package constant",
		},
		{
			name: "dot import",
			source: `package fixture
import . "os"
` + allowedDeclaration + `
func open(fd uintptr) { _ = NewFile(fd, approvedDescriptorName) }
`,
			match: "dot-imports os",
		},
		{
			name: "function value",
			source: `package fixture
import "os"
` + allowedDeclaration + `
func open(fd uintptr, userPath string) { newFile := os.NewFile; _ = newFile(fd, userPath) }
`,
			match: "not called directly",
		},
		{
			name: "local shadow",
			source: `package fixture
import "os"
` + allowedDeclaration + `
func open(fd uintptr, userPath string) { approvedDescriptorName := userPath; _ = os.NewFile(fd, approvedDescriptorName) }
`,
			match: "not an approved package constant",
		},
		{
			name: "constant changed to variable",
			source: `package fixture
import "os"
var approvedDescriptorName = "<approved>"
func open(fd uintptr) { _ = os.NewFile(fd, approvedDescriptorName) }
`,
			match: "declared 0 times",
		},
		{
			name: "constant value drift",
			source: `package fixture
import "os"
const approvedDescriptorName = "private/path"
func open(fd uintptr) { _ = os.NewFile(fd, approvedDescriptorName) }
`,
			match: "value",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			violations := managedDescriptorPolicyViolations(map[string]string{"fixture.go": test.source}, rules)
			if len(violations) == 0 {
				t.Fatal("bypass fixture passed the managed descriptor policy")
			}
			if !strings.Contains(strings.Join(violations, "\n"), test.match) {
				t.Fatalf("policy violations = %q, want reason containing %q", violations, test.match)
			}
		})
	}
}

func managedProductionSources(t *testing.T) map[string]string {
	t.Helper()
	_, testPath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate managed descriptor policy test")
	}
	packageDirectory := filepath.Dir(testPath)
	entries, err := os.ReadDir(packageDirectory)
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(packageDirectory, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		sources[entry.Name()] = string(content)
	}
	return sources
}

func managedDescriptorPolicyViolations(sources map[string]string, rules map[string]managedDescriptorPolicyRule) []string {
	files := token.NewFileSet()
	parsed := make(map[string]*ast.File, len(sources))
	var violations []string
	filenames := make([]string, 0, len(sources))
	for filename := range sources {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	for _, filename := range filenames {
		file, err := parser.ParseFile(files, filename, sources[filename], 0)
		if err != nil {
			violations = append(violations, filename+": parse failed: "+err.Error())
			continue
		}
		parsed[filename] = file
	}

	approvedObjects := make(map[*ast.Object]string, len(rules))
	declarations := make(map[string]int, len(rules))
	for _, filename := range filenames {
		file := parsed[filename]
		if file == nil {
			continue
		}
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			for _, specification := range group.Specs {
				values, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range values.Names {
					rule, tracked := rules[name.Name]
					if !tracked {
						continue
					}
					declarations[name.Name]++
					position := files.Position(name.Pos())
					if name.Obj == nil || name.Obj.Kind != ast.Con {
						violations = append(violations, position.String()+": approved descriptor name is not a package constant")
						continue
					}
					if len(values.Values) != len(values.Names) {
						violations = append(violations, position.String()+": approved descriptor constant must have an explicit value")
						continue
					}
					literal, ok := values.Values[index].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						violations = append(violations, position.String()+": approved descriptor constant must be a string literal")
						continue
					}
					value, err := strconv.Unquote(literal.Value)
					if err != nil || value != rule.value {
						violations = append(violations, position.String()+": approved descriptor constant value does not match policy")
						continue
					}
					approvedObjects[name.Obj] = name.Name
				}
			}
		}
	}

	uses := make(map[string]int, len(rules))
	for _, filename := range filenames {
		file := parsed[filename]
		if file == nil {
			continue
		}
		osImports := make(map[string]struct{})
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil || path != "os" {
				continue
			}
			name := "os"
			if imported.Name != nil {
				name = imported.Name.Name
			}
			if name == "." {
				violations = append(violations, files.Position(imported.Pos()).String()+": managed production file dot-imports os")
				continue
			}
			if name != "_" {
				osImports[name] = struct{}{}
			}
		}

		selectorUses := 0
		directCalls := 0
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && isOSNewFileSelector(selector, osImports) {
				selectorUses++
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok = call.Fun.(*ast.SelectorExpr)
			if !ok || !isOSNewFileSelector(selector, osImports) {
				return true
			}
			directCalls++
			position := files.Position(call.Pos())
			if len(call.Args) != 2 {
				violations = append(violations, position.String()+": os.NewFile must have exactly two arguments")
				return true
			}
			label, ok := call.Args[1].(*ast.Ident)
			if !ok || label.Obj == nil {
				violations = append(violations, position.String()+": os.NewFile name is not an approved package constant")
				return true
			}
			approvedName, approved := approvedObjects[label.Obj]
			if !approved {
				violations = append(violations, position.String()+": os.NewFile name is not an approved package constant")
				return true
			}
			uses[approvedName]++
			return true
		})
		if selectorUses != directCalls {
			violations = append(violations, filename+": os.NewFile is referenced but not called directly")
		}
	}

	for name, rule := range rules {
		if declarations[name] != 1 {
			violations = append(violations, name+": approved descriptor constant declared "+strconv.Itoa(declarations[name])+" times, want 1")
		}
		if uses[name] != rule.uses {
			violations = append(violations, name+": approved descriptor constant used "+strconv.Itoa(uses[name])+" times, want "+strconv.Itoa(rule.uses))
		}
	}
	sort.Strings(violations)
	return violations
}

func isOSNewFileSelector(selector *ast.SelectorExpr, osImports map[string]struct{}) bool {
	if selector == nil || selector.Sel.Name != "NewFile" {
		return false
	}
	packageName, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	_, imported := osImports[packageName.Name]
	return imported
}
