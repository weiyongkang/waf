package apisec

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxSchemaDepth = 64

type validator struct {
	spec       *Spec
	max        int
	violations []Violation
	regex      map[string]*regexp.Regexp
}

func newValidator(spec *Spec, max int) *validator {
	if max <= 0 {
		max = 16
	}
	return &validator{spec: spec, max: max, regex: make(map[string]*regexp.Regexp)}
}

func (v *validator) add(location, name, rule, message string) {
	if len(v.violations) >= v.max {
		return
	}
	v.violations = append(v.violations, Violation{
		Location: location, Name: name, Rule: rule, Message: message,
	})
}

func (v *validator) reachedLimit() bool {
	return len(v.violations) >= v.max
}

// Check 校验一个值是否满足单个 schema。
//
// 返回值是本分支的违规列表；组合关键字（anyOf/oneOf）需要先试跑各分支，
// 因此不能直接写入 validator 的全局列表。
func (v *validator) check(schema any, value any, location, name string, depth int) []Violation {
	if v.reachedLimit() {
		return nil
	}
	if depth > maxSchemaDepth {
		return []Violation{{Location: location, Name: name, Rule: "schema_depth",
			Message: fmt.Sprintf("schema 嵌套超过 %d 层", maxSchemaDepth)}}
	}

	resolved, ok := v.resolve(schema)
	if !ok {
		return []Violation{{Location: location, Name: name, Rule: "schema_ref",
			Message: "无法解析本地 $ref 引用"}}
	}
	if resolved == nil {
		return nil
	}
	if allowed, isBool := resolved.(bool); isBool {
		if !allowed {
			return []Violation{{Location: location, Name: name, Rule: "schema_false",
				Message: "schema 为 false，禁止任何值"}}
		}
		return nil
	}
	obj, ok := asMap(resolved)
	if !ok {
		return []Violation{{Location: location, Name: name, Rule: "schema_invalid",
			Message: "schema 必须是对象或布尔值"}}
	}

	if value == nil {
		if nullable(obj) {
			return nil
		}
		if _, hasType := obj["type"]; hasType || len(obj) > 0 {
			return []Violation{{Location: location, Name: name, Rule: "schema_type",
				Message: "值不能为 null"}}
		}
		return nil
	}

	var violations []Violation
	if enum, exists := obj["enum"]; exists {
		if !matchesEnum(enum, value) {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_enum", Message: "值不在 enum 允许范围内"})
		}
	}
	if constant, exists := obj["const"]; exists && !equalValue(constant, value) {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_const", Message: "值与 const 不一致"})
	}

	types := schemaTypes(obj)
	if len(types) > 0 && !matchesType(types, value) {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_type", Message: fmt.Sprintf("值类型不符合 schema（期望 %s）", strings.Join(types, " / "))})
		// 类型都不匹配时继续做属性校验只会产生噪音。
		return violations
	}

	violations = append(violations, v.checkComposition(obj, value, location, name, depth)...)
	if v.reachedLimit() {
		return violations
	}

	switch typed := value.(type) {
	case map[string]any:
		violations = append(violations, v.checkObject(obj, typed, location, name, depth)...)
	case []any:
		violations = append(violations, v.checkArray(obj, typed, location, name, depth)...)
	case string:
		violations = append(violations, checkString(obj, typed, location, name, v)...)
	default:
		if number, ok := asFloat(value); ok {
			violations = append(violations, checkNumber(obj, number, location, name)...)
		}
	}
	if len(violations) > v.max {
		violations = violations[:v.max]
	}
	return violations
}

func (v *validator) resolve(schema any) (any, bool) {
	current := schema
	for i := 0; i < 32; i++ {
		obj, ok := asMap(current)
		if !ok {
			return current, true
		}
		ref := strings.TrimSpace(asString(obj["$ref"]))
		if ref == "" {
			return current, true
		}
		resolved, found := v.spec.ResolveRef(ref)
		if !found {
			return nil, false
		}
		current = resolved
	}
	return nil, false
}

func nullable(obj map[string]any) bool {
	if flag, ok := asBool(obj["nullable"]); ok && flag {
		return true
	}
	for _, item := range schemaTypes(obj) {
		if item == "null" {
			return true
		}
	}
	return false
}

func schemaTypes(obj map[string]any) []string {
	raw, exists := obj["type"]
	if !exists {
		return nil
	}
	switch typed := raw.(type) {
	case string:
		if typed == "" {
			return nil
		}
		return []string{strings.ToLower(typed)}
	case []any:
		types := make([]string, 0, len(typed))
		for _, item := range typed {
			if name := strings.ToLower(asString(item)); name != "" {
				types = append(types, name)
			}
		}
		return types
	default:
		return nil
	}
}

func matchesType(types []string, value any) bool {
	for _, expected := range types {
		switch expected {
		case "null":
			if value == nil {
				return true
			}
		case "object":
			if _, ok := value.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := value.([]any); ok {
				return true
			}
		case "string":
			if _, ok := value.(string); ok {
				return true
			}
		case "boolean":
			if _, ok := value.(bool); ok {
				return true
			}
		case "integer":
			if number, ok := asFloat(value); ok && math.Trunc(number) == number {
				return true
			}
		case "number":
			if _, ok := asFloat(value); ok {
				return true
			}
		}
	}
	return false
}

func matchesEnum(enum any, value any) bool {
	items, ok := asSlice(enum)
	if !ok {
		return false
	}
	for _, item := range items {
		if equalValue(item, value) {
			return true
		}
	}
	return false
}

func equalValue(left, right any) bool {
	if leftNumber, ok := asFloat(left); ok {
		if rightNumber, rightOK := asFloat(right); rightOK {
			return leftNumber == rightNumber
		}
	}
	return reflect.DeepEqual(left, right)
}

func (v *validator) checkComposition(obj map[string]any, value any, location, name string, depth int) []Violation {
	var violations []Violation
	if allOf, ok := asSlice(obj["allOf"]); ok {
		for index, branch := range allOf {
			for _, item := range v.check(branch, value, location, name, depth+1) {
				item.Rule = "schema_all_of"
				item.Message = fmt.Sprintf("allOf[%d] 校验失败：%s", index, item.Message)
				violations = append(violations, item)
			}
		}
	}
	if anyOf, ok := asSlice(obj["anyOf"]); ok {
		matched := false
		for _, branch := range anyOf {
			if len(v.check(branch, value, location, name, depth+1)) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_any_of", Message: "值不满足 anyOf 中任何一个分支"})
		}
	}
	if oneOf, ok := asSlice(obj["oneOf"]); ok {
		count := 0
		for _, branch := range oneOf {
			if len(v.check(branch, value, location, name, depth+1)) == 0 {
				count++
			}
		}
		if count != 1 {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_one_of", Message: fmt.Sprintf("值命中 oneOf 的 %d 个分支（要求恰好 1 个）", count)})
		}
	}
	if notSchema, exists := obj["not"]; exists {
		if len(v.check(notSchema, value, location, name, depth+1)) == 0 {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_not", Message: "值命中了 not schema"})
		}
	}
	return violations
}

func (v *validator) checkObject(obj map[string]any, value map[string]any,
	location, name string, depth int) []Violation {
	var violations []Violation
	if required, ok := asSlice(obj["required"]); ok {
		for _, item := range required {
			field := asString(item)
			if _, exists := value[field]; !exists {
				violations = append(violations, Violation{Location: location,
					Name: joinPath(name, field), Rule: "schema_required", Message: "缺少必填字段"})
			}
		}
	}
	properties, _ := asMap(obj["properties"])
	patterns, _ := asMap(obj["patternProperties"])
	for field, fieldSchema := range properties {
		if fieldValue, exists := value[field]; exists {
			violations = append(violations, v.check(fieldSchema, fieldValue,
				location, joinPath(name, field), depth+1)...)
		}
	}
	for patternText, patternSchema := range patterns {
		compiled := v.regexFor(patternText)
		if compiled == nil {
			continue
		}
		for field, fieldValue := range value {
			if compiled.MatchString(field) {
				violations = append(violations, v.check(patternSchema, fieldValue,
					location, joinPath(name, field), depth+1)...)
			}
		}
	}

	additional, hasAdditional := obj["additionalProperties"]
	if hasAdditional {
		if flag, ok := asBool(additional); ok {
			if !flag {
				for field := range value {
					if _, declared := properties[field]; declared {
						continue
					}
					if matchesPattern(patterns, v, field) {
						continue
					}
					violations = append(violations, Violation{Location: location,
						Name: joinPath(name, field), Rule: "schema_additional_property",
						Message: "schema 不允许该额外字段"})
				}
			}
		} else {
			for field, fieldValue := range value {
				if _, declared := properties[field]; declared {
					continue
				}
				if matchesPattern(patterns, v, field) {
					continue
				}
				violations = append(violations, v.check(additional, fieldValue,
					location, joinPath(name, field), depth+1)...)
			}
		}
	}
	return violations
}

func matchesPattern(patterns map[string]any, v *validator, field string) bool {
	for patternText := range patterns {
		if compiled := v.regexFor(patternText); compiled != nil && compiled.MatchString(field) {
			return true
		}
	}
	return false
}

func (v *validator) checkArray(obj map[string]any, value []any,
	location, name string, depth int) []Violation {
	var violations []Violation
	if minimum, ok := integerKeyword(obj, "minItems"); ok && len(value) < minimum {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_min_items", Message: fmt.Sprintf("数组元素数 %d 小于 minItems=%d", len(value), minimum)})
	}
	if maximum, ok := integerKeyword(obj, "maxItems"); ok && len(value) > maximum {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_max_items", Message: fmt.Sprintf("数组元素数 %d 大于 maxItems=%d", len(value), maximum)})
	}
	if items, exists := obj["items"]; exists {
		for index, item := range value {
			violations = append(violations, v.check(items, item, location,
				fmt.Sprintf("%s[%d]", name, index), depth+1)...)
		}
	}
	return violations
}

func checkString(obj map[string]any, value, location, name string, v *validator) []Violation {
	var violations []Violation
	length := utf8.RuneCountInString(value)
	if minimum, ok := integerKeyword(obj, "minLength"); ok && length < minimum {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_min_length", Message: fmt.Sprintf("字符串长度 %d 小于 minLength=%d", length, minimum)})
	}
	if maximum, ok := integerKeyword(obj, "maxLength"); ok && length > maximum {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_max_length", Message: fmt.Sprintf("字符串长度 %d 大于 maxLength=%d", length, maximum)})
	}
	if patternText := asString(obj["pattern"]); patternText != "" {
		compiled := v.regexFor(patternText)
		if compiled == nil {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_pattern_invalid", Message: "schema.pattern 不是合法正则"})
		} else if !compiled.MatchString(value) {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_pattern", Message: "字符串不匹配 pattern"})
		}
	}
	return violations
}

func checkNumber(obj map[string]any, value float64, location, name string) []Violation {
	var violations []Violation
	if minimum, ok := numberKeyword(obj, "minimum"); ok {
		exclusive, _ := asBool(obj["exclusiveMinimum"])
		if (exclusive && value <= minimum) || (!exclusive && value < minimum) {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_minimum", Message: fmt.Sprintf("数值 %v 小于 minimum=%v", value, minimum)})
		}
	}
	if maximum, ok := numberKeyword(obj, "maximum"); ok {
		exclusive, _ := asBool(obj["exclusiveMaximum"])
		if (exclusive && value >= maximum) || (!exclusive && value > maximum) {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_maximum", Message: fmt.Sprintf("数值 %v 大于 maximum=%v", value, maximum)})
		}
	}
	// OpenAPI 3.1 允许 exclusiveMinimum / exclusiveMaximum 直接是数值。
	if exclusiveMinimum, ok := numberKeyword(obj, "exclusiveMinimum"); ok && value <= exclusiveMinimum {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_exclusive_minimum", Message: fmt.Sprintf("数值 %v 不大于 exclusiveMinimum=%v", value, exclusiveMinimum)})
	}
	if exclusiveMaximum, ok := numberKeyword(obj, "exclusiveMaximum"); ok && value >= exclusiveMaximum {
		violations = append(violations, Violation{Location: location, Name: name,
			Rule: "schema_exclusive_maximum", Message: fmt.Sprintf("数值 %v 不小于 exclusiveMaximum=%v", value, exclusiveMaximum)})
	}
	if multiple, ok := numberKeyword(obj, "multipleOf"); ok && multiple > 0 {
		quotient := value / multiple
		if math.Abs(quotient-math.Round(quotient)) > 1e-9 {
			violations = append(violations, Violation{Location: location, Name: name,
				Rule: "schema_multiple_of", Message: fmt.Sprintf("数值 %v 不是 %v 的倍数", value, multiple)})
		}
	}
	return violations
}

func (v *validator) regexFor(pattern string) *regexp.Regexp {
	if compiled, exists := v.regex[pattern]; exists {
		return compiled
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		v.regex[pattern] = nil
		return nil
	}
	v.regex[pattern] = compiled
	return compiled
}

func integerKeyword(obj map[string]any, key string) (int, bool) {
	value, ok := obj[key]
	if !ok {
		return 0, false
	}
	number, ok := asFloat(value)
	if !ok || math.Trunc(number) != number {
		return 0, false
	}
	return int(number), true
}

func numberKeyword(obj map[string]any, key string) (float64, bool) {
	value, ok := obj[key]
	if !ok {
		return 0, false
	}
	// 3.0 的 exclusiveMinimum/Maximum 是布尔值，不是数值约束。
	if _, isBool := asBool(value); isBool {
		return 0, false
	}
	return asFloat(value)
}

func joinPath(parent, field string) string {
	if parent == "" {
		return field
	}
	if field == "" {
		return parent
	}
	if strings.HasPrefix(field, "[") {
		return parent + field
	}
	return parent + "." + field
}
