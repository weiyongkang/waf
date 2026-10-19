package core

// ResultTarget 返回结论中首个可用于排障的检测目标。
//
// 优先使用插件显式写入的 target；旧插件没有该字段时，回退到 CRS 的 matched_var、
// 封禁范围、限速维度等既有证据字段，保证升级后立刻可用。
func ResultTarget(result *Result) string {
	if result == nil {
		return ""
	}
	for _, finding := range result.Findings {
		if target := FindingTarget(finding); target != "" {
			return target
		}
	}
	return ""
}

// FindingTarget 返回单条命中明细的检测目标。
func FindingTarget(finding Finding) string {
	for _, key := range []string{"target", "matched_var", "ban_scope", "dimensions", "location"} {
		if value := finding.Data[key]; value != "" {
			return value
		}
	}
	return ""
}

// ResultBanScope 返回结论中记录的封禁维度；没有封禁证据时返回空串。
func ResultBanScope(result *Result) string {
	if result == nil {
		return ""
	}
	for _, finding := range result.Findings {
		if scope := finding.Data["ban_scope"]; scope != "" {
			return scope
		}
	}
	return ""
}
