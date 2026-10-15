package notify

import (
	"fmt"
	"strings"

	"github.com/weiyongkang/waf/internal/core"
)

// 告警级别门槛常量：级别只增不减，便于用 >= 比较。
const (
	// levelRankInfo 是 info 级。
	levelRankInfo = 1
	// levelRankWarn 是 warn 级。
	levelRankWarn = 2
	// levelRankError 是 error 级。
	levelRankError = 3
)

// levelRank 把告警级别映射为可比较的序号。
//
// 未知级别按 info 处理（最宽松）：告警级别的拼写错误不应该导致「告警被静默丢弃」，
// 这类静默丢弃比多发一条告警危险得多。配置校验阶段已经把非法级别拦住了，
// 走到这里只可能是「有人绕过校验直接构造」的极端情况。
func levelRank(level core.AlertLevel) int {
	switch strings.ToLower(strings.TrimSpace(string(level))) {
	case string(core.AlertLevelError):
		return levelRankError
	case string(core.AlertLevelWarn):
		return levelRankWarn
	default:
		return levelRankInfo
	}
}

// ParseLevel 解析配置中的告警级别字符串。
//
// 空字符串表示「未配置」：调用方据此决定是继承全局值还是使用默认门槛。
func ParseLevel(value string) (core.AlertLevel, bool, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "":
		return "", false, nil
	case string(core.AlertLevelInfo):
		return core.AlertLevelInfo, true, nil
	case string(core.AlertLevelWarn):
		return core.AlertLevelWarn, true, nil
	case string(core.AlertLevelError):
		return core.AlertLevelError, true, nil
	default:
		return "", false, fmt.Errorf("未知的告警级别 %q，可选值：info / warn / error", value)
	}
}

// MeetsLevel 判断告警级别是否达到门槛。
func MeetsLevel(level core.AlertLevel, threshold core.AlertLevel) bool {
	return levelRank(level) >= levelRank(threshold)
}
