package config

import "reflect"

// RestartRequiredChanges 返回两次生效配置之间必须重启才能应用的段。
//
// 可热加载的段只有 pipeline / sites / ban / responder / engine：
// 它们都能在运行期重建为不可变快照并原子替换。其余段（监听地址、路由前缀、
// 接入适配、存储拓扑、日志、指标、告警通道、资源限额等）与已经启动的
// HTTP Server、日志器或后台协程绑定，运行期改值会造成半更新状态，因此必须拒绝。
func RestartRequiredChanges(oldConfig, newConfig *Config) []string {
	if oldConfig == nil || newConfig == nil {
		return []string{"config"}
	}

	changes := make([]string, 0, 10)
	if oldConfig.Version != newConfig.Version {
		changes = append(changes, "version")
	}
	if !reflect.DeepEqual(oldConfig.Server, newConfig.Server) {
		changes = append(changes, "server")
	}
	if !reflect.DeepEqual(oldConfig.Ingress, newConfig.Ingress) {
		changes = append(changes, "ingress")
	}
	if !reflect.DeepEqual(oldConfig.Stores, newConfig.Stores) {
		changes = append(changes, "stores")
	}
	if !reflect.DeepEqual(oldConfig.Notify, newConfig.Notify) {
		changes = append(changes, "notify")
	}
	if !reflect.DeepEqual(oldConfig.Notifiers, newConfig.Notifiers) {
		changes = append(changes, "notifiers")
	}
	if !reflect.DeepEqual(oldConfig.Logging, newConfig.Logging) {
		changes = append(changes, "logging")
	}
	if !reflect.DeepEqual(oldConfig.Metrics, newConfig.Metrics) {
		changes = append(changes, "metrics")
	}
	if !reflect.DeepEqual(oldConfig.Limits, newConfig.Limits) {
		changes = append(changes, "limits")
	}
	if !reflect.DeepEqual(oldConfig.Cache, newConfig.Cache) {
		changes = append(changes, "cache")
	}
	if !reflect.DeepEqual(oldConfig.Database, newConfig.Database) {
		changes = append(changes, "database")
	}
	return changes
}
