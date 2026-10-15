package core

import (
	"fmt"
	"sort"
	"sync"
)

// registry 是「实现类型 -> 构造函数」的全局注册表。
//
// 采用编译期装配（各插件包在 init 中调用 RegisterCheck），不使用 Go plugin 包，
// 以保证 CGO_ENABLED=0 下的静态单二进制交付（设计文档 §7.2）。
var (
	registryMu sync.RWMutex
	registry   = make(map[string]CheckFactory)
)

// RegisterCheck 登记一种校验单元实现。
//
// 该函数只应在插件包的 init 函数中调用。重复登记同一类型会触发 panic：
// 这属于编译期装配错误，必须在启动阶段立刻暴露，而不是在运行期静默覆盖。
func RegisterCheck(typeName string, factory CheckFactory) {
	if typeName == "" {
		panic("core: RegisterCheck 的类型名不能为空")
	}
	if factory == nil {
		panic(fmt.Sprintf("core: RegisterCheck(%q) 的构造函数不能为 nil", typeName))
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[typeName]; exists {
		panic(fmt.Sprintf("core: 校验单元类型 %q 被重复注册", typeName))
	}
	registry[typeName] = factory
}

// NewCheck 依据实例配置构造校验单元。
//
// 未注册的类型直接返回错误（fail fast）：配置里写了 type 却没有对应实现，
// 属于部署事故，必须在启动阶段而非首个请求到达时才发现。
func NewCheck(inst InstanceConfig, deps *Deps) (Check, error) {
	registryMu.RLock()
	factory, ok := registry[inst.Type]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("校验单元类型 %q 未注册（可用类型：%v）", inst.Type, RegisteredTypes())
	}

	check, err := factory(inst, deps)
	if err != nil {
		return nil, fmt.Errorf("构造校验单元 %q(type=%s) 失败：%w", inst.Name, inst.Type, err)
	}
	if check == nil {
		return nil, fmt.Errorf("校验单元 %q(type=%s) 的构造函数返回了空实例", inst.Name, inst.Type)
	}
	return check, nil
}

// RegisteredTypes 返回当前已注册的全部实现类型名，按字典序排列。
//
// 用于 `check-config` 输出与错误提示，帮助运维快速发现类型名拼写错误。
func RegisteredTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	types := make([]string, 0, len(registry))
	for name := range registry {
		types = append(types, name)
	}
	sort.Strings(types)
	return types
}
