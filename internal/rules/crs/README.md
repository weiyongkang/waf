# 内置 CRS 规则集（编译期嵌入）

本目录的规则文件通过 `//go:embed` 编入 WAF 二进制，运行期不需要任何外部规则目录，
因此 distroless 镜像里只有一个可执行文件（需求 R14）。

## 来源

本目录内容自 `reference/coraza-traefik-WAF/rules/` 复制而来（需求 R10：参考实现只能参考，
复用必须复制一份并在本项目内维护），上游为 OWASP ModSecurity Core Rule Set（CRS）。

- 规则版本：见各文件头部 `OWASP_CRS/4.17.0-dev`
- 许可协议：Apache License 2.0（见各文件头部声明）
- 注意：`crs-setup.conf` 是上游的精简版（仅设置 `tx.paranoia_level` 与异常评分阈值）；
  偏执等级的实际生效值由 `internal/check/coraza` 通过注入 `SecAction`
  （`tx.blocking_paranoia_level` / `tx.detection_paranoia_level`）控制，
  因此不要直接修改本文件来调节偏执等级，请改配置项 `engine.paranoia_level`。

## 更新方式

1. 用上游 CRS 的新版本覆盖本目录（保持文件名不变）；
2. 修改 `configs/waf.example.yaml` 中的 `engine.rules.dirs` 为空（使用内置规则集）；
3. 重启服务；启动日志会输出 `rule_source`、`rule_files`、`rule_bytes` 三项，
   用于确认新规则集已被加载。

规则文件的大小受 `limits.max_rule_file_bytes` 与 `limits.max_rules_total_bytes`
限制（需求 R13）：单文件超限会被拒绝加载，总量超限会让启动直接失败。