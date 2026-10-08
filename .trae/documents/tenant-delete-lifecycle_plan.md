# 租户删除完整生命周期一致性 实施计划

## Repository Research（现状结论）

三个删除入口已经共用同一个核心方法 `tenant.Manager.DeleteTenant(id)`，因此修复点集中、语义可以统一：

| 入口 | 路由 | 调用链 |
|---|---|---|
| dashboard 管理接口 | `DELETE /api/admin/tenants/{id}` | [tenant_admin_handler.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/dashboard/tenant_admin_handler.go#L230-L243) → adapter → `Manager.DeleteTenant` |
| 兼容 REST 路由 | `DELETE /api/v1/tenants/{id}` | [tenant_compat_handlers.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/dashboard/tenant_compat_handlers.go#L79-L89) → `Manager.DeleteTenant` |
| 内部 tenant handler | `DELETE /api/v1/tenants/{id}` | [handlers.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/handlers.go#L290-L297) → `Manager.DeleteTenant` |

已确认的缺陷（均有代码位置）：

1. **持久化失败被吞掉**：[manager.go:642-647](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/manager.go#L642-L647) `store.DeleteTenant` 出错只 `Warn` 日志、仍返回 nil → 接口返回成功，但 JSON 文件还在磁盘，`LoadAllTenants` 启动时按目录扫描重建（[store.go:252-318](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/store.go#L252-L318)），重启后旧租户复活。
2. **先删运行态再删磁盘、失败不回滚**：[manager.go:624-647](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/manager.go#L624-L647) 运行态已摘除时磁盘失败 → 运行态与重启态分裂，且调用方无法重试。
3. **运行态清理不完整**：`DeleteTenant` 不清理租户规则（只有几乎无人调用的 `DeleteTenantWithCleanup` 清理，[manager.go:1151-1160](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/manager.go#L1151-L1160)）；分钟/小时限流 tracker 无按租户删除方法（[ratetracker.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/ratetracker.go) 只有全局 `Cleanup`）；告警有 `ClearAlerts` 但 cooldown（key 为 `tenantID:alertType`）永不按租户清除（[alerts.go:257-263, 97](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/alerts.go#L257-L263)）。同名重建（ID 为随机 128bit，见 [manager.go:958-964](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/manager.go#L958-L964)）虽不继承新 ID 的配额，但旧 tracker/规则/告警在内存中残留，属于旧身份运行态泄漏。
4. **默认租户切换不确定**：[manager.go:633-639](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/manager.go#L633-L639) 用 map range 选下一个默认租户，Go map 遍历随机。
5. **兼容路由不清 dashboard 密钥缓存**：admin 删除后调用 `SetTenantAPIKey(id,"")`（[tenant_admin_handler.go:240](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/dashboard/tenant_admin_handler.go#L240)），compat 删除不清，而该 map 直接用于租户密钥鉴权（[auth.go:496-504](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/dashboard/auth.go#L496-L504)）。
6. **Store 删除非事务**：先 `os.Remove` 文件再 `saveIndex`，[saveIndex](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/store.go#L348-L355) 非原子（直接 WriteFile）；索引写失败时文件已丢，无法回到“旧租户完整可重试”。
7. **错误码不诚实**：三个 handler 对所有删除错误一律 404，持久化失败也报 404（本仓库已有“delete honesty”回归测试惯例，如 [apivalidation_delete_honesty_test.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/dashboard/apivalidation_delete_honesty_test.go)）。

关键约束/事实：

- 账单（invoices、currentUsage）与审计历史以**租户 ID 为键独立保留**（[billing.go:112-120](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/billing.go#L112-L120)），删除不得清理它们；同名新租户是新 ID，天然看不到旧账单，旧账单仍可经 `/api/admin/billing/{oldID}` 查询。
- 集群广播 `SetClusterSync` 无生产接线，广播语义本就是提交后的 best-effort（日志+丢弃），保持不变即可。
- `internal/dashboard` 包刻意不 import `internal/tenant`（接口全用 `any` + cmd 层 adapter），错误分类需维持该解耦。
- 审计在 `adminAuthAuditWrap` 包装层记录，与 handler 成败无关，无需改动。
- Store 删除不存在的租户必须继续返回 nil（幂等），已有测试依赖（tenant_extra_test.go:1272、tenant_coverage_test.go:106）。

## Files and Modules

- [internal/tenant/manager.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/manager.go)：新增 `ErrTenantNotFound` 哨兵错误；重写 `DeleteTenant`（持久化先行、失败不改任何状态；成功后确定性提交全部运行态清理）；默认租户确定性重选；`DeleteTenantWithCleanup` 收敛为委托。
- [internal/tenant/store.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/store.go)：`saveIndex` 改原子写（tmp+rename）；`DeleteTenant` 改为 all-or-nothing（备份文件字节→删文件→更新索引；索引失败回滚内存索引并从备份恢复 JSON，显式报错）。
- [internal/tenant/ratetracker.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/ratetracker.go)：新增 `TenantRateLimiter.RemoveTenant(id)`。
- [internal/tenant/alerts.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/alerts.go)：新增 `AlertManager.PurgeTenant(id)`（同时清 alerts 与 `id+":"` 前缀 cooldown）。
- [internal/tenant/handlers.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/tenant/handlers.go)：删除错误分流——not found → 404，其余 → 500；成功 204、正文格式、鉴权均不变。
- [internal/dashboard/tenant_admin_handler.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/dashboard/tenant_admin_handler.go)：同样的 404/500 分流（包内小型 not-found 分类函数，兼容现有 mock 的 `"not found"` 文本）；密钥缓存清理仅在成功时执行（现状如此，保留）。
- [internal/dashboard/tenant_compat_handlers.go](file:///Users/vance/project/mineProject/swe/09100806/project-02/internal/dashboard/tenant_compat_handlers.go)：同样的 404/500 分流；**成功后补 `d.SetTenantAPIKey(id,"")`**；失败不清缓存。
- 新增回归测试文件（均在对应包内）：
  - `internal/tenant/delete_lifecycle_test.go`
  - `internal/dashboard/tenant_delete_lifecycle_test.go`

## Implementation Steps

1. **Store 层事务化**（store.go）
   - `saveIndex`：写 `index.json.tmp`（0600）后 `rename`，与 `SaveTenant` 的原子写法一致。
   - `DeleteTenant`：校验 ID/索引一致性后：① 读取现存 JSON 字节作为回滚备份（NotExist 记为无文件，其他读错直接返回，状态未变）；② `os.Remove` 文件，非 NotExist 错误直接返回（只读目录在此失败，任何状态未改，可重试）；③ 在内存 map 的副本上删键并原子写 index；写失败则恢复内存 map、用备份字节把 JSON 文件写回原位，返回包含原因的显式错误（回滚再失败则返回复合错误）。文件先于索引删除是有意为之：`LoadAllTenants` 以目录文件为准，崩溃窗口内最坏结果是“已删除”（不会复活），而返回错误的非崩溃路径一律恢复到旧租户完整状态。
2. **限流/告警补按租户清除**：`TenantRateLimiter.RemoveTenant`（删 tracker map 键）；`AlertManager.PurgeTenant`（删 alerts 键 + 遍历 cooldowns 删 `id+":"` 前缀，前缀加分号避免 ID 前缀碰撞）。
3. **重写 Manager.DeleteTenant**（manager.go，单把 m.mu 覆盖全程）：
   - 不存在 → `fmt.Errorf("tenant %s not found: %w", id, ErrTenantNotFound)`；
   - Phase 1：`m.store != nil` 时先 `store.DeleteTenant(id)`，失败直接返回错误，**不触碰任何运行态**；
   - Phase 2：摘 domain 映射、`delete(m.tenants,id)`、`invalidateAPIKeyCache()`；若删的是默认租户，用“剩余 ID 排序取最小”确定性选定新默认（无则 ""）；
   - Phase 3：`rulesManager.DeleteTenantRules`、`rateLimiter.RemoveTenant`、`hourLimiter.RemoveTenant`、`alertManager.PurgeTenant`；**不动 billingManager**；
   - 提交成功后再 `broadcast("tenant",id,"delete",…)`（best-effort 语义不变）。
   - `DeleteTenantWithCleanup` 改为直接 `return m.DeleteTenant(id)`（清理已内含），保留导出签名兼容。
4. **三个 HTTP 入口错误分流**：
   - tenant/handlers.go 用 `errors.Is(err, ErrTenantNotFound)`；
   - dashboard 两个 handler 用包内辅助函数（错误文本含 `"not found"` 视为 404，其余 500；nil manager 仍 503）；响应体格式（dashboard 的 `{"error":…}`、内部 handler 的纯文本）与成功态 204 不变；
   - compat handler 成功后补清 dashboard 租户密钥缓存。
5. **回归测试**（见 Validation）。

## Dependencies and Considerations

- 锁序：m.mu → store.mu（与现有 Create/Update 一致）；m.mu → 子管理器自有锁为新增边，但子管理器从不回调 Manager，无环；请求路径仅持 tenant.mu 后访问子管理器，不会反向获取 m.mu。
- 并发：Create/Update/Delete 均在 m.mu 下串行。同名同域重建与删除并发时，domain 唯一校验给出确定的 409/成功；重复删除第二个请求确定得到 not-found。
- 删除前已解析、删除后才结束的在途请求可能用旧 *Tenant 再 `RecordUsage`：这是删除提交前已准入的请求，最多按旧 ID 再记一次账（账单本就保留），tracker 即便被重建也只服务于即将消失的在途请求并由既有 `CleanupRateLimiter` 兜底；删除提交后新请求在 domain/API key/default 三条解析路径上都不可能命中旧租户。
- 持久化失败时 HTTP 由 404 改为 500 是刻意修正（not-found 仍 404）；openapi.yaml 未为该操作枚举错误码，契约测试不约束，UI 对非 2xx 统一抛错展示。
- 不改动 Create/Update 的“持久化失败仅告警”行为（本次范围仅限删除生命周期）。

## Validation

- 新增测试覆盖：
  1. Store：只读目录删除→报错且 JSON+index 均不变、`LoadAllTenants` 仍含该租户、可重试成功；`index.json` 为目录注入“文件已删但索引写失败”→报错且文件从备份恢复、重载后租户仍在；正常删除后 JSON 与 index 键都消失；删除不存在租户仍 nil。
  2. Manager：存储删除失败→返回错误且 GetTenant/域名/API key/默认/规则/tracker/告警全部保持原状；同一目录新 Manager 重启后旧租户仍在。
  3. 成功删除：规则、分钟/小时 tracker（Count 归零且 tracker 键移除）、alerts 与 cooldown（Purge 后同类型告警可再次触发）全部失效；账单 invoices 仍可按旧 ID 查询。
  4. 同名重建：旧 API key 不解析、域名解析到新租户、规则/配额计数/告警从零开始、旧账单仍在。
  5. 默认租户确定性：连续多次构造相同 ID 集合，删除默认后新默认恒为剩余最小 ID。
  6. 并发：多 goroutine 并发删除/同名重建/访问，跑完后 tenants 与 domains 索引一致、无 race（`go test -race`）。
  7. HTTP：内部 handler 与 dashboard admin/compat 三入口——成功 204、不存在 404、持久化失败 500 且租户仍可 GET；compat 删除成功后旧租户密钥不再通过 dashboard 鉴权，失败时仍可鉴权。
- 全量回归：`go test ./internal/tenant/... ./internal/dashboard/... ./cmd/...`，新增测试加 `-race`；再跑一次 `go build ./...` 与 `go vet`（或 Makefile 既有目标）。

## Risks

- **回滚也失败（极端 IO 故障）**：返回包含双重原因的复合错误，调用方明确知晓未提交；不做静默吞错，运维可按错误重试或手工修复，符合“明确错误”要求。
- **500 状态码变化**：仅影响原本被谎称为 404 的持久化失败路径；成功/not-found/权限/审计格式全部不变。
- **在途请求尾巴**：如上分析，有界且不影响新租户隔离，不需要引入跨请求屏障。
