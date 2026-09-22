# x/p2p 接口改名：TunnelProvider.OpenTunnelStream → Dial

> 2026-09-22。与 p2p 的 `Provider` 接口对齐：`Provider` 是唯一对外的传输接口
> （`Dial` / `Listen` / `Close`，与 `net` 包一致）。p2p 与 x 之间靠**结构化匹配**耦合
> （`registry.P2PRegistry().Register(name, host.Provider())`），所以接口方法名必须两仓同步；
> **x 先改并发版，p2p 与 wisper 跟随**（见 `p2p/docs/2026-09-22-p2p-host-listen.md`）。

## 改动（3 个文件）

1. `x/p2p/tunnel_dialer.go`
   - `TunnelProvider` 接口：`OpenTunnelStream(ctx, network, peer string) (net.Conn, error)` → **`Dial(...)`**，接口注释同步；
   - 调用点（约 `:143`）`d.pr.OpenTunnelStream(...)` → `d.pr.Dial(...)`；
   - 注释中提及方法名的两处（`:85`、`:124`、`:137`）同步。
2. `x/p2p/plugin/grpc.go`
   - `func (p *grpcPlugin) OpenTunnelStream(...)` → `Dial(...)`；`:34`、`:61` 的注释同步。
3. `x/p2p/plugin/grpc_test.go`
   - `countingProvider.OpenTunnelStream` → `Dial`；三处断言文案同步。

不改：`x/config/loading/*`（只引用类型名 `xp2p.TunnelProvider`，不受方法改名影响）；
gost 主仓无引用（已 grep 确认）。

## 验证

```bash
cd x && go build ./... && go vet ./...
grep -rn "OpenTunnelStream" x/ || echo "no residue"
```

## 发布（需用户确认）

```bash
git push && git tag v0.18.0 && git push origin v0.18.0
```

（接口改名是破坏性变更 → 按 0.x 语义升 minor；若倾向 patch 则 v0.17.3。）
