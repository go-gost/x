# Go-Gost #652: User Namespace 支持 — 技术调研

## Issue

[go-gost/gost#652](https://github.com/go-gost/gost/issues/652) — Feature request: Linux user namespace support.

作者: @Niek | 状态: OPEN

请求支持 Linux user namespaces，使任意程序可以被透明代理。参考项目：[wirez](https://github.com/v-byte-cpu/wirez)（Go 实现的 per-program 透明代理）。

## 核心发现：User NS vs Net NS

GOST 已有完善的**网络命名空间 (netns)** 支持，但 user namespace 与 network namespace 有本质差异：

| 属性 | Network NS | User NS |
|------|-----------|---------|
| 切换时机 | 可事后进入 (`setns()`) | **必须在进程创建时** (`clone(CLONE_NEWUSER)`) |
| 作用域 | per-thread | **per-process** |
| 权限要求 | 需要 `CAP_SYS_ADMIN` | **无需特权** (Linux 3.8+) |
| Go 实现 | `github.com/vishvananda/netns` | `syscall.SysProcAttr` + `os/exec` |
| 可事后 setns? | ✅ (如果有 fd) | ❌ per-process，不能 per-thread 切换 |

**关键结论：现有的 `switchNetns()` 模式（[x/internal/net/dialer/dialer_netns.go]）无法直接套用到 user namespace。** 需要完全不同的架构：进程创建时通过 `clone()` 建立 namespace，而不是事后 `setns()` 切换。

---

## 现有基础：GOST 已有的可复用组件

### 1. TUN Listener 框架

两个 TUN listener 实现：
- `x/listener/tun/` — 使用 `golang.zx2c4.com/wireguard/tun`，注册名 `"tun"`
- `x/listener/tungo/` — 同样的 wireguard tun driver，注册名 `"tungo"`

两者结构相同：`Init()` → `listenLoop()` → `Accept()` 返回 TUN `net.Conn`，handler 在 conn 上读写 IP 包。

### 2. gVisor Netstack 集成

`x/handler/tungo/` 已深度集成 gVisor netstack (`gvisor.dev/gvisor/pkg/tcpip/stack`)。handler 接收 TUN conn 上的 IP 包，通过 gVisor 做 TCP/UDP 协议栈处理，将流量路由到 GOST proxy chain。

**关键架构优势**：TUN listener 和 handler 在 `io.ReadWriteCloser` 接口处解耦。意味着新增一个 "在 user namespace 内创建 TUN 并通过 fd 传递传回" 的 listener，可以直接对接现有的 `tungo` handler。

### 3. Namespace 基础设施

- `x/internal/net/dialer/dialer_netns.go` — `switchNetns()` 函数，`runtime.LockOSThread()` + `netns.Get()` + `netns.Set()` 模式
- `x/internal/net/net.go` — `ListenConfig` wrapper，支持 namespace-aware 的 `Listen()`/`ListenPacket()`
- `x/config/parsing/parse.go` — `MDKeyNetns`, `MDKeyNetnsOut` metadata key 常量
- `x/config/parsing/service/parse.go` — Service 级别的 netns 解析和注入

### 4. Proxy Chain 基础设施

完全复用：路由 → chain → hop → dialer → connector 管道无需任何修改。

---

## 方案对比

### 方案 A：Wirez 风格透明代理 — 新增 `usertun` Listener ⭐ 推荐

新增 listener 类型，在子进程中 spawn 目标程序（`CLONE_NEWUSER | CLONE_NEWNET`），子进程创建 TUN 并通过 Unix socket + `SCM_RIGHTS` 将 fd 传回父进程。父进程用 gVisor netstack 在 TUN 上处理 TCP/UDP，路由到 GOST proxy chain。

```
┌─ Parent (GOST, unprivileged host user) ───────────┐
│                                                     │
│  TUN fd ← SCM_RIGHTS ← Unix socket ← Child          │
│  gVisor netstack ← TUN                              │
│  TCP/UDP → GOST chain → SOCKS5/HTTP proxy           │
│                                                     │
└─────────────────────────────────────────────────────┘
          │ clone(CLONE_NEWUSER | CLONE_NEWNET)
          ▼
┌─ Child (new userns+netns, UID 0 inside) ───────────┐
│                                                     │
│  Creates /dev/net/tun                                │
│  Configures routing (default gw → TUN)              │
│  exec's target program                               │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**re-exec 核心代码示意：**

```go
// Parent: spawn child in new user+net namespace
socks, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
cmd := exec.Command("/proc/self/exe", "--gost-usertun-child", ...)
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
    UidMappings: []syscall.SysProcIDMap{
        {ContainerID: 0, HostID: os.Getuid(), Size: 1},
    },
    GidMappings: []syscall.SysProcIDMap{
        {ContainerID: 0, HostID: os.Getgid(), Size: 1},
    },
    GidMappingsEnableSetgroups: false,
}
cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(socks[1]), "tun-sock")}
cmd.Start()

// Receive TUN fd from child
oob := make([]byte, unix.CmsgSpace(4))
_, _, _, _, err := unix.Recvmsg(socks[0], nil, oob, 0)
// ... extract fd from SCM_RIGHTS control message
```

**可复用的已有代码：**

| 组件 | 文件 | 复用方式 |
|------|------|----------|
| TUN 设备创建 | `x/listener/tun/tun.go` (`createTunDevice()`) | 在子进程中调用 |
| gVisor netstack | `x/handler/tungo/` | 父进程中直接使用 |
| Proxy chain | `x/chain/`, `x/router/` | 无修改 |
| LockOSThread 模式 | `x/internal/net/dialer/dialer_netns.go` | 参考模式 |
| Netlink 路由配置 | `x/listener/tun/tun_linux.go` | 在子进程中调用 |

**需新增的代码（估算 ~400-600 行）：**

| 工作项 | 估算行数 |
|--------|----------|
| re-exec 入口点 (child mode handler in `cmd/gost/`) | ~50 |
| Namespace + TUN 创建 + 路由 (child side) | ~120 |
| Parent/child Unix socket + SCM_RIGHTS fd 传递 | ~60 |
| usertun listener (parent side, gVisor attachment) | ~150 |
| Metadata 解析 + config 定义 | ~80 |
| 错误处理 + 优雅关闭 + cleanup | ~80 |
| 非 Linux 平台 stub | ~40 |

**依赖变化：零新增依赖。** 所有需要的原语已在依赖树中：
- `golang.org/x/sys/unix` — `CLONE_NEWUSER`, `CLONE_NEWNET`, `SCM_RIGHTS`, `Recvmsg`
- `golang.zx2c4.com/wireguard/tun` — TUN 设备创建
- `github.com/vishvananda/netlink` — 地址/路由配置
- `gvisor.dev/gvisor/pkg/tcpip/stack` — userspace 协议栈（已在 tungo handler 中使用）

**复杂度：中等。** 核心挑战是进程管理和 fd 传递，不涉及 GOST 核心转发逻辑改动。

**平台限制：Linux only。**

---

### 方案 B：简单 User NS 包装器 — 新增 `userexec` Listener

不集成 TUN/gVisor。让 GOST 启动外部命令在 user+net namespace 中运行，GOST 在 namespace 内暴露一个 SOCKS5 listener，子进程通过该 listener 代理。

```
gost -L "userexec://?cmd=curl&listen=127.0.0.1:0"
                                            &proxy=socks5://127.0.0.1:1080"
```

GOST 在 namespace 内创建一个 SOCKS5 listener + handler，子进程通过环境变量 (`ALL_PROXY`) 或直接配置代理。

**改动量：~200-300 行**

**优点：** 实现简单，不影响现有架构
**缺点：** 
- 需要目标程序支持 SOCKS5/HTTP 代理（或 LD_PRELOAD），比不上 Wirez 的透明性
- 对于不支持代理的程序（Go 静态链接、某些 CLI 工具）无效
- 本质上只是 `unshare -Urn` + `proxy exec` 的包装

---

### 方案 C：GOST 自身沙箱化

将 GOST 拆分为特权 controller（处理 listener bind、TUN 创建）+ 非特权 worker（在 user namespace 中处理流量转发）。

**不推荐：** 改动范围太大（涉及核心生命周期重构），投入产出比不合理。作为安全加固方向可以在未来考虑，但不是 #652 的合理解决方案。

---

## 关键技术风险

| 风险 | 严重程度 | 缓解措施 |
|------|----------|----------|
| **Go #29789**: `Unshareflags` + `UidMappings` 组合在 `exec.Cmd` 中可能 `EPERM` | 中 | 使用 `Cloneflags` 而非 `Unshareflags`；此 bug 在 `exec.Cmd` 中已有 workaround |
| **`/dev/net/tun` 访问权限** | 低 | 子进程在 user ns 中是 UID 0，有 `CAP_NET_ADMIN`；`/dev/net/tun` 在内核中不检查 host UID |
| **gVisor netstack 性能** | 低 | `tungo` handler 已验证 gVisor 性能可接受；对日常使用足够 |
| **`/etc/subuid` 依赖** | 无 | 单 UID 映射 (`host_uid → ns_uid 0`) 不需要 `/etc/subuid` |
| **`setgroups` 限制** | 低 | `GidMappingsEnableSetgroups: false` 是 Go 1.7+ 的标准写法 |
| **User NS 嵌套** | 低 | 如果 GOST 本身在容器中运行（已有 user ns），嵌套创建需要内核支持（最大 32 层）；Linux 4.9+ 默认支持 |
| **re-exec 入口点** | 低 | 隐藏 CLI flag（`--gost-usertun-child`），不影响用户界面 |

---

## 不需要引入的库

以下库经过评估，**不建议引入**：

| 库 | 原因 |
|----|------|
| `github.com/opencontainers/runc/libcontainer` | 太重：~50+ 间接依赖（cgroups, seccomp, capabilities, apparmor, CRIU），只为 user+net ns 创建引入不划算 |
| `github.com/rootless-containers/rootlesskit` | 二进制导向架构（外部 `newuidmap`/`newgidmap`），不适合做 library |
| `github.com/v-byte-cpu/wirez` | 独立的命令行工具，不是 library |

---

## 实现路径建议

如果决定实现方案 A，分 3 个阶段：

### Phase 1: POC (~1-2 天)
- [ ] parent/child re-exec 框架（`cmd/gost/main.go` 中增加 `--gost-usertun-child` 隐藏 flag）
- [ ] 子进程中 user+net namespace 创建 + TUN 创建 + 路由配置
- [ ] Unix socket + SCM_RIGHTS fd 传递
- [ ] 父进程中 TUN fd → gVisor netstack → proxy chain 通路验证
- [ ] 非 root 用户端到端测试（如 `curl ifconfig.me` → SOCKS5 代理）

### Phase 2: 生产化 (~2-3 天)
- [ ] `usertun` listener 完整实现（metadata 解析、config 定义）
- [ ] 错误处理：子进程 crash、TUN 断开、namespace 清理
- [ ] 优雅关闭：SIGTERM → 子进程 cleanup → namespace 销毁
- [ ] DNS 在 namespace 内的处理（gVisor DNS resolver）
- [ ] 非 Linux 平台 stub（返回 "not supported"）

### Phase 3: 测试/文档 (~1 天)
- [ ] E2E 测试（Docker-based，参考 `gost/tests/e2e/`）
- [ ] `docs/issues/` 中配置文档
- [ ] 上游 issue 回复

---

## 需要修改的文件清单

### 新文件
- `x/listener/usertun/listener.go` — usertun listener（父进程侧，接收 TUN fd）
- `x/listener/usertun/listener_linux.go` — Linux 实现
- `x/listener/usertun/listener_other.go` — 非 Linux stub
- `x/listener/usertun/metadata.go` — metadata 解析
- `x/listener/usertun/conn.go` — TUN conn 包装
- `x/internal/net/userns/userns_linux.go` — user+net namespace 创建 + re-exec 逻辑
- `x/internal/net/userns/userns_other.go` — 非 Linux stub
- `gost/cmd/gost/usertun_child.go` — re-exec 子进程入口点

### 需要修改的已有文件
- `x/config/parsing/parse.go` — 新增 `MDKeyUserTun` metadata key
- `x/config/parsing/service/parse.go` — usertun 的 service 解析
- `x/config/config.go` — UserTun 相关 config struct（如需要）
- `gost/cmd/gost/main.go` — re-exec 入口分发
- `gost/cmd/gost/register.go` — 注册 usertun listener

### 不需要修改的文件
- `x/handler/tungo/` — 不做任何修改，直接复用
- `x/chain/`, `x/router/` — 不做任何修改
- `x/internal/net/dialer/` — 不做任何修改
- `core/` — 接口不变

---

## 结论

**可行性：高。** GOST 已有的 TUN + gVisor + proxy chain 架构天然适合 Wirez 风格的透明代理集成。User namespace 逻辑是完全隔离的"胶水代码"，不改动任何现有核心转发路径。

**集成复杂度：中等偏低。** 核心工作约 400-600 行新代码，零新增依赖，主要挑战是进程管理和 fd 传递。分为 3 个阶段，总计约 4-6 天工作量。

**建议：** 技术可行，值得列入 roadmap，但不急于实现。这个功能开启了"非 root 透明代理任意程序"的使用场景，对移动端/CI 环境/容器化部署有意义。可以等社区有更多需求信号时再推进实现。

---

## 附录：Windows 平台可行性研究

Linux user namespace 的核心价值是：**无需管理员权限，创建隔离的网络环境，使任意程序的流量可以被透明代理。** 在 Windows 上是否有等价机制？本节对此进行独立评估。

### Windows 与 Linux 的根本差异

| 概念 | Linux | Windows |
|------|-------|---------|
| Namespace 隔离 | 内核原生支持，非特权用户可创建 | 无等价概念 |
| 网络重定向 | `netns` + TUN + 路由表 | WFP / WinDivert / TUN（均需管理员） |
| 进程级代理 | `CLONE_NEWUSER` → 子进程隔离 | 无原生机制 |
| TUN 设备创建 | 非特权用户（在 user ns 内） | **始终需要管理员** |

**核心结论：Windows 不存在 Linux user namespace 的等价物。** 所有能实现"透明代理单个程序"的 Windows 机制都至少需要一次性管理员权限。

---

### Windows 透明代理技术全景

#### 方案 1：WinDivert（包级拦截 + 重定向）⭐ Windows 首选

WinDivert 是一个用户态包捕获/修改/重注入框架，内核驱动已签名预编译。

```
目标程序 → WinDivert.sys (内核) → Go 用户态程序 (godivert)
                                        │
                                  修改目标 IP → 127.0.0.1:proxy
                                        │
                                   GOST SOCKS5/HTTP 代理
                                        │
                                   GOST chain → 真实目标
```

| 属性 | 评估 |
|------|------|
| 管理员权限 | **需要**（安装驱动） |
| 单进程过滤 | ✅（`process.path = "C:\\...\\app.exe"`） |
| TCP 重定向 | ✅ |
| UDP 重定向 | ⚠️ 可能但复杂 |
| Go 库 | `github.com/yanlinLiu0424/godivert`, `github.com/imgk/divert-go` |
| 成熟度 | 高（ProxyBridge、Mullvad、SSTap 等均基于此） |
| 新增依赖 | `godivert` + `WinDivert64.sys`（预编译，~200KB） |

**GOST 集成方式：** 新增 `windivert` handler，监听 WinDivert 捕获的包，将 TCP SYN 目标改写为本机代理端口。参考实现：[ProxyBridge](https://github.com/InterceptSuite/ProxyBridge)（MIT，Go）。

**复杂度：中。** GOST 需要实现：WinDivert 会话管理 + 包解析/重写 + TCP 状态跟踪 + 代理转发。约 500-800 行新代码。

---

#### 方案 2：Wintun TUN + Route 重定向

GOST 已有完整的 Windows TUN 支持（`x/listener/tun/tun_windows.go`）。

| 属性 | 评估 |
|------|------|
| 管理员权限 | **需要**（创建网络适配器 + `netsh` 路由操作） |
| 单进程过滤 | ❌（路由表是系统级的） |
| TUN 创建 | ✅（已集成 `golang.zx2c4.com/wireguard/tun`） |
| gVisor netstack | ✅（`x/handler/tungo/` 已集成） |
| Go 库 | 全部已有 |

**限制：** Windows 没有 per-process 路由表。TUN 模式会将**整个系统**的流量（或在路由表中的特定 CIDR）导入代理，无法限制只代理单个进程。

**GOST 集成方式：** 完全不需新代码——`gost -L tun://` 在 Windows 上已经可以工作（以管理员权限运行）。

---

#### 方案 3：Wintun + WFP Callout（Mullvad 模式）— WinDivert 的主要竞争者

这是理论上最优、实践上最难的方案。核心思路：

**WFP callout 内核驱动在 `ALE_CONNECT_REDIRECT` / `ALE_BIND_REDIRECT` 层拦截特定进程的 socket 操作，将流量重定向到 Wintun 虚拟适配器。Wintun 上的 IP 包**保留原始目标地址**（因为重定向发生在 socket 层而非包层），GOST 已有的 TUN listener + gVisor netstack + proxy chain 直接处理，零新 handler 代码。**

```
目标进程调用 connect("example.com:443")
         │
         ▼
┌─ WFP Callout 内核驱动 ──────────────────────────────┐
│  ALE_CONNECT_REDIRECT_V4/V6                          │
│  ├─ 按 PID/进程名过滤                                │
│  ├─ 重定向 socket → Wintun 接口                     │
│  └─ 原始目标 IP 保持不变（socket 级操作）            │
└──────────────────────┬──────────────────────────────┘
                       │ TCP SYN dst=example.com:443
                       ▼
┌─ Wintun TUN 适配器 ─────────────────────────────────┐
│  IP 包: src=<app> dst=example.com:443 ← 目标完整保留 │
│  GOST TUN listener (已有)                            │
│  gVisor netstack (已有)                              │
│  GOST proxy chain (已有)                             │
└─────────────────────────────────────────────────────┘
```

**为什么这比 WinDivert 优雅：**

| 维度 | WFP Callout → Wintun | WinDivert |
|------|---------------------|-----------|
| **拦截层** | Socket 层（`connect()`/`bind()` 级别） | 包层（IP/TCP 头修改） |
| **原始目标** | 自然保留在 IP 头中 | 丢失，需映射表恢复 |
| **TCP 状态** | 内核处理，无需用户态跟踪 | 需用户态维护 TCP 状态机 |
| **校验和** | 无需修改 | 需重算 IP/TCP checksum |
| **UDP 支持** | ✅ 干净（BIND_REDIRECT + CONNECT_REDIRECT） | ⚠️ 复杂 |
| **GOST 代码复用** | ✅ 100%（TUN+gVisor+chain 不变） | ⚠️ ~50%（需新 handler） |
| **连接生命周期** | WFP 原生跟踪（connect/close 事件） | 用户态推断 |
| **递归重定向防护** | WFP 内置机制（`SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`） | 需手动维护排除列表 |

**但是——实现代价极其巨大：**

下面是 Mullvad [win-split-tunnel](https://github.com/mullvad/win-split-tunnel)（开源的 WFP callout 驱动，GPLv3/MPL-2.0）的工程复杂度分析：

| 维度 | 数据 |
|------|------|
| 语言 | C++ 94.2% + C 4.2%（非 C#/Rust/Go） |
| 类型 | 非 PnP KMDF 内核驱动 |
| 源文件 | 21 个根级文件 + 8 个 firewall/ 子系统文件 |
| 子系统 | 防火墙(WFP callout)、进程管理(完整进程树)、事件(用户态通信)、IOCTL 接口 |
| 驱动状态机 | STARTED → INITIALIZED → READY → ENGAGED（4 阶段 IOCTL 初始化） |
| WFP 层 | `ALE_CONNECT_REDIRECT_V4/V6`, `ALE_BIND_REDIRECT_V4/V6`, `ALE_AUTH_CONNECT_V4/V6`, `ALE_AUTH_RECV_ACCEPT_V4/V6` |
| 流量场景 | 9 种组合（IPv4/v6 × internet/tunnel 接口可用性） |
| 进程管理 | 系统范围进程创建/销毁通知 + 父子进程继承 |
| 事务系统 | 自定义并行事务系统（独立于 WFP 事务） |
| 构建环境 | Visual Studio 2022 + WDK v10.0.22621 + Windows SDK v10.0.22621（仅可在 Win10 2004+ 构建） |
| 代码签名 | EV 证书（$300-500/年）+ Microsoft 认证签名 |
| 用户态依赖 | 需要 agent 进程持续提供配置、监控网络接口变化 |
| Git 提交 | 205 commits |

**对 GOST 来说，实现一个 WFP callout 驱动的实际工作量估算：**

| 工作项 | 估算 |
|--------|------|
| WFP callout 驱动开发（C++） | 3-5 周（全职） |
| 进程管理子系统（PID/进程名过滤 + 父子继承） | 1-2 周 |
| IOCTL 接口 + 用户态 Go 控制库（CGO） | 1 周 |
| EV 签名 + Microsoft 认证签名 | 持续成本 |
| 驱动安装/卸载/升级逻辑 | 1 周 |
| 跨 Windows 版本兼容性测试（10/11/Server） | 1-2 周 |
| 调试和稳定性（内核崩溃 = BSOD） | 2-4 周 |
| 用户态 agent（网络变化监控 + 配置推送） | 1 周 |
| **总计** | **10-16 周 + 持续的签名费用** |

**结论：Wintun+WFP 在技术架构上明显优于 WinDivert，但实现代价完全不匹配 GOST 的投入规模。** 这条路线只有在以下场景才合理：(a) 商业化产品有专职 Windows 内核开发团队；(b) 可以 fork Mullvad win-split-tunnel 直接复用（但 Mullvad 的驱动是"排除进程出 VPN"方向，需要反转逻辑 + 仍然需要签名）。

**GOST 若选择此路线，最现实的方案是直接复用 Mullvad 驱动 + 反转过滤逻辑（从"排除"改为"包含"）**——但即使如此，仍需精通 Windows 内核开发的工程师，以及持续的代码签名费用。

---

#### 方案 4：API Hooking / DLL 注入

启动目标进程时注入 hook DLL，拦截 Winsock `connect()`/`WSAConnect()` 调用并重定向到本机代理。

| 属性 | 评估 |
|------|------|
| 管理员权限 | ⚠️ 不一定需要（注入自己启动的子进程通常可行） |
| 单进程过滤 | ✅（注入到目标进程内） |
| TCP 重定向 | ✅ |
| UDP 重定向 | ✅（hook `sendto()`/`recvfrom()`) |
| Go 实现 | 需要 CGO + 注入 DLL（C 编写） |
| 风险 | 杀软可能标记；32/64 位不匹配；对反注入保护的应用无效 |

参考：[ProxiGo](https://github.com/hypnguyen1209/proxigo)（Go 实现的 Detours 风格注入器）。

**复杂度：中高。** 需要维护注入 DLL（C 代码），且可靠性不如内核级方案。

---

#### 方案 5：AppContainer + 环境变量

Windows AppContainer 提供进程级安全隔离（UWP/IoT 使用），结合环境变量实现"受限代理"。

| 属性 | 评估 |
|------|------|
| 管理员权限 | **不需要** |
| 网络能力控制 | ✅（通过 Capability SID 限制 Internet/Private 访问） |
| 代理重定向 | ❌（只能 Allow/Deny，不能重定向） |
| 环境变量注入 | ✅（`HTTP_PROXY` 等） |

**限制：** AppContainer 不能重定向流量到代理。只能配合 `HTTP_PROXY` 环境变量使用（仅覆盖支持它的应用）。这不是透明代理方案。

---

#### 方案 6：Windows 容器 / HCS

Windows 容器（通过 `hcsshim` Go SDK）提供网络命名空间级别的隔离，等效于 Linux network namespace + user namespace。

| 属性 | 评估 |
|------|------|
| 管理员权限 | **需要**（启用 Containers 功能 + HCS 操作） |
| 网络隔离 | ✅（HCN/HNS 提供 network namespace 等效能力） |
| 代理策略 | ✅（`hcnproxyctrl` 支持 L4 WFP 代理策略） |
| Go SDK | ✅（`github.com/Microsoft/hcsshim`） |
| 开销 | 高（~200MB+ 基础镜像，秒级启动） |

**不推荐。** 开销太大，不适合"代理单个命令"的场景。

---

#### 方案 7：PAC / WinHTTP / WinINET 代理设置

| 属性 | 评估 |
|------|------|
| 管理员权限 | WinINET: 不需要（HKCU registry）。WinHTTP: 需要（HKLM）。 |
| 单进程过滤 | ❌（用户级或机器级全局设置） |
| 覆盖范围 | WinINET: IE + 使用 WinINET 的应用。WinHTTP: 服务/后台应用。均不覆盖直接使用 Winsock 的程序。 |

**不适合。** 既不能做到单进程，也不能覆盖所有应用。

---

### Windows 方案对比总表

| 方案 | 需要 Admin | 单进程代理 | 透明性 | TCP | UDP | 新代码 | 新依赖 |
|------|-----------|-----------|--------|-----|-----|--------|--------|
| **WinDivert** ⭐ | 一次性（驱动安装） | ✅ | ✅ | ✅ | ⚠️ | ~500-800行 | `godivert` |
| Wintun TUN | 每次运行 | ❌ | ✅ | ✅ | ✅ | 0 | 无 |
| Wintun + WFP | 每次运行 | ✅ | ✅ | ✅ | ✅ | ~1000行 | 内核驱动(C) |
| DLL 注入/Hooking | ⚠️ 不一定 | ✅ | ✅ | ✅ | ✅ | ~600行 | 注入DLL(C) |
| AppContainer | ❌ | ✅ | ❌ | N/A | N/A | ~200行 | 无 |
| Windows 容器 | 每次运行 | ✅ | ✅ | ✅ | ✅ | ~400行 | `hcsshim` (~10MB) |
| PAC/WinHTTP | ❌ | ❌ | ❌ | N/A | N/A | 0 | 无 |

---

### Windows 推荐方案：WinDivert

在 Windows 上实现 #652 的目标（透明代理单个程序），**WinDivert 是唯一在复杂度、可靠性、成熟度之间取得合理平衡的方案**。

**架构设计：**

```
gost -L "windivert://?process=chrome.exe&proxy=socks5://127.0.0.1:1080"
```

```
                    ┌──────────────┐
                    │ GOST Process  │
                    │              │
WinDivert64.sys ──→ │ godivert     │──→ TCP 状态跟踪
(kernel driver)     │ handler      │──→ 包重写(目标→127.0.0.1:proxy)
        ↑           │              │──→ 代理 SOCKS5/HTTP
  目标进程流量       │ local proxy  │──→ GOST proxy chain
 (chrome.exe)       └──────────────┘
```

**关键实现要点：**

1. **进程过滤：** WinDivert filter string `outbound and tcp and process.path = "C:\\...\\target.exe"`
2. **包重写：** 修改 TCP SYN 的 destination IP/port 为 `127.0.0.1:<proxy_port>`，重算 checksum
3. **原目标记录：** 在代理端通过自定义协议或 TPROXY 等价机制获取原始目标地址
4. **连接跟踪：** 维护 src_ip:src_port → original_dst 映射表
5. **DNS 劫持：** 拦截 UDP 53 的 DNS 请求，防止 DNS 泄漏

**与 Linux 方案的对比：**

| 维度 | Linux (usertun) | Windows (windivert) |
|------|----------------|---------------------|
| 权限模型 | 零特权（user ns 内 root） | 需要一次性管理员安装驱动 |
| 架构 | re-exec 子进程 + TUN fd 传递 | 内核驱动拦截 + 用户态包重写 |
| 代码量 | ~400-600 行 | ~500-800 行 |
| 新增依赖 | 零 | `godivert` (~3KB Go 代码) + `WinDivert64.sys` (~200KB) |
| 成熟度参考 | wirez, tun2socks, gVisor | ProxyBridge, Mullvad, SSTap |
| 平台 | Linux 3.8+ | Windows 7+ |

---

### 业界参考：SocksCap64 与 Netch 的进程流量代理原理

为了更全面地评估 Windows 上的技术选型，本节分析两个成熟的 Windows 进程代理工具的内部机制。

#### SocksCap64：Inline API Hook + 远程 DLL 注入

**主页：** https://www.sockscap64.com/

**核心原理：** SocksCap64 是经典的 Permeo SocksCap 的 64 位继任者，采用**用户态 Inline API Hook + 远程 DLL 注入**技术。

**架构流程：**

```
SocksCap64.exe (启动器)
    │
    │ CreateProcess + 远程 DLL 注入
    ▼
目标进程 (已注入 Hook DLL)
    │
    │ Hook ws2_32.dll 函数:
    │   connect(), send(), recv()
    │   WSASend(), WSARecv()
    │   sendto(), recvfrom()
    │   bind(), GetAddrInfoW()
    │
    │ 每次 connect() 被截获时:
    │   1. 记录原始目标地址
    │   2. 将目标改写为 127.0.0.1:<proxy_port>
    │   3. 完成 SOCKS5 握手（认证 + CONNECT）
    │   4. 所有 send()/recv() → 通过 SOCKS5 隧道中转
    ▼
SOCKS5 代理服务器
```

**技术细节：**

| 维度 | 说明 |
|------|------|
| Hook 方式 | **Inline Hook**（函数开头写入 `JMP <HookHandler>`，5 字节） |
| Hook 库 | 未公开（可能基于 Detours 或自研） |
| 注入方式 | 远程线程注入（`CreateRemoteThread` + `LoadLibrary`） |
| 目标进程 | 由 SocksCap64 启动的任意 Win32 程序 |
| 管理员权限 | 理论上不需要（注入自己启动的子进程），安装时可能需要 |
| 源码 | 闭源 |
| Go 绑定 | 无 |
| 稳定性 | 中低 — 侵入式注入可能被反作弊/杀软拦截 |
| 覆盖范围 | 所有使用 Winsock 的 Win32 应用；**不覆盖 UWP/Metro 应用** |

**Hook 过程（5 步）：**

1. `GetProcAddress` 获取 `ws2_32.dll` 中 `connect`/`send`/`recv` 等函数地址
2. 保存原始函数的前 N 字节指令（用于 trampoline 回调原始函数）
3. `VirtualProtect` 将函数地址页设为 `PAGE_EXECUTE_READWRITE`
4. 在函数开头写入 `JMP <HookHandler>`（E9 相对跳转，5 字节）
5. Hook Handler 中：判断是否代理 → 修改目标地址 → SOCKS5 握手 → 转发数据

**SocksCap64 vs Proxifier 差异：**

| | SocksCap64 | Proxifier |
|---|---|---|
| 技术 | Inline API Hook + DLL 注入 | Winsock LSP（Winsock SPI） |
| 机制 | 修改函数 prologue | 注册 Layered Service Provider |
| 稳定性 | 较低（侵入式注入） | 较高（使用官方 SPI 接口） |
| 反作弊对抗 | 容易被检测/拦截 | 兼容性更好 |
| 现状 | 已停止更新 | 持续维护 |
| 64 位支持 | 原生支持 | 原生支持 |

**对 GOST 的参考价值：** 
- ✅ 验证了 "拦截 Winsock → 改写目标 → SOCKS5 转发" 模式的有效性
- ✅ 不需要内核驱动，不强制需要管理员权限
- ❌ DLL 注入本身可靠性低，对 GOST 这种网络工具不适用
- ❌ 注入 DLL 需要 C 编写，Go 无法直接实现

---

#### Netch ProcessMode：内核级包过滤 (netfilter2) + 用户态重定向

**主页：** https://github.com/BoyceLig/Netch | **许可：** GPLv3

**核心原理：** Netch 的 `ProcessMode` 使用 **ntkernel.com netfilter2 SDK**（商业内核驱动）+ **用户态 Redirector DLL**（C++），实现进程级 TCP/UDP 流量拦截和 SOCKS5 重定向。

**架构流程：**

```
┌─ Netch.exe (C# / .NET) ──────────────────────────┐
│                                                     │
│  P/Invoke → Redirector.bin (C++ DLL)               │
│  ├─ aio_init()        初始化                        │
│  ├─ aio_register()    注册进程过滤规则              │
│  └─ aio_dial()        配置代理目标                  │
│                                                     │
│  Redirector DLL:                                    │
│  ├─ nf_init()         注册 netfilter2 驱动          │
│  ├─ nf_registerDriver()                             │
│  ├─ nf_addRule()      安装过滤规则                  │
│  └─ NF_EventHandler 回调:                           │
│      ├─ tcpConnectRequest  ← 内核拦截 TCP 连接      │
│      ├─ tcpSend / tcpReceive                         │
│      ├─ udpCreated / udpSend / udpReceive            │
│      └─ tcpClosed / udpClosed                        │
│                                                     │
│  TCPHandler (用户态):                                │
│  ├─ 本地 TCP listener (127.0.0.1:<port>)            │
│  ├─ CreateHandler(client, original_dst) 映射表       │
│  └─ Handle() → SocksHelper::TCP → SOCKS5            │
│                                                     │
└─────────────────────────────────────────────────────┘
         │ nf_registerDriver (ioctl)
         ▼
┌─ netfilter2.sys (内核驱动, ntkernel.com) ──────────┐
│  拦截 TCP connect request (NDIS/WFP 层)             │
│  按 PID/进程名过滤                                   │
│  将包信息回调到用户态                                │
└─────────────────────────────────────────────────────┘
```

**关键源码文件（基于 GitHub 仓库分析）：**

| 文件 | 作用 |
|------|------|
| `Redirector/Redirector.cpp` | DLL 入口，初始化 netfilter2 |
| `Redirector/EventHandler.cpp` | `tcpConnectRequest` 等回调实现 |
| `Redirector/TCPHandler.cpp` | 本地 TCP 监听 + 连接映射表 |
| `Redirector/SocksHelper.cpp` | SOCKS5 握手 + 认证 + CONNECT/UDP ASSOCIATE |
| `Redirector/DNSHandler.cpp` | DNS 劫持/重定向 |
| `Netch/` (C#) | 主程序，P/Invoke 调用 Redirector.bin |
| `RouteHelper/` | 辅助路由工具 |

**TCP `tcpConnectRequest` 重定向流程（基于 EventHandler.cpp 源码）：**

```cpp
void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO info) {
    // 1. 自过滤：不拦截 redirector 自身的流量
    if (CurrentID == info->processId) return;

    // 2. 进程名过滤：检查 bypassList 和 handleList
    if (checkBypassName(info->processName)) return;   // 白名单跳过
    if (!checkHandleName(info->processName)) return;   // 不在代理列表中

    // 3. 记录原始目标地址
    SOCKADDR_IN6 client, remote;
    memcpy(&client, &info->localAddress, sizeof(client));
    memcpy(&remote, &info->remoteAddress, sizeof(remote));

    // 4. 改写连接目标 → 本机 SOCKS 端口
    // IPv4: info->remoteAddress = 127.0.0.1:tcpListen
    // IPv6: info->remoteAddress = ::1:tcpListen

    // 5. 建立映射表：client_addr → original_remote
    TCPHandler::CreateHandler(client, remote);
}
```

**技术总结：**

| 维度 | 说明 |
|------|------|
| 拦截层 | **内核级**（netfilter2 NDIS/WFP 驱动） |
| 用户态组件 | Redirector.bin (C++ DLL)，C# P/Invoke 调用 |
| 进程过滤 | 驱动层按 PID + 进程名匹配 |
| TCP 重定向 | 内核拦截 connect → 改写目标 → 本地 listener → SOCKS5 |
| DNS 处理 | DNSHandler 劫持 DNS 查询 |
| 管理员权限 | **必须**（内核驱动安装 + 运行） |
| 源码 | C++/C# 部分 GPLv3 开源；netfilter2 驱动是商业闭源 |
| Go 绑定 | **无**（netfilter2 SDK 提供 C API，可理论上通过 CGO 调用） |
| 稳定性 | 高（内核级拦截比用户态 DLL 注入可靠） |

**Netch 的 4 种模式对比：**

| 模式 | 技术 | 粒度 | Admin |
|------|------|------|-------|
| **ProcessMode** | netfilter2 内核驱动 | 单进程 | 必须 |
| **ShareMode** | WinPcap/Npcap | 系统级（共享） | 必须 |
| **TunMode** | WinTUN 驱动 | 系统级 | 必须 |
| **WebMode** | HTTP 代理 | 应用层（需应用支持） | 不需要 |

---

### Wintun+WFP vs WinDivert — 深度对比

#### 架构差异的本质

这两种方案的**根本区别**在于流量拦截的层级：

```
Wintun+WFP (socket级)：                 WinDivert (包级)：

connect("example.com")                  connect("example.com")
       │                                       │
   [WFP callout]                          [WinDivert driver]
   改 socket 路由到 TUN                    捕获 TCP SYN 包
       │                                       │
   TCP SYN: dst=example.com              改包: dst=127.0.0.1:proxy
   原始目标在 IP 头中!                         │
       │                                  TCP SYN: dst=127.0.0.1
   [GOST TUN listener]                   原始目标丢失!
       │                                       │
   [gVisor netstack]                     [自定义 handler]
   TCP 协议栈自然处理                    SOCKS5 握手 + dst 恢复
       │                                       │
   [GOST proxy chain]                    [GOST proxy chain]
       │                                       │
   → example.com:443                     → example.com:443
```

#### 逐项对比

| 评估维度 | Wintun+WFP Callout | WinDivert | 优势方 |
|----------|-------------------|-----------|--------|
| **原始目标保留** | ✅ IP 头自然保留 | ❌ 需映射表/编码恢复 | WFP |
| **TCP 处理** | ✅ gVisor 协议栈 | ⚠️ 手动 checksum + 状态跟踪 | WFP |
| **UDP 处理** | ✅ WFP bind/connect redirect | ⚠️ 无连接语义，复杂 | WFP |
| **连接生命周期** | ✅ WFP 原生 connect/close 事件 | ⚠️ 用户态推断 | WFP |
| **DNS 处理** | ✅ gVisor DNS resolver | ⚠️ 需独立 DNSHandler | WFP |
| **递归重定向防护** | ✅ WFP `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` | ⚠️ 手动排除本地代理端口 | WFP |
| **GOST 代码复用** | ✅ 100%（TUN+gVisor+chain 零修改） | ⚠️ ~50%（需新 handler + 协议） | WFP |
| **驱动依赖** | ❌ 需自写内核驱动 (C++) | ✅ WinDivert64.sys 已存在 | **WinDivert** |
| **驱动签名** | ❌ EV 证书 + MS 认证 ($300-500/年) | ✅ 已签名 | **WinDivert** |
| **开发语言** | ❌ C++ (KMDF 内核驱动) | ✅ Go (`godivert`) | **WinDivert** |
| **开发工作量** | ❌ 10-16 周 + 内核调试 | ✅ 1-2 周 | **WinDivert** |
| **维护负担** | ❌ 跨 Win10/11/Server 兼容性 + BSOD 风险 | ✅ 上游维护驱动 | **WinDivert** |
| **Go 生态** | ❌ 无 Go 库，需 CGO 封装 | ✅ `godivert` 成熟 | **WinDivert** |
| **构建环境** | ❌ VS2022 + WDK + WinSDK（仅 Win10 2004+ 可构建） | ✅ `go build` | **WinDivert** |
| **开源参考** | Mullvad win-split-tunnel (C++, 205 commits) | ProxyBridge (Go, MIT) | **WinDivert** |

#### 结论

**Wintun+WFP 在技术架构上全面优于 WinDivert**（socket 级重定向 + 原始目标保留 + 100% 复用 GOST 已有 TUN 代码），但**实现代价完全不匹配 GOST 的投入规模**。

| | Wintun+WFP | WinDivert |
|---|---|---|
| 技术优雅度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| 实现可行性（对 GOST） | ⭐ | ⭐⭐⭐⭐⭐ |
| 投入产出比 | ⭐ | ⭐⭐⭐⭐ |

**WinDivert 仍然是 GOST 在 Windows 上唯一实际可行的单进程透明代理方案。** Wintun+WFP 在以下条件同时满足时才有意义：
1. 有专职 Windows 内核开发工程师
2. 愿意持续支付 EV 代码签名费用
3. 愿意承担跨 Windows 版本的内核兼容性维护

对于 GOST 这样以 Go 为主的社区驱动项目——WinDivert 是正确选择。

---

### Windows 三种技术路线对比

综合 SocksCap64、Netch、Wintun+WFP、WinDivert 的分析，Windows 上实现单进程透明代理的路径：

| | **SocksCap64** | **Netch** | **Wintun+WFP** | **WinDivert** ⭐ |
|---|---|---|---|---|
| **技术** | Inline Hook + DLL 注入 | netfilter2 商业驱动 | WFP Callout 驱动 + Wintun | WinDivert 开源驱动 |
| **拦截层** | 用户态（函数 hook） | 内核态（NDIS/WFP） | 内核态（WFP socket 重定向） | 内核态（WFP 包捕获） |
| **Go 集成** | ❌（需 C 注入 DLL） | ❌（商业驱动 + C API） | ❌（需写 C++ 内核驱动） | ✅（`godivert` Go 库） |
| **开源** | 闭源 | 半开源（驱动商业） | Mullvad 参考（GPLv3） | 开源（GPLv3+MIT） |
| **Admin** | ⚠️ 不必要 | 必须 | 必须 | 一次性驱动安装 |
| **可靠性** | 中低（注入易被拦截） | 高 | 高 | 高 |
| **原始目标保留** | ✅（hook 参数） | ✅（内核提供） | ✅（IP 头自然保留） | ❌（需映射表） |
| **GOST 代码复用** | 低 | 低 | ✅ 100%（TUN+gVisor 零改动） | 中（需新 handler） |
| **开发量** | 高（注入 DLL） | 中高（商业授权） | **极高（10-16周+签名费）** | 中（~500-800行Go） |
| **维护** | 高 | 中高 | **极高（内核跨版本）** | 低（上游维护） |
| **GOST** | 不推荐 | 不推荐（商业驱动） | 技术最优，实践不现实 | ⭐ 唯一可行 |

**结论：WinDivert 仍然是 GOST 在 Windows 上的唯一实际可行方案。** Wintun+WFP 在技术架构上更优（socket 级重定向保留原始目标、100% 复用 GOST TUN+gVisor 代码），但实现代价（自写 C++ 内核驱动 + EV 签名费 + 跨版本兼容维护）与 GOST 的投入规模完全不匹配。

- SocksCap64 路线：Go 不能写注入 DLL，排除
- Netch 路线：netfilter2 是商业闭源驱动，排除
- **Wintun+WFP 路线：技术架构最优，但需 10-16 周 C++ 内核开发 + 持续签名费，对社区项目不现实**
- **WinDivert 路线：技术上不如 WFP 优雅，但是唯一开源+Go 可集成的方案**

---

### WinDivert UDP 可靠性深度分析

WinDivert 对 TCP 的支持相对成熟（有连接的语义、可以可靠地重写 SYN 目标地址、通过 ACK/FIN 跟踪生命周期），但 **UDP 的支持有一系列架构层面的限制**，直接影响 GOST 集成的可行性。

#### 核心矛盾：SOCKET 层 vs NETWORK 层

这是 WinDivert 最根本的问题，源于 WFP 内核框架的设计：

| 层 | 进程 ID 可用 | 包数据正确 | 用途 |
|-----|------------|-----------|------|
| `WINDIVERT_LAYER_SOCKET` | ✅ `processId` 可用 | ❌ 包数据**损坏/丢失** | 仅能获取进程关联，不能用于数据捕获 |
| `WINDIVERT_LAYER_FLOW` | ✅ `processId` 可用 | ❌ 包数据**损坏/丢失** | 同上 |
| `WINDIVERT_LAYER_NETWORK` | ❌ `processId = 0` | ✅ 完整正确的 IP 包 | 可用于数据捕获，但**不能按进程过滤** |

**根因**（来自 WinDivert 作者）：WFP 的 NETWORK/IPPACKET 层在内核中**不携带 ProcessId**——这不是 WinDivert 的 bug，而是 WFP 框架的设计限制。SOCKET/FLOW 层有进程信息，但 WinDivert 在这两层捕获的包数据不包含可解析的 IP/TCP/UDP 头。

来源：[basil00/WinDivert#382](https://github.com/basil00/WinDivert/issues/382), [basil00/WinDivert#71](https://github.com/basil00/WinDivert/issues/71)

#### 唯一可行的 workaround：双 Handle + 5-tuple 映射

所有基于 WinDivert 的透明代理工具（Tallow、zapret/winws、ProxyBridge）的通用做法：

```
┌─ Handle 1: SOCKET 层 ────────────────────────┐
│  Filter: "processId != 0"                     │
│  目的: 仅用于建立 5-tuple → PID 映射表         │
│  (数据损坏不关心，只要事件到达即可)             │
│                                                │
│  g_pidMap[(proto, srcIP, srcPort,              │
│            dstIP, dstPort)] = processId        │
└────────────────────────────────────────────────┘
         │ 共享映射表 (mutex + cv)
         ▼
┌─ Handle 2: NETWORK 层 ───────────────────────┐
│  Filter: "outbound && udp"                    │
│  目的: 捕获正确的 UDP 包                       │
│  每个包: 提取 5-tuple → 查映射表 → 决定放行/拦截│
└────────────────────────────────────────────────┘
```

**但这个架构有三个不可消除的固有问题：**

**问题 1：竞态条件 (Race Condition)**

NETWORK 层包可能**先于** SOCKET 层事件到达。没有顺序保证。

缓解方案：
- 对未命中映射的包做**排队等待**（典型超时 2-5 秒）
- 超时后如果仍无映射，**丢弃该包**（首包丢失）
- 这意味着 UDP 应用的**第一个数据包可能被静默丢弃**

**问题 2：UDP 是无连接的 — 映射表管理远比 TCP 复杂**

| | TCP | UDP |
|---|---|---|
| 生命周期事件 | SYN → 已连接 → FIN/RST | **无** |
| 映射何时建立 | connect 前即可获得 | 第一个 sendto() 后 |
| 映射何时释放 | close/fin 事件明确可知 | **无法确定**（socket 可能一直复用） |
| 端口复用 | 简单（TIME_WAIT 后不可复用） | 同一个 socket sendto 到**不同目标**可能复用端口 |
| 映射表增长 | 可控（一个连接一条记录） | 不可控（一个 socket 可能有 N 条记录） |

对于 UDP，如果程序创建了一个 socket 并 sendto 到 100 个不同目标，映射表需要 100 条记录。且无法知道程序何时不再向某个目标发送数据。

缓解方案（ProxyBridge 的做法）：
- 通过 `GetExtendedUdpTable` 轮询当前 UDP 绑定关系，作为补充
- 设置较短的 TTL（~30s），超时未使用则清除映射

**问题 3：SOCKET 层可能不触发 UDP 事件**

WinDivert SOCKET 层的 `WINDIVERT_EVENT_SOCKET_BIND` 和 `WINDIVERT_EVENT_SOCKET_CONNECT` 事件主要针对 TCP 设计。UDP 的 `bind()`/`connect()`（若存在）触发的事件覆盖率不可靠。对于无连接的 `sendto()`，SOCKET 层可能**完全不产生事件**。

这意味着某些 UDP 应用的 5-tuple → PID 映射**永远无法建立**。

#### WinDivert UDP 已知问题清单

| 问题 | 严重度 | 缓解措施 | 来源 |
|------|--------|----------|------|
| **SOCKET 层包数据损坏** | 🔴 致命 | 双 handle 架构 | [#382](https://github.com/basil00/WinDivert/issues/382) |
| **NETWORK 层无 processId** | 🔴 致命 | 双 handle + 5-tuple 映射 | [#71](https://github.com/basil00/WinDivert/issues/71) |
| **NETWORK 与 SOCKET 层竞态** | 🟠 高 | 包排队 + 超时（首包可能丢） | 通用架构问题 |
| **DHCP/广播 UDP 丢失** | 🟠 高 | Filter 排除广播 IP | [mitmproxy#6902](https://github.com/mitmproxy/mitmproxy/issues/6902) |
| **多播包重复** | 🟡 中 | 跳过 Loopback=1 的包 | [#364](https://github.com/basil00/WinDivert/issues/364) |
| **校验和 offload 冲突（VM）** | 🟡 中 | 禁用网卡 checksum offload | Xen ML |
| **DontFragment 标志干扰** | 🟡 中 | 无已知 fix | [#278](https://github.com/basil00/WinDivert/issues/278) |
| **高负载下队列断开** | 🟡 中 | 保护性队列大小限制 | 文档 |
| **包重排序** | 🟡 中 | 无（WinDivert 本身会引入） | 文档 |
| **PID 过期/无效** | 🟡 中 | TTL 缓存 | SO |

#### 业界工具的实际 UDP 支持情况

| 工具 | UDP 支持 | 实际策略 | 可靠性 |
|------|----------|----------|--------|
| **ProxyBridge** | 声称支持 | 双 handle + GetExtendedUdpTable 轮询 | ⚠️ DNS 单独处理，警告"大多数 SOCKS5 代理不支持 UDP" |
| **Netch ProcessMode** | 声称支持 | netfilter2 商业驱动（内核级 udpCreated/udpSend 回调） | ✅ 高（商业驱动，socket 级拦截） |
| **SocksCap64** | 声称支持 | Hook sendto/recvfrom | ⚠️ 中（用户态 hook，覆盖不全） |
| **Clash Verge/Mihomo** | 部分支持 | TUN 模式（系统级，不走 WinDivert） | ✅ 高（TUN 模式绕过 WinDivert） |
| **Tallow (Transparent Tor)** | ❌ TCP only | 明确只支持 TCP | N/A |

#### 对 GOST 集成的具体影响

如果 GOST 采用 WinDivert 实现 Windows 透明代理，UDP 的可靠性边界如下：

**可以可靠支持的场景：**
- ✅ TCP 所有流量（有连接 + 生命周期清晰 + 映射表可靠）
- ✅ DNS UDP（端口 53，单独处理，不改写目标，仅劫持响应）
- ⚠️ "典型" UDP 应用（使用 connected UDP socket 的应用，如 QUIC/HTTP3）

**不可靠/不支持的场景：**
- ⚠️ 无连接 UDP (sendto 到多目标，映射表爆炸)
- ⚠️ 高频 UDP（游戏、VoIP，包重排序和延迟不可预测）
- ⚠️ 广播/多播 UDP（DHCP、mDNS、SSDP）
- ❌ 依赖精确 `processId` 的 UDP 过滤（5-tuple 映射可能永远无法建立）

**实用建议：** GOST 的 WinDivert handler 应该默认只处理 TCP，UDP 支持作为**实验性功能**（opt-in flag），并明确文档化限制。

#### 与 Linux usertun 方案的对比

| | Linux usertun (user ns) | Windows WinDivert |
|---|---|---|
| TCP | ✅ 内核协议栈 (gVisor) | ✅ 可接受 |
| UDP | ✅ 内核协议栈 (gVisor) | ⚠️ 有限制 |
| 原始目标 | ✅ IP 头保留 | ❌ 需映射（TCP 还算可靠，UDP 不可靠） |
| 进程隔离 | ✅ 完全（独立 netns） | ⚠️ 基于 5-tuple 推断 |
| 实现复杂度 | TUN+gVisor (已有) | 自定义 handler (~500 行) |

这也又一次说明：**Linux usertun 方案在架构上远优于 Windows 上的任何方案**（包括 WinDivert）。

---

### Windows 额外发现：GOST 现有能力

GOST 在 Windows 上已有以下可用的透明代理能力（均需管理员）：

1. **`gost -L tun://`** — TUN 模式，通过 Wintun 创建虚拟网卡，系统级透明代理。**无需新代码，已可用。**
2. **`gost -L tap://`** — TAP 模式，通过 OpenVPN TAP 驱动。同上。
3. **`gost -L tun://` + `gost -L tungo://`** — TUN + gVisor netstack，更完整的协议栈支持。

限制：这些是**系统级**透明代理，不是 Linux user namespace 的**单进程**透明代理。

---

### Windows 结论

**可行性：有条件可行。** 在 Windows 上不存在 Linux user namespace 的非特权等价物。实现"透明代理单个程序"需要内核级拦截（WinDivert 或 WFP callout），均需要一次性管理员权限安装驱动。

**推荐路径：**
1. **如果需要管理员权限可接受：** 实现 `windivert` handler（新代码 ~500-800 行），基于 `godivert` + 已有的 proxy chain。**TCP 支持可靠，UDP 应作为实验性 opt-in 功能。**
2. **如果要求零管理员权限：** 不可行。退而求其次的方案是环境变量注入（`HTTP_PROXY`）+ AppContainer 网络限制，仅覆盖尊重代理环境变量的应用。
3. **如果只需系统级透明代理：** GOST 现有 `tun://` listener 在 Windows 上已可用（需管理员运行）。TUN 模式走 gVisor netstack，**TCP/UDP 均可靠**——缺点是系统级而非单进程。

**建议：** Windows 的 WinDivert 方案可以作为 Linux usertun 方案的后续补充（Phase 2），但不作为 #652 的核心交付。Issue #652 应以 Linux user namespace 方案为主。
