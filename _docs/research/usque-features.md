# usque 库功能全解：能力清单、抗封锁机制与端点说明

> 调查日期：2026-10-25。方法：以本地源码（`D:\Dev\Github\OpenCode\usque-android`，fork 基线 + 本地改动）为一手来源，与上游最新版克隆（`usque-upstream`，github.com/Diniboy1123/usque）交叉比对；协议背景引用作者自己的逆向笔记 `RESEARCH.md` 和 warpscout v0.16.1 源码。**每条论断都标注了出处**；未能核实的明确标注。
>
> 引用约定：`路径:行号` 指 fork 仓库内文件；`upstream: 路径:行号` 指上游克隆内文件；`warpscout: 文件` 指 warpscout v0.16.1 源码。

---

## 1. 一页总览

usque 是 Cloudflare WARP 的**第三方非官方客户端库 + CLI**，实现的是 WARP 的 **MASQUE 隧道**（HTTP/3 上的 CONNECT-IP，见 RFC 9484），把整台设备的流量装进一条"看起来像浏览器访问 Cloudflare 的 HTTPS"的 QUIC 连接里。作者在 RESEARCH.md 中记录了对官方客户端（libwarp_mobile.so）的逆向过程（RESEARCH.md:23-297），usque 是其可用的开源复现。

与 WARP 的另一种协议 **WireGuard** 的关系：注册接口是同一个（POST /reg，`internal/consts.go:4-14`），但 MASQUE 需要在注册后再"换钥匙"为 ECDSA（`api/cloudflare.go` EnrollKey），WireGuard 设备则直接用 curve25519。一个 Cloudflare 设备同一时间只有一种钥匙类型（`models/register.go` 的 Registration.KeyType/TunType）。

---

## 2. CLI 子命令全解（上游最新版）

| 命令 | 作用 | 本地 fork | 上游引用 |
|---|---|---|---|
| `register` | 注册新 WARP 账号并 enroll MASQUE 密钥，生成 config.json | ✅ 有 | `upstream: cmd/register.go:119` |
| `enroll` | 单独换 MASQUE 私钥/改设备名（-r 重新生成密钥）。上游注释：对 ZeroTier 场景有用（IPv6 地址会变） | ✅ 有 | `upstream: cmd/enroll.go:19,131` |
| `socks` | 在本地开 **SOCKS5 代理**，流量走 MASQUE 隧道（gVisor netstack 用户态协议栈，**不需要 TUN/管理员权限**） | ✅ 有 | `upstream: cmd/socks.go:321` |
| `httpproxy` | 同上，开 **HTTP 代理** | ✅ 有 | `upstream: cmd/httpproxy.go:453` |
| `nativetun` | 创建真正的 TUN 网卡做全局 VPN（Linux/Windows 实现），默认配置 IP 和路由 | ✅ 有 | `upstream: cmd/nativetun.go:245` |
| `portfw` | **端口转发**：SSH 风格的 `-L 本地端口转发` 和 `-R 远程端口转发`（如 `localhost:8080:100.96.0.2:8080`），把隧道内/外的 TCP 服务映射出来 | ✅ 有 | `upstream: cmd/portfw.go:422,404-405` |
| `account` | 账号管理：`info`（账号信息）、`set`/`reset`（license key 操作）、`devices`（设备列表/管理） | ❌ 本地没有 | `upstream: cmd/account.go:199-203` |
| `l4-socks` | **L4 TCP-only SOCKS5 代理**：不走 netstack，直接用 HTTP/3 CONNECT 流拨号 TCP。上游注释："Doesn't require elevated privileges" | ❌ 本地没有 | `upstream: cmd/l4_socks.go:11-13,48` |
| `l4-http-proxy` | 同 l4-socks 的 HTTP 代理版 | ❌ 本地没有 | `upstream: cmd/l4_http_proxy.go:151` |
| `version` | 版本号 | ✅ 有 | `upstream: cmd/version.go:26` |

### 共用的连接参数（socks/httpproxy/nativetun/portfw 四个隧道命令几乎一致）

全部见 `upstream: cmd/socks.go:298-320`（其余命令同款）：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-P, --connect-port` | 443 | MASQUE 连接用的 UDP 端口 |
| `-s, --sni-address` | `consumer-masque.cloudflareclient.com` | **TLS SNI 伪装目标**（见 §4.2） |
| `-6, --ipv6` | false | 用 IPv6 端点连接 |
| `-F/-S, --no-tunnel-ipv4/6` | false | 隧道内禁用 v4/v6（单栈） |
| `-k, --keepalive-period` | 30s | QUIC keepalive 周期 |
| `-m, --mtu` | 1280 | 隧道 MTU |
| `-i, --initial-packet-size` | 自动（PMTU 探测） | **QUIC 首包大小**（见 §4.4） |
| `-r, --reconnect-delay` | 1s | 断线重连间隔 |
| `--always-reconnect` | false | 空闲断线也重连 |
| `--http2` | false | **HTTP/2 回退**（见 §4.6） |
| `--insecure` | false | **关闭证书钉死**（见 §4.3） |
| `-l/--local-dns`, `--system-dns` | false | DNS 解析位置（防泄漏/兼容性） |
| `--on-connect/--on-disconnect` | — | 连接/断开钩子脚本，上下文通过 `USQUE_*` 环境变量传入 |

`register` 参数：`-l locale -m model -n name --jwt <ZeroTrust团队token> -a`（`upstream: cmd/register.go:114-118`）；`enroll` 参数：`-n -r`（`upstream: cmd/enroll.go:129-130`）。

---

## 3. config.json 字段表

本地 fork 的 schema（`config/config.go:14-35`）：

| 字段 | 含义 | 引用 |
|---|---|---|
| `private_key` | MASQUE 设备 ECDSA P-256 私钥（base64 DER） | config.go:15 |
| `endpoint_v4` / `endpoint_v6` | MASQUE 连接端点 IP（注册响应里来） | config.go:16-17 |
| `endpoint_pub_key` | 端点 ECDSA 公钥（PEM），用于**钉死服务端身份** | config.go:18 |
| `license` / `id` / `access_token` | WARP+ 许可证、设备 ID、API token | config.go:19-21 |
| `ipv4` / `ipv6` | 隧道内分配的地址 | config.go:22-23 |
| `wg_*`（7 个字段） | **本地新增**：WireGuard 设备的私钥/对端公钥/端点/隧道地址 | config.go:25-31 |
| `endpoint_h2_v4` / `endpoint_h2_v6` | HTTP/2 模式专用端点 | **仅上游**：`upstream: config/config.go:18-19` |

注册响应里 `config.peers[0]` 携带 `endpoint.host`（域名）、`endpoint.v4/v6`（含端口的地址）、`endpoint.ports[]`（官方客户端使用的端口列表）、`public_key`（对端公钥），见 `models/register.go` Peer 结构。

---

## 4. 抗封锁机制逐条（本文核心）

### 4.1 连接伪装的本质：整个 VPN 藏在一次"HTTPS"里

MASQUE 模式下，客户端与 Cloudflare 建立的是一条标准 QUIC/HTTP-3 连接，在里面发 `CONNECT IP`（RFC 9484）请求建立 IP 隧道。对审查设备来说，这**就是一个普通的 QUIC HTTPS 会话**——QUIC 首包之后一切加密，没有明文协议特征。这是它比 WireGuard 抗封的根本原因：WG 的 UDP 握手有固定的明文 Cookie/Init 包特征，DPI 可识别并可整协议封杀。作者对官方客户端的逆向确认了同一实现（RESEARCH.md:67-141「TLS Authentication / QUIC / Connect-IP」）。

### 4.2 SNI 伪装——为什么可以随便报

QUIC 握手里的 TLS ClientHello 携带 SNI（服务器名指示），审查设备常靠它判断"你在访问谁"。usque 的三个相关常量（`internal/consts.go:6-8`）：

- `ConnectSNI = "consumer-masque.cloudflareclient.com"` —— 默认 SNI（`upstream: cmd/socks.go:308` 的 -s 默认值）；
- `L4ConnectSNI = "consumer-masque-proxy.cloudflareclient.com"` —— 上游 L4 代理专用（`upstream: internal/consts.go:7`）；
- `ZeroTierSNI = "zt-masque.cloudflareclient.com"` —— **预留未实装**（`internal/consts.go:8` 注释 "unused for now"）。

**SNI 可以任意伪造的原因**：连接目标是裸 IP（`endpoint_v4`），TLS 客户端证书由我们自己生成（自签、无 CA 链，`internal/utils.go:106-117` GenerateCert），服务端的身份靠**钉死注册时下发的对端 ECDSA 公钥**来验证（`config/config.go:104-120` GetEcEndpointPublicKey + `api/masque.go:31-91` PrepareTlsConfig 的 VerifyPeerCertificate）——**根本不做域名-证书匹配**。所以 SNI 报什么完全自由：报 `www.visa.cn`（App 的默认值）、报任何未被封的域名，都能通过 DPI 的 SNI 白名单/黑名单检查，而 Cloudflare 照样按公钥识别你是哪个 WARP 设备。

### 4.3 客户端证书 = 身份；`--insecure` 是什么

MASQUE 的认证 = 注册时 PATCH 上去的 ECDSA 公钥（`api/cloudflare.go` EnrollKey）。每次连接用对应私钥自签一张 24 小时证书呈给服务端（`internal/utils.go:106`，warpscout 的 masque.go 也复刻了此流程并注释"Cloudflare 从不签名客户端证书，认证全靠 enroll"）。上游新增 `--insecure`（`upstream: cmd/socks.go:316`）会**取消对端公钥钉死**——正常抗封锁场景不该用，它是给自建/测试网关准备的。

### 4.4 QUIC 参数的讲究

`internal/utils.go:127-149` DefaultQuicConfig：`EnableDatagrams: true`（CONNECT-IP 需要）、`InitialPacketSize` 可指定——**1242 字节是官方客户端的取值**（utils.go:123 注释），首包大小是抗封锁的重要旋钮：部分网络按 QUIC 首包尺寸/速率限速或丢弃，调小首包可改善连通性（上游默认改为 PMTU 自动探测，`upstream: cmd/socks.go:311`）。本地 fork 还记录了一条教训：收紧 QUIC 流控窗口会导致 WARP 网关握手后 stall（utils.go:132-147 注释），内存调优只能做在运行时层，不能动协议参数。

### 4.5 端点与端口的自由度

- `-P` 端口：MASQUE 服务在 `443, 500, 1701, 4500, 4443, 8443, 8095` 都有监听（官方下发列表，warpscout: masque.go `masqueEndpointPorts`）；被墙网络可以逐个试。
- 端点地址：config.json 的 `endpoint_v4/v6` 可改成任意 IP（App 的 SetEndpoint 同理）。MASQUE 的入口是 **anycast** `162.159.198.1/.2`（IPv6 `2606:4700:103::1/.2`），实测"这两个地址之外的其他地址会拒绝 TLS 握手"（warpscout: masque.go 注释，实测 20-28 组 ip:port 验证）——所以 MASQUE 换端点**只为连通性，不为换出口**。
- IPv6：`-6` 可走 v6 端点（部分网络 v4 被掐而 v6 通）。

### 4.6 HTTP/2 回退（上游功能，本地 fork 没有）

`--http2`（`upstream: cmd/socks.go:315` 等）把传输层从 "HTTP/3 over QUIC/UDP" 换成 "HTTP/2 over TCP+TLS"（CONNECT-IP over TCP），配合独立的 `endpoint_h2_v4/v6` 端点字段（`upstream: config/config.go:18-19`）。**用途：UDP/QUIC 被整网封锁时，走 TCP 443 的 HTTPS 长连接照样能建隧道**——这是上游目前最强的降级通道。上游 wiki 有专页（usque wiki "HTTP-2 support"；本机网络原因未能访问原文，此条标注为**部分未证实**——但 `--http2` flag 与 h2 端点字段在源码中确凿）。

### 4.7 l4-socks / l4-http-proxy（上游新增，本地没有）

`l4-socks`："TCP-only SOCKS5 proxy using direct HTTP/3 CONNECT streams"（`upstream: cmd/l4_socks.go:12`），专用 SNI `consumer-masque-proxy.cloudflareclient.com`（`upstream: internal/consts.go:7`）。它不建 IP 隧道、不需要 netstack/TUN，只有 TCP 拨号——**更轻、更低调，且行为模式与普通网页流量几乎无差别**。代价：只支持 TCP（无 UDP），且远端地址经 Cloudflare 的 L4 代理服务转出。

### 4.8 本地代理模式（socks/httpproxy）在抗封锁中的定位

不开 TUN、不动系统路由，只在 127.0.0.1 开代理口——流量特征面更小（只有你主动走代理的应用产生隧道流量），且**无需管理员/root**。配合 `--local-dns`（DNS 在本地解析而不是塞进隧道，`upstream: cmd/socks.go:317`）可避免 DNS 行为异常。

### 4.9 ZeroTier

仅存在 SNI 常量与 enroll 的说明文字（"Useful for ZeroTier where IPv6 address can change"，`upstream: cmd/enroll.go:19`），**没有任何实装代码**——属于 Cloudflare Zero Trust（企业 WARP）方向的预留。标注：未实装。

### 4.10 portfw 端口转发

SSH 风格 `-L localhost:8080:100.96.0.2:8080`（本地端口 → 隧道内地址）与 `-R`（反向），见 `upstream: cmd/portfw.go:404-405`。用途：只把特定服务搬进/搬出隧道（比如只代理一个 SSH 或 NAS 端口），比全局 VPN 更隐蔽。

---

## 5. 端点与出口节点（"节点"）说明

### 5.1 两套入口，两种"挑节点"能力

| | MASQUE | WireGuard |
|---|---|---|
| 入口地址 | **anycast**：`162.159.198.1/.2`、`2606:4700:103::1/.2`（warpscout: masque.go `masquePoolsV4/V6`） | **端点池**：14 个 IPv4 /24 段（8.6.112.0/24、162.159.192.0/24、188.114.96-99.0/24 等）+ 2 个 IPv6 /48（warpscout: pools.go `poolsV4/V6`） |
| 可用端口 | 443/500/1701/4500/4443/8443/8095（warpscout: masque.go） | 主力 2408/500/1701/4500 + 备用 50 个（2408-8886，warpscout: warp.go `primaryWarpPorts/extendedWarpPorts`） |
| 出口节点（colo） | **固定**：anycast 由你的运营商路由决定，换端点换不掉 | **可挑**：不同端点地址落不同 colo，扫描可筛选 |
| 已知端口可达性表现 | 同端口时通时不通（"flap"），需要多次重试（warpscout: masque.go `masqueDefaultAttempts=3`） | 相对稳定 |

### 5.2 colo 是什么

colo = Cloudflare 边缘机房的 **IATA 机场代码**（如 LAX=洛杉矶、HKG=香港、DME=莫斯科）。隧道内访问 `https://speed.cloudflare.com/meta` 可返回当前出口的 `colo.iata/city/cca2`（扫描器用它判出口，warpscout: discovery.go `metaURL` + meta.go）。选择出口的意义：不同 colo 受审查/干扰程度不同（典型：DME 被 DPI 过滤导致部分站点打不开，warpscout README 动机段），换入口端点即换出口。

### 5.3 为什么"换端点=换出口"只对 WG 成立

WG 端点池是按地区分散广播的普通地址（每个地址有较固定的路由归属）；MASQUE 入口是 anycast（见上一节对话结论 + warpscout masque.go 注释"MASQUE has no endpoint pools"）。**这是协议服务的架构差异，不是 App 能改变的。**

---

## 6. 本地 fork 现状对照表（App 能力盘点）

| 能力 | 上游 CLI | 本地 fork / App |
|---|---|---|
| MASQUE 注册/enroll | ✅ | ✅（App 内一键注册，android/usque_android.go Register） |
| SOCKS/HTTP 本地代理 | ✅ | ✅ CLI 有；App 未暴露 |
| 全局 TUN VPN | ✅ nativetun | ✅（App 的 VpnService + MaintainTunnel） |
| 自定义 SNI | ✅ -s | ✅（SetSNI，默认 www.visa.cn） |
| 自定义端点/端口 | ✅ -P + config | ✅（SetEndpoint + 扫描应用） |
| 端口转发 portfw | ✅ | ✅ CLI 有；App 未暴露 |
| WireGuard 隧道 | ❌（usque 定位是 MASQUE 客户端） | ✅ **本地新增**（api/wgtunnel.go + 双设备注册） |
| 端点扫描器 | ❌ | ✅ **本地新增**（internal/scanner，warpscout 移植，WG 协议） |
| HTTP/2 回退 | ✅ --http2 | ❌ 未有（可移植，需 h2 端点字段 + ConnectTunnel h2 分支） |
| l4-socks / l4-http-proxy | ✅ | ❌ 未有（轻量抗封锁好候选） |
| account 管理（license/设备） | ✅ | ❌ 未有（设备列表/换 license 可加） |
| ZeroTier | ❌ 未实装 | ❌ |
| --insecure | ✅ | ❌（不建议） |

---

## 7. 来源清单

- 本地 fork 源码：`internal/consts.go`、`internal/utils.go:106-310`、`api/cloudflare.go`、`api/tunnel.go`、`config/config.go`、`models/register.go`、`cmd/register.go`、`android/usque_android.go`、`api/wgtunnel.go`、`internal/scanner/*`
- 上游克隆（2026-10-25 抓取）：`cmd/socks.go`、`cmd/nativetun.go`、`cmd/portfw.go`、`cmd/httpproxy.go`、`cmd/l4_socks.go`、`cmd/account.go`、`cmd/enroll.go`、`cmd/register.go`、`internal/consts.go`、`config/config.go`、`config/endpoints.go:29`
- 作者逆向笔记：本仓库 `RESEARCH.md`（§Initial poking/API/Poking on QUIC/TLS Authentication/QUIC/Connect-IP/libwarp_mobile.so/Wireshark inspection）
- warpscout v0.16.1（github.com/vernette/warpscout，MIT）：`pools.go`、`warp.go`、`masque.go`、`discovery.go`、`meta.go`
- 未能访问：上游 GitHub wiki 页（网络受限），相关论断已标注"部分未证实"
