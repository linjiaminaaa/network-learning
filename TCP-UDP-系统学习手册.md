# TCP/UDP 系统学习手册

> 面向有编程基础、兼顾工程实践与面试的读者。侧重字段级细节与可验证结论；配套 HTML 实验室用于建立直觉，动画不在此重复。  
> 约定：序列号示例为相对值；`MSS` 指 TCP 最大报文段长度；默认 IPv4、以太网 MTU 1500。  
> 主要标准：RFC 9293（TCP）、RFC 768（UDP）、RFC 6298（RTO）、RFC 5681（拥塞控制）、RFC 2018（SACK）、RFC 7323（窗口缩放/时间戳）、RFC 9000（QUIC）。

## 目录

- [1. 总览与定位](#sec1)
- [2. UDP 详解](#sec2)
- [3. TCP 报文头逐字段](#sec3)
- [4. 连接建立：三次握手](#sec4)
- [5. 连接释放：四次挥手与 TIME_WAIT](#sec5)
- [6. 11 种状态机与完整迁移表](#sec6)
- [7. 可靠传输机制](#sec7)
- [8. 滑动窗口与流量控制](#sec8)
- [9. 拥塞控制](#sec9)
- [10. 其他机制与工程细节](#sec10)
- [11. UDP 之上做可靠传输](#sec11)
- [12. TCP vs UDP 对比表](#sec12)
- [13. 选型决策清单](#sec13)
- [14. 动手与命令速查](#sec14)
- [15. 面试高频 25 问速答](#sec15)
- [16. 学习路线图](#sec16)
- [附录 A：关键 RFC 与常见误区](#appendix-a)

## 配套资源

| 文件 | 用途 |
|---|---|
| [`tcp-udp-lab.html`](tcp-udp-lab.html) | 交互实验室：报文头逐字段、三次握手/四次挥手动画、滑动窗口与丢包重传仿真、rwnd/cwnd、TCP vs UDP vs QUIC 丢包对比、pcap/pcapng 导入与序号-时间图 |
| [`tcp_udp_demo.py`](tcp_udp_demo.py) | 可直接运行的 socket 实验：TCP 回显、UDP 丢包、粘包/拆包、回环吞吐 |
| [`README.md`](README.md) | 文件说明与学习路径 |
| [参考项目调研与改进清单.md](参考项目调研与改进清单.md) | 同类开源项目调研、对比矩阵与后续改进清单 |

建议路径：先读第 1–3 章建立骨架 → 打开实验室把每个机制点一遍 → 跑 `tcp_udp_demo.py` 做真实 socket 实验 → 用第 15 章 25 问自测。

<a id="sec1"></a>
## 1. 总览与定位

传输层解决**进程到进程**通信，网络层解决**主机到主机**通信。IP 只负责把分组送到目的主机，不保证顺序和送达；TCP/UDP 用 16 位端口把数据交付给应用进程。

| OSI | TCP/IP | 典型协议 | 复用单位 |
|---|---|---|---|
| 应用层/表示层/会话层 | 应用层 | HTTP、DNS、SSH、SMTP、RTP | 进程/连接 |
| 传输层 | 传输层 | TCP、UDP、SCTP、DCCP | 端口 |
| 网络层 | 网络层 | IPv4/IPv6、ICMP、IPsec | IP 地址 |
| 链路层/物理层 | 网络接口层 | Ethernet、Wi-Fi、PPP | MAC 地址 |

| 协议 | 连接 | 可靠性 | 有序/边界 | 拥塞控制 | 实现 |
|---|---|---|---|---|---|
| TCP | 面向连接 | 可靠 | 有序、字节流、无边界 | 有 | 内核 |
| UDP | 无连接 | 不可靠 | 不保证有序、保留边界 | 无 | 内核 |
| QUIC | 逻辑连接 | 可靠（流） | 流内有序；DATAGRAM 有边界 | 有 | 用户态，基于 UDP |

QUIC 把可靠性、TLS 1.3、多路复用、连接迁移和拥塞控制放到 UDP 之上，不是“链路层协议”，也不是简单改名 TCP。

**端口**（RFC 6335）：0–1023 系统/知名端口；1024–49151 注册端口；49152–65535 动态/私有端口。Linux 临时端口常见 32768–60999。

**五元组**唯一标识连接/会话方向：

```text
(源 IP, 源端口, 目的 IP, 目的端口, 传输层协议)
```

**复用**：多个 socket 共用 IP/链路发送，传输层加端口区分。**分用**：接收端按协议、目的 IP、目的端口（TCP/已连接 UDP 还看源 IP/端口）交给正确 socket。未连接 UDP 通常只看本地端口，因此同一端口可服务多个远端。

<a id="sec2"></a>
## 2. UDP 详解

### 2.1 8 字节头部

```text
 0                   16                  31
+-------------------+-------------------+
|    Source Port    | Destination Port  |  4
+-------------------+-------------------+
|      Length       |     Checksum      |  4
+-------------------+-------------------+
|              Data ...                 |
+---------------------------------------+
```

| 字段 | 长度 | 含义 | 要点 |
|---|---|---|---|
| 源端口 | 16 | 发送方端口 | 不需要回复时可置 0 |
| 目的端口 | 16 | 接收方端口 | 分用关键 |
| 长度 | 16 | UDP 头 + 数据 | 最小 8；字段本身最大 65535，但 IPv4 下受 IP 总长限制，UDP 长度实际最大 65515（载荷 65507） |
| 校验和 | 16 | 伪首部 + 头 + 数据 | IPv4 可置 0 表示未计算；IPv6 通常强制 |

IPv4 最大载荷 `65535 - 20 - 8 = 65507` 字节；IPv6 普通载荷最大 `65535 - 8 = 65527` 字节，Jumbogram 可更大。实际还受路径 MTU、缓冲区和中间设备限制。

### 2.2 伪首部与校验和

UDP 校验和覆盖**伪首部、UDP 头、数据**。伪首部不传输，只参与计算。

```text
IPv4 伪首部（12B）: 源IP(4) | 目的IP(4) | 0(1) | 协议17(1) | UDP长度(2)
IPv6 伪首部（40B）: 源IPv6(16) | 目的IPv6(16) | 上层长度(4) | 0(3) | 下一头17(1)
```

算法：按 16 位字相加（奇数长度补 0），回进位加到低 16 位，取反填入；接收端同样计算，结果全 1 为正确。计算值为 0 时 UDP 发送 `0xFFFF`，因为 IPv4 中 0 表示“未计算”。

- IPv4 校验和可选；IPv6 通常强制（RFC 8200），RFC 6935/6936 仅对隧道等特定场景允许零校验和。
- 校验和只能发现比特错误，不能发现丢包、乱序、重复，也不提供认证。

### 2.3 语义与“缺什么”

UDP 无连接、不可靠、不保证有序、面向报文、无流量/拥塞控制。一次 `sendto` 对应一个数据报，接收端一次 `recvfrom` 取一个完整数据报（缓冲区不足会截断）。

| 能力 | TCP | UDP | UDP 缺失后的现象 |
|---|---|---|---|
| 连接状态/确认/重传 | 有 | 无 | 不知道是否到达，丢包永久丢失 |
| 排序/去重 | 有 | 无 | 后发先至、重复处理 |
| 流量/拥塞控制 | 有 | 无 | 冲垮接收方、挤占网络 |
| RTT/RTO 估计 | 有 | 无 | 无法自适应重传 |
| 消息边界 | 无 | 有 | TCP 需应用层拆包 |

IP 分片/重组只是把大 IP 数据报拆成链路可承载片段；任一分片丢失通常导致整条 UDP 数据报丢失，不是传输层可靠机制。

### 2.4 为什么常选 UDP

| 场景 | 示例端口 | 原因 |
|---|---|---|
| DNS | 53/UDP，TCP 兜底 | 请求小、量大、低延迟；截断转 TCP |
| DHCP | 67/68 | 客户端尚无 IP，需广播 |
| NTP/SNMP/TFTP | 123/161/69 | 小报文、简单、可容忍丢失 |
| RTP/WebRTC | 动态 | 实时媒体，过期重传无意义 |
| 游戏 | 自定义 | 只重传仍有意义的状态，避免队头阻塞 |
| QUIC/HTTP3 | 443/UDP | 用户态可靠传输 + TLS 1.3 + 多流 |
| mDNS/SSDP | 5353/1900 | 局域网多播发现 |
| VXLAN/WireGuard | 4789/51820 | 隧道封装、NAT 穿透、低开销 |

核心不是“UDP 更快”，而是**不需要 TCP 的某些语义，或需要 TCP 不提供的语义**：广播/多播、消息边界、应用自定义重传、低握手延迟。

### 2.5 打洞、广播、多播

UDP 打洞：双方先经 STUN 获知各自公网映射，再互相向对方公网地址发 UDP，使 NAT 建立/刷新映射。依赖 NAT 行为；对称 NAT、CGNAT、严格防火墙可能失败，实际用 ICE（RFC 8445）、STUN（RFC 8489）、TURN 中继兜底。打洞不是 UDP 标准的一部分。

广播/多播：IPv4 受限广播 `255.255.255.255`、子网广播；IPv4 多播 `224.0.0.0/4`（本地链路 `224.0.0.0/24`）；IPv6 多播 `ff00::/8`。主机用 IGMP/MLD 加组；TCP 不支持广播/多播。

### 2.6 报文边界 vs TCP 字节流

```text
应用写: [A 100B] [B 50B] [C 200B]
UDP 收: [A] [B] [C]              ← 边界保留，可能丢/乱/重
TCP 收: [字节流 ................]  ← 无边界，可能合并/切分
```

UDP 一次发送对应一个数据报；TCP 多次 `send` 可能合并，一次 `send` 也可能拆分，`recv` 的边界与写入边界无关。这就是粘包/拆包的根源。

<a id="sec3"></a>
## 3. TCP 报文头逐字段

### 3.1 布局

基础头 20 字节，最多 60 字节（选项最多 40 字节）。

```text
 0                   16                  31
+-------------------+-------------------+
|    Source Port    | Destination Port  |  4
+-------------------+-------------------+
|            Sequence Number            |  4
+---------------------------------------+
|        Acknowledgment Number          |  4
+----+-------+-----+-------------------+
|Data|Reserv.| NS  |CWR|ECE|URG|ACK|PSH|RST|SYN|FIN| 4
|Off | 3 bit |     |   |   |   |   |   |   |   |   |
+----+-------+-----+-------------------+
|            Window Size                |  4
+-------------------+-------------------+
|     Checksum      |  Urgent Pointer  |  4
+-------------------+-------------------+
|            Options (0–40B)            |
+---------------------------------------+
|              Data ...                 |
+---------------------------------------+
```

第 13 字节起：数据偏移 4 位 + 保留 3 位 + NS 1 位 + 8 个标志（CWR/ECE/URG/ACK/PSH/RST/SYN/FIN）。传统教材只画 6 个标志，加上 ECE/CWR 共 8 个；NS 是 RFC 3540 实验位。

### 3.2 字段

| 字段 | 长度 | 作用 | 细节 |
|---|---|---|---|
| 源/目的端口 | 各 16 | 标识进程 | 与 IP 组成连接标识 |
| 序号 `SEQ` | 32 | 本段第一个数据字节序号 | SYN/FIN 各消耗 1；纯 ACK 不消耗 |
| 确认号 `ACK` | 32 | 期望的下一个字节 | 累计确认；仅 ACK=1 时有效 |
| 数据偏移 | 4 | 头部长度，单位 4B | 5–15，即 20–60B |
| 保留 | 3 | 保留 | 发送置 0 |
| NS | 1 | ECN Nonce（实验） | 通常 0 |
| CWR | 1 | 发送方已降窗 | 配合 ECE |
| ECE | 1 | 回显 CE；SYN 中协商 ECN | RFC 3168 |
| URG | 1 | 紧急指针有效 | 现代应用少用 |
| ACK | 1 | 确认号有效 | 建立后通常恒 1 |
| PSH | 1 | 提示尽快交付 | 不是消息边界 |
| RST | 1 | 复位连接 | 异常终止 |
| SYN | 1 | 同步序号 | 建立连接，消耗 1 序号 |
| FIN | 1 | 发送方无更多数据 | 半关闭，消耗 1 序号 |
| 窗口 | 16 | 接收窗口通告 | 未缩放最大 65535B |
| 校验和 | 16 | 头+数据+伪首部 | 强制 |
| 紧急指针 | 16 | 紧急数据位置 | 仅 URG=1 有意义；历史有 off-by-one 争议 |

### 3.3 标志位与选项

| 标志 | 触发/含义 | 注意 |
|---|---|---|
| SYN | 建立连接 | 握手/同时打开 |
| ACK | 确认 | 建立后几乎总为 1 |
| FIN | 关闭本方向 | 仍可接收 |
| RST | 异常中止 | 通常立即释放，无 TIME_WAIT |
| PSH | 尽快交付 | 不保证边界 |
| URG | 紧急数据 | RFC 6093 讨论歧义 |
| ECE | 回显拥塞/ECN 协商 | 接收方看到 CE 时置位 |
| CWR | 已减小拥塞窗口 | 发送方响应 ECE |

ECN 常见流程：SYN 中协商 ECN；路由器拥塞时把 IP 头 CE 置 1；接收方用 ECE 回显；发送方降窗并置 CWR。抓包要同时看 IP 的 ECN 字段和 TCP 的 ECE/CWR。

| 选项 | Kind | 长度 | 位置 | 作用 |
|---|---|---|---|---|
| EOL/NOP | 0/1 | 1 | 任意 | 结束/对齐 |
| MSS | 2 | 4 | SYN | 可接收的 TCP 载荷上限（不含头） |
| Window Scale | 3 | 3 | SYN | 窗口缩放因子 |
| SACK-Permitted | 4 | 2 | SYN | 支持选择性确认 |
| SACK | 5 | 可变 | ACK | 报告非连续块 |
| Timestamps | 8 | 10 | SYN/数据/ACK | RTT 测量、PAWS |
| TFO | 34 | 可变 | SYN/数据 | TCP Fast Open（RFC 7413） |
| MD5/AO | 19/29 | 可变 | 任意 | TCP 认证（RFC 5925） |

MSS 只算数据。以太网 MTU 1500：IPv4 典型 MSS `1500-20-20=1460`；IPv6 `1500-40-20=1440`。实际发送还要扣除选项（如时间戳 12B），因此 1460 是上限而非固定值。MSS 在 SYN 中通告，是“我希望你发给我的单段数据上限”，不等于完整 PMTUD。

### 3.4 校验和、伪首部、长度上限

TCP 校验和覆盖**伪首部 + TCP 头 + 数据**。IPv4 伪首部：源 IP(4)、目的 IP(4)、0(1)、协议 6(1)、TCP 长度(2)；IPv6 伪首部：源/目的各 16、上层长度 4、0(3)、下一头 6(1)。TCP 长度 = TCP 头 + 数据，不含伪首部。

数据偏移 4 位最大 15，所以头部最大 `15×4=60` 字节；选项最多 40 字节。头部越长，单段可载数据越少。

> 易错点：数据偏移单位是 4 字节；SYN 段的窗口字段不能被缩放；紧急指针只在 URG=1 时有意义。

<a id="sec4"></a>
## 4. 连接建立：三次握手

```text
客户端                                      服务器
CLOSED                                      LISTEN
  |  SYN=1, seq=x, MSS/WS/SACK/TS           |
  |---------------------------------------->|
SYN_SENT                                    SYN_RCVD
  |  SYN=1, ACK=1, seq=y, ack=x+1           |
  |<----------------------------------------|
ESTABLISHED                                 ESTABLISHED
  |  ACK=1, seq=x+1, ack=y+1                |
  |---------------------------------------->|
  |        （第三次 ACK 可携带数据）          |
```

例：客户端 ISN `x=1000`，服务器 `y=3000`。① `SYN seq=1000`；② `SYN+ACK seq=3000 ack=1001`；③ `ACK seq=1001 ack=3001`。SYN 消耗 1 序号，所以确认 `x+1`；FIN 也消耗 1；纯 ACK 不消耗。若第三次 ACK 带 100B 数据，则 `seq=1001`，下次客户端序号 `1101`。

**为什么三次**：双方要确认“我能发/能收、你能发/能收”并同步 ISN。两次不够：服务器无法确认客户端收到了 SYN+ACK，客户端接收方向也未确认。四次多余：服务器的 SYN 与对客户端 SYN 的 ACK 可合并为 SYN+ACK，客户端第三次 ACK 已确认服务器 SYN，且不需再被确认。完整握手约 1.5 RTT；客户端收到 SYN+ACK 后即可把第三次 ACK（可带数据）发出，无需等待“ACK 的 ACK”。

**ISN**：32 位，按 RFC 6528 用时钟 + 四元组哈希 + 秘密值生成，不能固定从 0/1 开始。随机化防止旧连接延迟段误收，也提高盲注入成本；它不是加密，不能替代 TLS。

**两个队列（Linux）**：

| 队列 | 内容 | 限制 |
|---|---|---|
| SYN 队列（syns） | 收到 SYN、已回 SYN+ACK，未收最终 ACK | `tcp_max_syn_backlog` |
| accept 队列 | 握手完成，等待应用 `accept()` | `listen()` backlog、`somaxconn` |

`ss -lnt` 的 `Recv-Q` 常见为已排队未 accept 的连接数，`Send-Q` 常为队列上限（随内核版本略有差异）。accept 队列满时，新连接可能被丢弃或触发重传。

**SYN Flood**：伪造大量 SYN，服务器为半连接分配状态并重传 SYN+ACK，耗尽队列。**SYN Cookie** 不在队列保存状态，而把四元组、时间、MSS 等编码进 SYN+ACK 的序列号；收到第三次 ACK 时验证 cookie 再建连。它抗队列耗尽，但可能丢失窗口缩放/SACK 等选项。Linux `tcp_syncookies=1`；不要随意开 `tcp_abort_on_overflow`，可能把瞬时溢出变成 RST。

**同时打开**：双方几乎同时发 SYN，均从 `SYN_SENT` 收到对方 SYN 进入 `SYN_RCVD`，再互发 SYN+ACK 并确认，最终 `ESTABLISHED`。少见，但状态机必须支持。

<a id="sec5"></a>
## 5. 连接释放：四次挥手与 TIME_WAIT

```text
主动关闭方                                  被动关闭方
ESTABLISHED                                 ESTABLISHED
  |  FIN=1, seq=u                           |
  |---------------------------------------->|
FIN_WAIT_1                                  CLOSE_WAIT
  |  ACK=1, seq=v, ack=u+1                  |
  |<----------------------------------------|
FIN_WAIT_2                                  CLOSE_WAIT
  |  （服务器继续发送剩余数据，客户端仍可收）  |
  |  FIN=1, ACK=1, seq=w, ack=u+1           |
  |<----------------------------------------|
  |  ACK=1, seq=u+1, ack=w+1                |
  |---------------------------------------->|
TIME_WAIT                                   LAST_ACK
  |  （等待 2MSL）                           |
CLOSED                                      CLOSED
```

要点：FIN 只关闭**发送方向**，主动方在 `FIN_WAIT_2` 仍可接收，这叫半关闭；FIN 消耗 1 序号，确认 `u+1`；被动方收到 FIN 进入 `CLOSE_WAIT`，应用 `close()` 后才发自己的 FIN，进入 `LAST_ACK`。

**TIME_WAIT 的两种作用**：

1. **保证最后 ACK 到达**：最后 ACK 丢失时，对端会重传 FIN；主动方仍在 TIME_WAIT 可再回 ACK。若已 CLOSED，可能回 RST，导致对端异常终止。
2. **让旧连接的延迟段消亡**：四元组可能快速复用，等待 2MSL 给旧段生命周期一个上界，避免其落入新连接窗口。

时长：RFC 793 传统 `MSL=2 分钟`，`2MSL=4 分钟`；Linux 常见约 **60 秒**（`TCP_TIMEWAIT_LEN`）；Windows `TcpTimedWaitDelay` 默认常见 **120 秒**（2 分钟），可配置。以本机实现为准；面试答“理论 2MSL，Linux 常见 60s”较稳。

**为什么四次不是三次**：TCP 全双工，两个方向独立关闭。被动方收到 FIN 后可能还有数据，所以先 ACK，发完再 FIN；只有恰好无剩余数据时 ACK 与 FIN 才可能合并，抓包像三个包，逻辑仍是四步。

**半关闭**：`shutdown(fd, SHUT_WR)` 只关闭写方向，仍可 `recv()`；`close(fd)` 减少引用，通常在引用归零时关闭。

**CLOSE_WAIT vs TIME_WAIT**：

| 现象 | 含义 | 常见原因 | 排查 |
|---|---|---|---|
| 大量 `CLOSE_WAIT` | 对端已 FIN，本端应用未 `close()` | 代码遗漏、线程阻塞、连接池泄漏、下游卡住 | `ss -tanp state close-wait`、`lsof -i`、线程栈 |
| 大量 `TIME_WAIT` | 本端主动关闭，等 2MSL | 短连接高并发、服务端主动关、HTTP/1.0、NAT | `ss -tan state time-wait`、连接池/长连接 |

`CLOSE_WAIT` 多通常是应用 bug；`TIME_WAIT` 多是正常行为，只有端口/四元组耗尽才需优化。用连接池/keep-alive 减少短连接；`SO_REUSEADDR` 只影响绑定，不消除 TIME_WAIT；Linux `tcp_tw_reuse` 仅对主动连接且通常要求时间戳，`tcp_tw_recycle` 已在 4.12 移除。不要用 `SO_LINGER=0` 强行 RST 来“优化”。

**RST 典型场景**：连接不存在的端口；应用崩溃/异常终止；`SO_LINGER=0`；收到窗口外/非法段；半开连接；防火墙/中间设备拒绝；accept 队列溢出（视配置）；Keepalive 失败。RST 立即中止，不保证数据送达，通常不进入 TIME_WAIT。

**同时关闭**：双方几乎同时发 FIN，均从 `FIN_WAIT_1` 进入 `CLOSING`，收到对自己 FIN 的 ACK 后进入 `TIME_WAIT`。

<a id="sec6"></a>
## 6. 11 种状态机与完整迁移表

| 状态 | 含义 | 谁通常在此 |
|---|---|---|
| `CLOSED` | 无连接 | 初始/最终 |
| `LISTEN` | 等 SYN | 服务器 |
| `SYN_SENT` | 已发 SYN，等 SYN+ACK | 主动打开方 |
| `SYN_RCVD` | 已回 SYN+ACK，等 ACK | 被动打开方 |
| `ESTABLISHED` | 已建立，可双向传输 | 双方 |
| `FIN_WAIT_1` | 已发 FIN，等 ACK/对方 FIN | 主动关闭方 |
| `FIN_WAIT_2` | 自己 FIN 已 ACK，等对方 FIN | 主动关闭方 |
| `CLOSE_WAIT` | 已收对方 FIN，等应用关闭 | 被动关闭方 |
| `CLOSING` | 双方同时发 FIN，等 ACK | 同时关闭双方 |
| `LAST_ACK` | 已发 FIN，等最后 ACK | 被动关闭方 |
| `TIME_WAIT` | 等 2MSL，处理重传 FIN/旧段 | 主动关闭方 |

表中 `—` 表示不触发常规迁移；`/` 后为动作。`SS`=SYN_SENT，`SR`=SYN_RCVD，`EST`=ESTABLISHED，`FW1`=FIN_WAIT_1，`FW2`=FIN_WAIT_2，`CW`=CLOSE_WAIT，`CLO`=CLOSING，`LA`=LAST_ACK，`TW`=TIME_WAIT；`SYN`/`SA`/`ACK`/`FIN`/`RST` 为发送对应标志，`Del` 为删除 TCB。

| 当前状态 | 主动 OPEN | 被动 OPEN | 收 SYN | 收 SYN+ACK | 收 ACK | 收 FIN | 收 FIN+ACK | 收 RST | 应用 CLOSE | 超时 |
|---|---|---|---|---|---|---|---|---|---|---|
| `CLOSED` | SS / SYN | LISTEN / — | CLOSED / RST | CLOSED / RST | CLOSED / RST | CLOSED / RST | CLOSED / RST | CLOSED / — | — | — |
| `LISTEN` | SS / SYN | LISTEN / — | SR / SA | LISTEN / RST | LISTEN / RST | LISTEN / 丢弃 | LISTEN / RST | LISTEN / — | CLOSED / Del | — |
| `SYN_SENT` | — | — | SR / SA | EST / ACK | SS / RST | SS / 丢弃 | SS / RST | CLOSED / — | CLOSED / Del | CLOSED / Del |
| `SYN_RCVD` | — | — | SR / SA | EST / ACK | EST / — | CW / ACK | CW / ACK | CLOSED / — | FW1 / FIN | CLOSED / Del |
| `ESTABLISHED` | — | — | EST / ACK | EST / ACK | EST / — | CW / ACK | CW / ACK | CLOSED / — | FW1 / FIN | — |
| `FIN_WAIT_1` | — | — | — | — | FW2 / — | CLO / ACK | TW / ACK | CLOSED / — | — | CLOSED / Del |
| `FIN_WAIT_2` | — | — | — | — | FW2 / — | TW / ACK | TW / ACK | CLOSED / — | — | CLOSED / Del |
| `CLOSE_WAIT` | — | — | — | — | CW / — | CW / ACK | CW / ACK | CLOSED / — | LA / FIN | — |
| `CLOSING` | — | — | — | — | TW / — | CLO / ACK | TW / ACK | CLOSED / — | — | CLOSED / Del |
| `LAST_ACK` | — | — | — | — | CLOSED / — | LA / ACK | CLOSED / ACK | CLOSED / — | — | CLOSED / Del |
| `TIME_WAIT` | — | — | — | — | TW / — | TW / ACK | TW / ACK | CLOSED / — | — | CLOSED / Del |

这是**状态迁移视图**，省略了序号/窗口校验、ACK 可接受性、重传、Challenge ACK 等；真实实现必须先验证段在窗口内、ACK 合法再迁移。`SYN_SENT` 收到不可接受 ACK 时只回 RST 并保持 `SYN_SENT`，不能立即当作 `CLOSED`。`SYN_RCVD` 收 FIN 较少见但异常流量可能发生；`TIME_WAIT` 收 RST 在 RFC 793 与 RFC 1337 安全建议间有差异，现代实现更保守；`FIN_WAIT_2` 超时常见 `tcp_fin_timeout`（约 60s）。

```bash
ss -tan                    # 所有 TCP 状态
ss -tan state time-wait
ss -tan state close-wait
ss -lnt                    # 监听队列
ss -s                      # 汇总
```

<a id="sec7"></a>
## 7. 可靠传输机制

TCP 把应用数据视为**无结构字节流**，每个字节有 32 位序号（模 `2^32`）。段 `SEQ` 是首字节序号；`ACK` 是期望的**下一个字节**序号，表示此前字节都收到。

```text
发送 SEQ=1000, len=500  → 覆盖 1000..1499
接收 ACK=1500           → 1000..1499 已收，期望 1500
```

SYN 占 1 序号，FIN 占 1 序号，纯 ACK 不占；重传用原序号。**按字节而非按包编号**：段大小可变（MSS/窗口/MTU），按包无法表达“部分字节已收”；累计 ACK 可用一个号表示大段连续数据；接收端可合并/切分，字节编号与分片解耦，能精确描述乱序、空洞和部分重传。

**累计确认**：`ACK=n` 表示 n 之前全部收到，即使中间有空洞也不能确认其后数据（SACK 补充）。**延迟 ACK**：接收方等待一小段时间再 ACK，以便合并或捎带；RFC 1122 要求至少每两个满段确认一次，延迟不超过 500ms；Linux 常见 40–200ms，Windows 传统约 200ms。

**RTO（RFC 6298）**：

```text
首个样本 R:
  SRTT = R
  RTTVAR = R/2
  RTO = SRTT + max(G, K×RTTVAR)

后续样本 R':
  RTTVAR = (1-β)×RTTVAR + β×|SRTT-R'|
  SRTT   = (1-α)×SRTT   + α×R'
  RTO    = SRTT + max(G, K×RTTVAR)

α=1/8, β=1/4, K=4, G=时钟粒度
```

先更新 `RTTVAR`（用旧 `SRTT`），再更新 `SRTT`。初始 RTO 1s；RFC 建议下限 1s，Linux 可低至 200ms；上限至少 60s，Linux 常见 120s。超时后指数退避。**Karn 算法**：重传过的段不用于 RTT 采样，避免 ACK 对应原发还是重传的歧义；时间戳可在一定程度上消除歧义。

**快速重传**：连续收到 **3 个重复 ACK**（同一 ACK 号、无新数据），说明丢失段之后的数据已到达，接收方在催空洞；立即重传，不等 RTO。加上第一个正常 ACK，抓包常见 **4 个相同 ACK**；“3 个”指 3 个额外重复。

```text
发送: [1000-1499] [1500-1999] [2000-2499] [2500-2999]
丢失:              ↑
接收: ACK=1500, ACK=1500, ACK=1500, ACK=1500
发送: 立即重传 1500-1999
```

**快速恢复（Reno）**：`ssthresh=max(FlightSize/2,2×MSS)`；重传丢失段；`cwnd=ssthresh+3×MSS`；每个 dup ACK `cwnd+=MSS`；收到新 ACK 后 `cwnd=ssthresh`，进入拥塞避免。

**SACK（RFC 2018）**：接收方在 ACK 中报告已收到的非连续块，发送方只重传空洞，避免多丢包时从头重传。`SACK-Permitted` 在 SYN 协商；`ACK=1500, SACK=[2000-2999]` 表示 1500 前连续、2000–2999 已收、1500–1999 是空洞。**D-SACK（RFC 2883）** 报告重复段，帮助识别伪重传/网络重复。SACK 是累计 ACK 的补充，不替代它。

**乱序与伪重传**：轻微乱序不应误判丢包；伪重传是实际未丢包但因超时/误判重复 ACK 而重传，常见于 RTT 突增、路径抖动、ACK 延迟。可用 DSACK、F-RTO（RFC 5682）、Eifel（RFC 3522）检测/缓解。

<a id="sec8"></a>
## 8. 滑动窗口与流量控制

| 窗口 | 位置 | 含义 |
|---|---|---|
| `rwnd` | 接收方通告 | 接收缓冲区还能收多少，防止压垮接收方 |
| `cwnd` | 发送方维护 | 根据网络拥塞估计允许的在途数据量 |
| 发送窗口 | 发送方 | `min(rwnd, cwnd)` |

```text
SND.UNA          SND.NXT                     SND.UNA + SND.WND
   |                |                              |
   | 已发已确认     | 已发未确认                   | 允许发送上界
   |<--- 已用窗口 -->|<------ 可用窗口 ----------->|
```

可用窗口 `= SND.UNA + SND.WND - SND.NXT`；只有大于 0 才能发新数据。窗口按**字节区间**滑动，不是按包数。例：`UNA=1000, NXT=1000, WND=3000`，发 1000B 后 `NXT=2000`；收到 `ACK=2000` 后 `UNA=2000`，窗口右移，可用窗口仍为 2000；若 `rwnd` 降为 1500，发送窗口变为 `min(1500,cwnd)`。接收方用 ACK 的窗口字段动态调整；现代实现避免窗口回缩（window shrink）。

**零窗口与坚持定时器**：接收方缓冲区满时通告 `rwnd=0`，发送方停发新数据，但窗口更新 ACK 可能丢失，不能永久睡眠。坚持定时器（persist timer）周期发送**窗口探测**（常带 1 字节或零长度段），迫使接收方回复当前窗口；仍为 0 则指数退避，直到窗口打开或超时。它不是重传数据，而是“询问窗口”。

**糊涂窗口综合征（SWS）**：双方反复交换极小窗口/数据，导致大量小包、吞吐极低。接收方不要通告只增加几字节的小窗口；Clark 算法建议窗口从 0 恢复时等到能容纳 `min(MSS, 缓冲区一半)` 再通告。发送方用 Nagle 避免小段。

**Nagle + 延迟 ACK**：

```text
Nagle：有未确认数据时，缓存小段，直到凑满 MSS 或收到 ACK
延迟 ACK：收到数据后等一段时间（常见 40ms，最多约 200ms）再 ACK
```

经典延迟：请求被拆成多次小写（如 header + body），或双向小包交互。发送方先发第一小段；接收方延迟 ACK；Nagle 因有未确认数据扣住第二小段；第二小段要等 ACK，于是多等一个延迟 ACK 周期（Linux 常见约 40ms，部分实现 200ms）。若应用一次 `send()` 写完整个请求，Nagle 通常不会延迟第一个段，问题多出在多次小写/双向小包。

解决：`TCP_NODELAY` 关闭 Nagle（低延迟交互、RPC、游戏）；Linux `TCP_CORK` 合并小写直到 uncork/超时；`writev`/应用层缓冲减少小写；接收端 `TCP_QUICKACK` 尽快 ACK（临时行为，非跨平台契约）。

**窗口缩放（RFC 7323）**：16 位窗口最大 65535B，高 BDP 网络不够。SYN 中协商 `shift`，实际窗口 `= 窗口字段 << shift`；选项 3 字节 `Kind=3, Length=3, shift`；双方都发送才启用；SYN 段窗口不缩放；`shift` 最大 14，最大窗口约 `65535<<14=1,073,725,440B`，约 1GiB（`2^30` 量级）。

<a id="sec9"></a>
## 9. 拥塞控制

早期互联网出现过**拥塞崩溃**：大量重传填满网络，有效吞吐趋近零。拥塞控制让多条流在共享瓶颈上公平、稳定、高效地共存。

| 维度 | 流量控制 | 拥塞控制 |
|---|---|---|
| 保护对象 | 接收方缓冲区 | 网络瓶颈/链路 |
| 信号 | 接收方 `rwnd` | 丢包、延迟、ECN |
| 发送上限 | `rwnd` | `cwnd` |
| 实际窗口 | `min(rwnd, cwnd)` | 同左 |

**AIMD**（加性增、乘性减）：无拥塞时每 RTT 约 `+1 MSS`；检测到拥塞时窗口乘性减小（通常减半）。关键变量：`cwnd`、`ssthresh`、`FlightSize`（已发未确认数据量）。

| 阶段 | 触发 | `cwnd` 变化 | 结束 |
|---|---|---|---|
| 慢启动 | 连接开始/超时后 | 每 ACK 约 `+1 MSS`，每 RTT 翻倍 | `cwnd>=ssthresh` |
| 拥塞避免 | 达到阈值 | 每 ACK 约 `+MSS²/cwnd`，每 RTT 约 `+1 MSS` | 丢包/ECN |
| 快速重传 | 3 个重复 ACK | 立即重传丢失段 | 新 ACK |
| 快速恢复 | 快速重传后 | `ssthresh` 减半，`cwnd=ssthresh+3MSS`，每 dup ACK `+MSS` | 新 ACK 后 `cwnd=ssthresh` |

超时：`ssthresh=max(FlightSize/2,2×MSS)`，`cwnd=1MSS`，重新慢启动。3 个重复 ACK：网络仍在交付后续段，进入快速恢复，避免吞吐骤降。初始窗口：RFC 5681 建议 `min(4×MSS,max(2×MSS,4380B))`；Linux 等常用 10 MSS（RFC 6928 方向），缩短短流启动，但过大可能突发丢包。

| 版本 | 丢包后行为 | 特点 |
|---|---|---|
| Tahoe | 任何丢包都 `cwnd=1`，慢启动 | 简单保守，恢复慢 |
| Reno | 快速重传/恢复；超时降到 1 | 单窗口单丢包表现好 |
| NewReno | partial ACK 处理多丢包 | 减少等待超时 |
| SACK 增强 | 按 SACK 块精确重传 | 多丢包明显优于传统 Reno |

**CUBIC**（RFC 8312，Linux 长期默认）：窗口按时间三次函数增长，不直接依赖 RTT；以 `W_max` 为参考，先快后慢；丢包仍是主要信号，乘性减因子通常 0.7。

**BBR**（Bottleneck Bandwidth and Round-trip propagation time，非 RFC）：估计瓶颈带宽和最小 RTT，用 pacing 控制发送，维护“在途 ≈ BDP”；周期 ProbeBW/ProbeRTT。它不把丢包当唯一信号，在浅缓冲/无线等场景可能更好，但公平性、深队列、与 CUBIC 共存有争议，版本间差异大。

**ECN（RFC 3168）**：路由器拥塞时把 IP 头 CE 置 1，而非直接丢包；接收方用 TCP ECE 回显；发送方降窗并置 CWR。它避免不必要丢包/重传，但需端到端支持；不是拥塞控制的替代品。ECN 标记在 IP 层，回显在 TCP 层。

<a id="sec10"></a>
## 10. 其他机制与工程细节

### 10.1 定时器

| 定时器 | 作用 | 典型行为 |
|---|---|---|
| 重传 | 检测丢失 | RTO 到期重传，指数退避 |
| 坚持 | 避免零窗口死锁 | 周期窗口探测，退避 |
| 保活 | 检测空闲对端存活 | 默认 2h 后开始 |
| 2MSL/TIME_WAIT | 等旧段消亡、保证最后 ACK | Linux 约 60s；传统 4min |
| 延迟 ACK | 合并确认 | 常见 40–200ms |
| FIN_WAIT_2 | 防被动方永不发 FIN | Linux `tcp_fin_timeout` 约 60s |
| SYN 重传 | 握手超时重试 | 指数退避，次数有限 |

### 10.2 Keepalive

Linux 默认空闲 `tcp_keepalive_time=7200s` 后开始，间隔 `tcp_keepalive_intvl=75s`，探测 `tcp_keepalive_probes=9` 次；Windows 传统约 2 小时。探测失败后内核可能关闭连接并报错。HTTP 的 `Keep-Alive` 是应用层连接复用，与 TCP Keepalive 不同；中间设备/NAT 可能超时，应用层心跳通常更可控。Keepalive 只检测链路/对端是否响应，不检测业务可用性。

### 10.3 MSS、MTU、PMTUD

| 概念 | 含义 | 以太网典型 |
|---|---|---|
| MTU | 链路层最大传输单元（IP 包总长上限） | 1500B |
| MSS | TCP 载荷上限（不含 TCP/IP 头） | IPv4 1460；IPv6 1440 |
| IP 分片 | 大 IP 包拆成链路可承载片段 | 应尽量避免 |
| PMTUD | 路径 MTU 发现（DF + ICMP 反馈） | IPv4 DF；IPv6 默认 |

PMTUD：发送方置 DF，遇小 MTU 路由器时收到 ICMP“需要分片但 DF 置位”（IPv4 Type 3 Code 4）或 Packet Too Big（IPv6），据此降低包长。若 ICMP 被防火墙丢弃，形成 **PMTUD 黑洞**：能 ping/握手，但大文件卡住。工程手段：MSS clamping（VPN/隧道常见）、应用层控制包长、QUIC 的 DPLPMTUD（RFC 8899）。IPv4 1500 MTU 可用 `ping -M do -s 1472`（Linux）或 `ping -f -l 1472`（Windows）探测：`1472+8 ICMP+20 IP=1500`。

### 10.4 粘包/拆包与代码

TCP 是字节流，不保留应用消息边界：

```text
send("A"), send("B")   → 可能合并为 "AB" 一个段
send("A"*10000)        → 可能拆成多段
recv()                 → 返回任意长度字节块
```

“粘包”不是 TCP bug，而是应用层没定义消息边界。三种方案：

| 方案 | 优点 | 缺点 | 适用 |
|---|---|---|---|
| 长度前缀 | 二进制安全、解析简单 | 需固定长度字段、限制最大值 | RPC、自定义二进制 |
| 分隔符 | 可读、简单 | 数据不能含分隔符，需转义 | 文本协议、Redis |
| 固定长度 | 解析最快 | 浪费空间、不灵活 | 定长记录、硬件协议 |

Python 长度前缀示例（4 字节大端）：

```python
import struct

MAX_MSG = 16 * 1024 * 1024

def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)

def send_msg(sock, payload: bytes) -> None:
    if len(payload) > MAX_MSG:
        raise ValueError("message too large")
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_msg(sock) -> bytes:
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > MAX_MSG:
        raise ValueError("message too large")
    return recv_exact(sock, length)
```

要点：`sendall()` 不保证一次系统调用写完；`recv()` 可能只返回部分数据；长度前缀用网络字节序（大端 `!I`）并限制最大值，防止恶意长度耗尽内存。UDP 不需要这套拆包逻辑，但要注意数据报截断和最大载荷。

### 10.5 `SO_REUSEADDR`、`SO_LINGER`、`TCP_FASTOPEN`

**`SO_REUSEADDR`**：允许 `bind()` 到处于 TIME_WAIT 的本地地址/端口，便于服务器重启；也影响通配地址与具体地址的绑定冲突，各系统语义有差异。它不允许同一四元组同时存在两条活动连接，也不减少 TIME_WAIT。多进程监听同一端口通常用 `SO_REUSEPORT`（Linux），不要混淆。

**`SO_LINGER`**：

```c
struct linger { int l_onoff; int l_linger; };
```

`l_onoff=0` 默认优雅关闭；`l_onoff=1, l_linger=0` 丢弃发送缓冲区并发 RST，不保证数据送达；`l_onoff=1, l_linger>0` `close()` 阻塞到数据发完或超时（超时可能 RST）。不要用 `SO_LINGER=0` 规避 TIME_WAIT，它会破坏可靠关闭语义。

**`TCP_FASTOPEN`（TFO，RFC 7413）**：客户端在 SYN 中带数据，服务器可在 SYN+ACK 中返回数据，减少一个 RTT；依赖 TFO Cookie，首次连接获取，后续携带 Cookie 才能在 SYN 带数据。服务器开启 `net.ipv4.tcp_fastopen`（常见位掩码 1 客户端、2 服务器、3 两者）并设置 listen 队列；客户端用 `sendto(..., MSG_FASTOPEN)` 或 `TCP_FASTOPEN_CONNECT`。0-RTT 数据有重放风险，只适合幂等请求；与 TLS 1.3 的 0-RTT 不是同一层机制。

<a id="sec11"></a>
## 11. UDP 之上做可靠传输

### 11.1 QUIC

| 特性 | 机制 | 解决的问题 |
|---|---|---|
| 连接建立 | 1-RTT；恢复可 0-RTT | 降低首包/重连延迟 |
| 加密 | 内建 TLS 1.3（RFC 9001） | 头部受保护，减少中间设备干预 |
| 多流 | 独立 stream，流内有序 | 避免跨流队头阻塞 |
| 连接迁移 | Connection ID 标识连接 | NAT 重绑定/Wi-Fi 切换不断连 |
| 丢包恢复 | ACK 帧、包号、PTO、快速重传 | 用户态精确控制 |
| 拥塞控制 | 可插拔 CUBIC/BBR 等 | 不依赖内核升级 |
| 不可靠数据报 | DATAGRAM 帧（RFC 9221） | 实时媒体等可丢数据 |

细节：QUIC 的“无队头阻塞”主要指**流之间**；流内仍有序，一个 QUIC 包丢失仍会阻塞该包中所有流的数据直到重传，所以不是完全没有队头阻塞。0-RTT 数据可被重放，只用于幂等操作；连接迁移依赖 Connection ID，迁移可能触发路径验证；UDP 443 可能被企业网络封禁，用户态实现有 CPU 开销。

### 11.2 KCP、UDT、ENet、SCTP

| 协议/库 | 定位 | 特点 |
|---|---|---|
| KCP | 快速可靠 ARQ over UDP | 选择性 ACK、快速重传、可配置 RTO；带宽换延迟 |
| UDT | 高速大数据 over UDP | 面向块、拥塞控制、高 BDP；实现较重 |
| ENet | 游戏网络库 | 可靠/不可靠通道、轻量、适合状态同步 |

**SCTP（RFC 4960）**：面向消息、可靠、多流（一条流阻塞不影响其他流）、多宿主（多 IP 切换）、四次握手（INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK，Cookie 防 SYN Flood）、部分可靠 PR-SCTP（RFC 3758）。SCTP 直接跑 IP（协议号 132），NAT/防火墙支持差，于是有 SCTP over UDP（RFC 6951）；WebRTC 数据通道用 SCTP over DTLS over UDP（RFC 8831）。

**部分可靠**：QUIC DATAGRAM（RFC 9221）在 QUIC 连接上发不可靠数据报，保留边界、不重传；PR-SCTP 可为消息设生存时间/重传次数。“可靠 UDP”不是标准协议名，通常指在 UDP 上实现确认/重传/排序的统称，具体是 QUIC、KCP、UDT、ENet 或自研；面试要说清具体协议。

<a id="sec12"></a>
## 12. TCP vs UDP 对比表

| 维度 | TCP | UDP | QUIC（参考） |
|---|---|---|---|
| 连接 | 三次握手 | 无连接 | 逻辑连接，1-RTT/0-RTT |
| 可靠性 | 确认、重传、去重 | 不保证 | 确认、重传、去重 |
| 有序/边界 | 全连接有序，字节流 | 不保证有序，保留边界 | 流内有序；DATAGRAM 有边界 |
| 拥塞/流量控制 | 有 | 无 | 有，用户态可插拔 |
| 头部开销 | 20–60B + IP | 8B + IP | 短头 + CID + 包号 + AEAD，通常大于 UDP |
| 握手延迟 | TCP 1 RTT；TFO 可 0-RTT | 0 | 1-RTT；恢复可 0-RTT |
| 队头阻塞 | 有（全连接） | 无（传输层） | 流间无，包内仍有 |
| 广播/多播 | 不支持 | 支持 | 不支持 |
| NAT 兼容 | 好 | 好，但可能被防火墙限制 | 依赖 UDP 443，可能被限 |
| 加密 | 需 TLS/IPsec | 需应用层 | 内建 TLS 1.3 |
| 适用场景 | Web、SSH、数据库、文件、邮件 | DNS、DHCP、RTP、游戏、隧道 | HTTP/3、移动 Web、实时多流 |
| 应用层示例 | HTTP/1.1、HTTP/2、SMTP、FTP、SSH、MySQL | DNS、DHCP、NTP、SNMP、RTP、QUIC | HTTP/3、DoQ、部分游戏/加速 |

表格是典型画像，不是绝对规则：DNS 主要 UDP，但区域传送/大响应用 TCP；MQTT 通常 TCP，也有 MQTT over QUIC。

<a id="sec13"></a>
## 13. 选型决策清单

```text
需要可靠、有序、字节流？
├─ 是 → 需要多流/0-RTT/连接迁移/移动优化？
│        ├─ 是 → QUIC（HTTP/3、移动端、可控用户态）
│        └─ 否 → TCP（生态成熟、NAT 友好、内核优化）
└─ 否 → 能容忍丢包/乱序，或需要广播/多播/极低握手延迟？
         ├─ 是 → UDP（DNS、RTP、游戏、隧道、发现）
         └─ 否 → 需要“可靠但低延迟” → QUIC/KCP/自研 ARQ
```

逐项问：①语义：必须可靠有序还是可丢？需要消息边界吗？②延迟：握手 RTT、队头阻塞、重传可接受吗？③网络：UDP 是否被封？需要广播/多播吗？④生态：TLS、HTTP、负载均衡、可观测性、内核参数成熟吗？⑤成本：自研可靠 UDP 要处理 ACK、重传、拥塞、加密、NAT、放大攻击，成本远高于“选 UDP”。⑥公平性：UDP 无拥塞控制会挤占带宽，生产应用应使用带拥塞控制的协议。⑦安全：UDP 易被反射放大（DNS/NTP/memcached），需限速、认证、反欺骗。

经验：通用业务、HTTP/1.1、数据库、SSH、文件优先 TCP；公网 Web/移动、多流/0-RTT/迁移优先 QUIC；实时媒体、游戏、DNS、DHCP、局域网发现、隧道优先 UDP；不要轻易自研“可靠 UDP”，先评估 QUIC/KCP。

<a id="sec14"></a>
## 14. 动手与命令速查

### 14.1 Windows

```powershell
netstat -ano                              # 所有连接与 PID
netstat -ano | findstr :8080              # 按端口
netstat -ano | findstr TIME_WAIT          # TIME_WAIT
Get-NetTCPConnection -State TimeWait | Measure-Object
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress,LocalPort,OwningProcess
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess
Test-NetConnection example.com -Port 443
Get-Process -Id <PID>
curl.exe -v https://example.com
curl.exe -v --http2 https://example.com
```

### 14.2 Linux

```bash
ss -tanp                      # 所有 TCP，含进程
ss -lntp                      # 监听端口
ss -tan state time-wait
ss -tan state close-wait
ss -tan state syn-recv
ss -s                         # 汇总
lsof -i :8080
lsof -iTCP -sTCP:LISTEN -P -n
netstat -s                    # 重传、超时、半连接等
nstat -az | grep -iE 'retrans|timeout|syn'
```

### 14.3 tcpdump

```bash
tcpdump -i any -nn 'tcp port 80'
tcpdump -i any -nn 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'
tcpdump -i any -nn 'tcp[tcpflags] & tcp-rst != 0'
tcpdump -i any -nn 'udp port 53'
tcpdump -i any -nn 'host 192.0.2.10 and port 443'
tcpdump -i any -nn -A 'tcp port 80'
tcpdump -i any -nn -w tcp.pcap 'tcp port 443'
tcpdump -r tcp.pcap -nn -A
```

### 14.4 Wireshark 过滤器

| 过滤器 | 用途 |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | 只看 SYN |
| `tcp.flags.reset == 1` | 只看 RST |
| `tcp.analysis.retransmission` | 重传 |
| `tcp.analysis.fast_retransmission` | 快速重传 |
| `tcp.analysis.duplicate_ack` | 重复 ACK |
| `tcp.analysis.zero_window` | 零窗口 |
| `tcp.analysis.window_update` | 窗口更新 |
| `tcp.stream eq 0` | 跟踪某条 TCP 流 |
| `tcp.len > 0` | 只看带数据段 |
| `tcp.options.mss_val` | MSS |
| `tcp.options.wscale.shift` | 窗口缩放因子 |
| `http.request.method == "GET"` | HTTP GET |
| `tls.handshake.type == 1` | TLS ClientHello |
| `dns.flags.response == 0` | DNS 查询 |
| `quic` | QUIC |
| `icmp` | ICMP（PMTUD 问题） |

### 14.5 curl 与 nc

```bash
curl -v https://example.com
curl -v --http1.1 https://example.com
curl -v --http2 https://example.com
curl -v --http3 https://example.com       # 若 curl 支持
nc -vz example.com 443                     # OpenBSD netcat
nc -vz -u example.com 53
ncat -zv example.com 443                   # Windows Nmap
```

排查顺序：`ss -lntp`/`netstat -ano` 看监听与 PID → `curl -v`/`nc -vz` 看 DNS/TCP/TLS/HTTP 哪步失败 → `tcpdump`/Wireshark 看 SYN/SYN+ACK/RST/重传/零窗口/ICMP → 应用日志、线程栈、连接池、fd 限制 → 区分网络不通、端口未监听、防火墙 RST、应用不 accept/不 close。

<a id="sec15"></a>
## 15. 面试高频 25 问速答

<a id="q1"></a>
<details>
<summary>Q1：传输层与网络层的区别？端口和五元组？</summary>

网络层负责主机到主机的寻址/路由（IP），传输层负责进程到进程交付（端口）。五元组是源 IP、源端口、目的 IP、目的端口、协议，唯一标识连接/会话方向。端口 16 位，0–1023 知名，49152–65535 常作临时端口。

</details>

<a id="q2"></a>
<details>
<summary>Q2：TCP 与 UDP 的核心区别？</summary>

TCP 面向连接、可靠、有序、字节流、有流量/拥塞控制，头 20–60B；UDP 无连接、不可靠、保留报文边界、无拥塞控制，头 8B。TCP 适合可靠传输，UDP 适合低延迟、广播/多播或应用自定义可靠性。

</details>

<a id="q3"></a>
<details>
<summary>Q3：描述三次握手。</summary>

客户端发 `SYN, seq=x`；服务器回 `SYN+ACK, seq=y, ack=x+1`；客户端回 `ACK, seq=x+1, ack=y+1`。SYN 消耗一个序号，第三次 ACK 可带数据；双方交换 ISN 并确认收发能力，进入 `ESTABLISHED`。

</details>

<a id="q4"></a>
<details>
<summary>Q4：为什么是三次，不是两次或四次？</summary>

两次无法让服务器确认客户端收到了 SYN+ACK，客户端接收方向也未确认；四次多余，因为服务器 SYN 与对客户端 SYN 的 ACK 可合并，客户端第三次 ACK 已确认服务器 SYN且不需再被确认。

</details>

<a id="q5"></a>
<details>
<summary>Q5：描述四次挥手。</summary>

主动方发 `FIN, seq=u`；被动方回 `ACK, ack=u+1`，进入 `CLOSE_WAIT`；被动方发完剩余数据后发 `FIN, seq=w`；主动方回 `ACK, ack=w+1`，进入 `TIME_WAIT`，等 2MSL 后关闭。FIN 消耗一个序号。

</details>

<a id="q6"></a>
<details>
<summary>Q6：为什么挥手是四次，不是三次？</summary>

TCP 全双工，两个方向独立关闭。被动方收到 FIN 后可能还有数据，所以先 ACK，发完再 FIN；只有恰好无剩余数据时 ACK 与 FIN 才可能合并，抓包像三个包，逻辑仍是四步。

</details>

<a id="q7"></a>
<details>
<summary>Q7：TIME_WAIT 的作用和时长？</summary>

作用：保证最后 ACK 丢失时还能重发 ACK，让对端正常关闭；等待 2MSL 让旧连接延迟段消亡，避免污染复用同一四元组的新连接。理论 2MSL（传统 4 分钟），Linux 常见约 60 秒，Windows `TcpTimedWaitDelay` 默认常见 120 秒。

</details>

<a id="q8"></a>
<details>
<summary>Q8：CLOSE_WAIT 与 TIME_WAIT 过多分别说明什么？</summary>

`CLOSE_WAIT` 多说明对端已 FIN，本端应用没 `close()`，通常是代码/连接池/线程阻塞。`TIME_WAIT` 多是主动关闭后的正常状态，短连接高并发会很多；只有端口/四元组耗尽才需优化，不能简单归为故障。

</details>

<a id="q9"></a>
<details>
<summary>Q9：RST 常见于哪些场景？</summary>

连接不存在的端口、应用崩溃/异常终止、`SO_LINGER=0`、收到窗口外/非法段、半开连接、防火墙或中间设备拒绝、accept 队列溢出等。RST 立即中止，不保证数据送达，通常不进入 TIME_WAIT。

</details>

<a id="q10"></a>
<details>
<summary>Q10：SYN Flood 与 SYN Cookie？</summary>

攻击者伪造大量 SYN，服务器为半连接分配状态并重传 SYN+ACK，耗尽 SYN 队列。SYN Cookie 不保存半连接状态，把四元组、时间、MSS 等编码进 SYN+ACK 序列号；收到第三次 ACK 时验证 cookie 再建连。它抗队列耗尽，但可能丢失窗口缩放/SACK 选项。

</details>

<a id="q11"></a>
<details>
<summary>Q11：ISN 为什么必须随机？</summary>

固定或可预测 ISN 会让旧连接延迟段被新连接误收，也方便攻击者伪造序列号、注入数据或盲打 RST。RFC 6528 建议用时钟 + 四元组哈希 + 秘密值生成。随机化提高攻击成本，但不等于加密。

</details>

<a id="q12"></a>
<details>
<summary>Q12：TCP 的 11 种状态？</summary>

`CLOSED`、`LISTEN`、`SYN_SENT`、`SYN_RCVD`、`ESTABLISHED`、`FIN_WAIT_1`、`FIN_WAIT_2`、`CLOSE_WAIT`、`CLOSING`、`LAST_ACK`、`TIME_WAIT`。主动打开经 `SYN_SENT`，被动打开经 `LISTEN`/`SYN_RCVD`；关闭分主动、被动、同时关闭。

</details>

<a id="q13"></a>
<details>
<summary>Q13：为什么 TCP 按字节编号，而不是按包？</summary>

TCP 段大小可变，按包无法表达“部分字节收到”。字节编号配合累计 ACK，能精确描述连续区间、乱序、空洞和部分重传；段可合并/切分而不影响语义。SYN/FIN 各占一个序号，纯 ACK 不占。

</details>

<a id="q14"></a>
<details>
<summary>Q14：累计确认与延迟 ACK？</summary>

`ACK=n` 表示 n 之前所有字节都收到，n 是下一个期望字节；这是累计确认。延迟 ACK 是接收方等一小段时间再确认，以合并 ACK 或捎带数据；RFC 1122 要求至少每两个满段确认一次，延迟不超过 500ms，Linux 常见 40–200ms。

</details>

<a id="q15"></a>
<details>
<summary>Q15：RTO 怎么算？Karn 算法是什么？</summary>

RFC 6298：首个样本 `SRTT=R, RTTVAR=R/2, RTO=SRTT+max(G,4RTTVAR)`；后续 `RTTVAR=(1-1/4)RTTVAR+1/4|SRTT-R'|`，`SRTT=(1-1/8)SRTT+1/8R'`，再算 RTO。Karn 规定重传过的段不用于 RTT 采样，并对重传指数退避。

</details>

<a id="q16"></a>
<details>
<summary>Q16：快速重传/快速恢复？为什么是 3 个重复 ACK？</summary>

发送方连续收到 3 个重复 ACK（同一 ACK 号、无新数据），说明丢失段之后的数据已到达，接收方在催空洞；立即重传，不等 RTO。快速恢复把 `ssthresh` 减半，`cwnd=ssthresh+3MSS`，每个 dup ACK 再 `+MSS`，新 ACK 后回到 `ssthresh`。

</details>

<a id="q17"></a>
<details>
<summary>Q17：SACK 与 D-SACK 解决什么？</summary>

SACK 让接收方报告已收到的非连续块，发送方只重传空洞，避免多丢包时从头重传。D-SACK 报告重复段，帮助识别伪重传、网络重复和 ACK 丢失。SACK 是累计 ACK 的补充，不替代累计确认。

</details>

<a id="q18"></a>
<details>
<summary>Q18：滑动窗口、rwnd、cwnd 与零窗口？</summary>

`rwnd` 是接收方通告的接收能力，`cwnd` 是发送方估计的网络容量，发送窗口 `=min(rwnd,cwnd)`。窗口左边界随 ACK 右移；可用窗口为 `UNA+WND-NXT`。零窗口时发送方停发，用坚持定时器发窗口探测，防止窗口更新丢失造成死锁。

</details>

<a id="q19"></a>
<details>
<summary>Q19：Nagle 与延迟 ACK 为什么造成 40ms 延迟？</summary>

当请求被拆成多次小写，或双向小包交互时：发送方先发一小段；接收方延迟 ACK；Nagle 因有未确认数据扣住下一小段；下一小段要等 ACK，于是多等一个延迟 ACK 周期（Linux 常见 40ms，部分实现 200ms）。`TCP_NODELAY` 可关闭 Nagle，合并写/`writev` 也能缓解。

</details>

<a id="q20"></a>
<details>
<summary>Q20：什么是糊涂窗口综合征（SWS）？</summary>

双方反复交换极小窗口/数据，导致大量小包、有效吞吐很低。接收方应避免通告只增加几字节的窗口（Clark 算法：等到能容纳 MSS 或半个缓冲区）；发送方用 Nagle 避免小段。核心是不要用微小窗口/小段喂网络。

</details>

<a id="q21"></a>
<details>
<summary>Q21：AIMD、慢启动、拥塞避免？</summary>

AIMD 是加性增、乘性减：无拥塞时每 RTT 约 `+1 MSS`，拥塞时乘性减小。慢启动每 ACK `+1 MSS`，每 RTT 翻倍，直到 `ssthresh`；之后拥塞避免每 RTT 约 `+1 MSS`。超时把 `cwnd` 降到 1 MSS，3 个重复 ACK 走快速重传/恢复。

</details>

<a id="q22"></a>
<details>
<summary>Q22：Tahoe、Reno、NewReno、CUBIC、BBR 的差异？</summary>

Tahoe 任何丢包都回慢启动；Reno 引入快速重传/恢复，但一个窗口多丢包处理差；NewReno 用 partial ACK 处理多丢包；CUBIC 用时间三次函数增长、丢包仍是信号，Linux 长期默认；BBR 用瓶颈带宽和最小 RTT 建模、pacing 发送，不把丢包当唯一信号，但并非 RFC，版本差异大。

</details>

<a id="q23"></a>
<details>
<summary>Q23：ECN 是什么？流量控制与拥塞控制区别？</summary>

ECN 让路由器拥塞时把 IP 头 CE 置 1，而非丢包；接收方用 TCP ECE 回显，发送方降窗并置 CWR。流量控制保护接收方缓冲（`rwnd`），拥塞控制保护网络（`cwnd`）；发送窗口取两者最小值。

</details>

<a id="q24"></a>
<details>
<summary>Q24：Keepalive、MSS/MTU、粘包？</summary>

TCP Keepalive 是空闲连接探测（Linux 默认 2h 起、75s 间隔、9 次），HTTP Keep-Alive 是应用层复用。MSS 是 TCP 载荷上限，MTU 是 IP 包上限；以太网 IPv4 典型 MSS=1460。TCP 是字节流，粘包/拆包本质是应用层没定义消息边界，可用长度前缀、分隔符、固定长度解决。

</details>

<a id="q25"></a>
<details>
<summary>Q25：QUIC 为什么基于 UDP？“可靠 UDP”是什么？如何选型？</summary>

QUIC 基于 UDP 是为了绕过内核 TCP 的实现/部署限制，在用户态实现可靠传输、TLS 1.3、多流、连接迁移和可插拔拥塞控制；仍需处理 UDP 被封、CPU 开销和 NAT。所谓“可靠 UDP”不是标准名，通常指 QUIC/KCP/UDT/自研 ARQ。选型看可靠性、延迟、广播/多播、网络可达性和实现成本，优先 TCP 或 QUIC，避免轻易自研。

</details>

<a id="sec16"></a>
## 16. 学习路线图

### 阶段一：建立骨架（约 1 周）

目标：能画 TCP/UDP 头，复述三次握手/四次挥手，解释五元组/端口，用工具看到真实连接。

- 精读第 1–6 章；手画 TCP 头、UDP 头、握手/挥手时序图。
- Wireshark 抓 `curl -v https://example.com`，找 DNS、TCP 握手、TLS、HTTP、挥手。
- 用 `ss -tanp`/`netstat -ano` 观察 `LISTEN`、`ESTABLISHED`、`TIME_WAIT`。
- 实验：写 TCP echo 服务 + 客户端，用 `nc` 连接并抓包。

### 阶段二：理解机制（约 2 周）

目标：能解释可靠传输、滑动窗口、拥塞控制、Nagle/延迟 ACK，并从抓包判断重传/零窗口/乱序。

- 精读第 7–10 章；推导 RFC 6298 的 RTO 公式并手算。
- Linux/WSL2 用 `tc netem` 注入延迟/丢包/乱序，观察重传、快速重传、SACK、cwnd。
- 写 Python 长度前缀协议，故意分片发送，验证 `recv()` 边界与粘包。
- 对比 `TCP_NODELAY` 开/关的请求延迟，用 `tcpdump` 观察小包。
- 用 `ss -ti` 看 `cwnd`、`rtt`、`retrans`，用 Wireshark `tcp.analysis` 定位问题。

### 阶段三：工程与进阶（约 2–3 周）

目标：能做协议选型、排查线上连接问题，理解 QUIC/可靠 UDP 的取舍。

- 精读第 11–14 章；对比 QUIC、KCP、SCTP。
- 用 `curl --http3` 或浏览器 DevTools 观察 HTTP/3；抓 QUIC 包（解密需密钥）。
- 读一个 QUIC 实现的关键模块（quiche/ngtcp2）或 KCP 的 ARQ 逻辑，理解 ACK/重传/拥塞接口。
- 故障演练：端口未监听、RST、零窗口、PMTUD 黑洞，记录排查路径。
- 输出自己的 TCP 排障 checklist，并在项目/压测中验证。

实验环境：Windows 本机用 Wireshark、PowerShell、`curl.exe`、Nmap `ncat`；Linux/WSL2/Docker/云主机用 `ss`、`tcpdump`、`tc`、`sysctl`。不要在生产随意改 `tcp_tw_recycle`、`tcp_abort_on_overflow`、`SO_LINGER=0`。

<a id="appendix-a"></a>
## 附录 A：关键 RFC 与常见误区

| RFC | 主题 | 关键点 |
|---|---|---|
| RFC 768 | UDP | 8B 头、伪首部校验和 |
| RFC 9293 | TCP | 现行 TCP 核心规范，替代 RFC 793 等 |
| RFC 6298 | 重传定时器 | SRTT/RTTVAR/RTO、Karn |
| RFC 5681 | 拥塞控制 | 慢启动、拥塞避免、快速重传/恢复 |
| RFC 2018 | SACK | 选择性确认块 |
| RFC 2883 | D-SACK | 重复段报告 |
| RFC 7323 | 窗口缩放/时间戳 | shift≤14，最大约 1GiB；PAWS |
| RFC 3168 | ECN | CE/ECT/ECE/CWR |
| RFC 6528 | ISN 安全 | 时钟 + 四元组哈希 + 秘密 |
| RFC 7413 | TFO | SYN 带数据、Cookie |
| RFC 9000/9001/9002 | QUIC | 传输框架、TLS 1.3、恢复 |
| RFC 9221 | QUIC DATAGRAM | 不可靠数据报 |
| RFC 4960/6951 | SCTP | 多流/多宿主；UDP 封装 |
| RFC 3758 | PR-SCTP | 部分可靠 |

| 误区 | 纠正 |
|---|---|
| “TCP 是可靠 UDP” | TCP/UDP 是独立协议；QUIC 才是基于 UDP 的可靠传输 |
| “三次握手保证可靠传输” | 握手同步 ISN、确认收发能力；可靠性靠 ACK/重传/排序 |
| “TIME_WAIT 是 bug” | 正常的安全/可靠关闭机制；过多才结合场景优化 |
| “窗口最大 64KB” | 未缩放 64KB；缩放后最大约 1GiB |
| “Nagle 一定导致 40ms” | 需未确认小段 + 延迟 ACK + 多次小写/双向小包等条件 |
| “3 个 ACK 触发快速重传” | 是 3 个**重复** ACK，抓包常见 4 个相同 ACK |
| “UDP 一定比 TCP 快” | UDP 省握手/重传，但补可靠性后未必更快，还可能被限速 |
| “QUIC 完全没有队头阻塞” | 流间无队头阻塞；流内仍有序，包内丢包仍阻塞相关流 |
| “MSS 是 MTU” | MSS 只算 TCP 载荷；MTU 是 IP 包总长上限 |
| “`SO_REUSEADDR` 消除 TIME_WAIT” | 只影响绑定规则，不消除 TIME_WAIT |

> 最后提醒：协议细节以 RFC 和实际内核行为为准；不同系统、内核版本、云网络设备可能有差异。抓包、日志、计数器交叉验证，比背结论更可靠。
