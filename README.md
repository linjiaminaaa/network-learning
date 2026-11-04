# 学习包索引

本工作区有两个独立的网络学习包，互不依赖，可各自单独使用：

| 学习包 | 主题 | 入口 | 内容 |
|---|---|---|---|
| 一 | 传输层：TCP / UDP / QUIC | 本文件下方 | 交互实验室 + ~1000 行手册 + socket 实验脚本 + 同类项目调研 |
| 二 | 游戏网络同步：**帧同步 / 状态同步** | [`game-sync/README.md`](game-sync/README.md) | 8 模块交互实验室 + 2056 行手册 + 真实 UDP 多进程演示 + 可核查的开源项目调研（28 个仓库） |

---

# TCP / UDP 学习包

一套「能读、能点、能跑」的传输层学习材料，纯本地、零依赖、可离线。

## 文件说明

| 文件 | 类型 | 说明 |
|---|---|---|
| [`tcp-udp-lab.html`](tcp-udp-lab.html) | 交互实验室 | 单文件网页，双击用浏览器打开。8 个模块：概览选型、报文结构、握手/挥手动画、滑动窗口与重传仿真、流量/拥塞控制、TCP vs UDP vs QUIC 对比、抓包分析（pcap/pcapng 导入 + 序号-时间图）、命令与面试速查 |
| [`TCP-UDP-系统学习手册.md`](TCP-UDP-系统学习手册.md) | 系统手册 | 约 1000 行，16 章 + 附录：字段级细节、状态机迁移表、RTO 公式、拥塞控制、工程排查、25 道面试速答 |
| [`tcp_udp_demo.py`](tcp_udp_demo.py) | 实验脚本 | Python 3.7+ 标准库，无第三方依赖；真实 socket 演示 TCP/UDP、粘包、吞吐 |
| [参考项目调研与改进清单.md](参考项目调研与改进清单.md) | 调研记录 | 同类开源项目的优点、与本次交付物的对比矩阵、后续改进优先级 |
| `README.md` | 本文件 | 使用说明与学习路径 |

## 快速开始

**1. 打开实验室**

直接双击 `tcp-udp-lab.html`（Chrome / Edge / Firefox 均可）。

左侧 8 个模块，建议按顺序点一遍：

1. **概览与选型**：先建立「TCP / UDP / QUIC」三张地图，做三题选型助手。
2. **报文结构**：点击 TCP 每个字段看说明；拨动 8 个标志位看十六进制变化。
3. **三次握手 / 四次挥手**：单步或自动播放；切换 3 个异常场景（SYN 丢失、SYN+ACK 丢失、第三次 ACK 丢失）。
4. **滑动窗口**：先点一个序号标记「会丢包」，再播放 —— 看超时重传与 3 次重复 ACK 触发的快速重传。
5. **流量 / 拥塞控制**：点「发送」填满接收缓冲区看 rwnd=0；点「运行」看 cwnd 曲线，随时「注入丢包」观察 Tahoe/Reno 差异。
6. **TCP vs UDP vs QUIC**：选一个丢包位置，运行实验，看「队头阻塞 / 永久丢失 / 按流隔离」三种结果。
7. **抓包分析（pcap）**：把 `.pcap` / `.pcapng` 拖进来，或点「载入内置示例 trace」；左侧报文列表点任意一行看字段与十六进制，下方看该 TCP 流的**序号-时间图**（可识别重传）。也可以下载示例 pcap 用 Wireshark 对照。
8. **命令与面试**：抓包过滤器、netstat/ss、10 题即时判分自测（答错给解析）、8 道高频题折叠答案。

**2. 跑真实 socket 实验**

```powershell
cd E:\DeepSeekHarmess\学习
python tcp_udp_demo.py tcp       # connect/accept/send/recv、内核缓冲区
python tcp_udp_demo.py udp       # 无连接 + 应用层丢包不重传
python tcp_udp_demo.py framing   # 粘包/拆包 + 长度前缀分帧
python tcp_udp_demo.py bench     # TCP vs UDP 回环吞吐
python tcp_udp_demo.py listen 9000   # 监听端口，配合 netstat/Wireshark
```

抓包对照：先开 Wireshark 过滤 `tcp.port == 9000`，再运行 `listen`，另开终端 `curl -v http://127.0.0.1:9000/`。

**3. 读手册**

`TCP-UDP-系统学习手册.md` 建议用支持目录跳转的编辑器（Typora / VS Code / Obsidian）打开。第 15 章的 25 问适合面试前自测。

## 建议学习节奏

| 时间 | 内容 | 验收标准 |
|---|---|---|
| 第 1 天 | 手册 1–6 章 + 实验室 1–3 | 能默画 TCP/UDP 头、三次握手/四次挥手时序，解释 TIME_WAIT |
| 第 2 天 | 手册 7–9 章 + 实验室 4–5 | 能解释累计 ACK、快速重传、rwnd 与 cwnd 的区别，算一遍 RTO |
| 第 3 天 | 手册 10–14 章 + 跑 demo + 抓包 | 能用 ss/netstat/Wireshark 定位重传、零窗口、CLOSE_WAIT 过多；能导入自己的 pcap 并读懂序号-时间图 |
| 第 4 天 | 手册 15 章 + 实验室 6–8 | 25 问能答出 20 问以上，能说清 QUIC 为什么基于 UDP |

## 环境要求

- 浏览器：任意现代浏览器（实验室不含外部字体/CDN，离线可用）。
- Python：3.7+（实验脚本只用标准库；Windows 上 `python` 命令可用即可）。
- 抓包：可选，Wireshark / tcpdump。

## 说明

- 实验室里滑动窗口、拥塞控制、QUIC 对比都是**简化模型**，用于建立直觉，数值不代表真实内核实现。
- 手册中的平台默认值（TIME_WAIT 时长、延迟 ACK、Keepalive）随系统与版本变化，以本机 `sysctl` / 注册表 / 抓包为准。
- 协议细节以 RFC 与实际内核行为为准：RFC 9293（TCP）、RFC 768（UDP）、RFC 6298（RTO）、RFC 5681（拥塞控制）、RFC 9000（QUIC）。
