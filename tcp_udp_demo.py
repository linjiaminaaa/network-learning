#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP / UDP 动手实验脚本（Python 3.7+，零第三方依赖，仅用标准库）

用法：
    python tcp_udp_demo.py tcp       # TCP 回显：connect/accept/send/recv 与内核缓冲区
    python tcp_udp_demo.py udp       # UDP：无连接 + 应用层“丢包”后不会自动重传
    python tcp_udp_demo.py framing   # TCP 粘包/拆包：裸 recv vs 长度前缀分帧
    python tcp_udp_demo.py bench     # TCP vs UDP 回环吞吐粗略对比
    python tcp_udp_demo.py listen 9000   # 监听一个端口，配合 netstat / Wireshark 观察

配套：
    - 交互实验室：tcp-udp-lab.html（浏览器打开）
    - 系统手册：TCP-UDP-系统学习手册.md
"""

import argparse
import socket
import struct
import sys
import threading
import time

HOST = "127.0.0.1"
BUF = 4096


# ---------------------------------------------------------------- 工具函数
def log(tag, msg):
    """统一格式的日志：tag 表示客户端/服务端。"""
    print("[%-6s] %s" % (tag, msg), flush=True)


def tcp_server():
    """创建一个只监听本机随机端口的 TCP 服务端。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 0))
    srv.listen(8)
    return srv, srv.getsockname()[1]


def recv_exact(conn, n):
    """从 TCP 字节流里精确读出 n 个字节（处理“一次 recv 只读到一半”）。"""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("对端提前关闭，期望 %d 字节，实际 %d 字节" % (n, len(buf)))
        buf += chunk
    return buf


def port_hint(port):
    print()
    print("提示：另开一个终端观察端口状态")
    print("  Windows: netstat -ano | findstr :%d" % port)
    print("  Linux  : ss -tanp | grep %d" % port)
    print("  Wireshark 过滤器: tcp.port == %d" % port)
    print()


# ---------------------------------------------------------------- 1. TCP
def demo_tcp():
    srv, port = tcp_server()
    log("SERVER", "TCP 监听 %s:%d（listen 之后端口才可被连接）" % (HOST, port))

    def serve():
        conn, addr = srv.accept()
        log("SERVER", "accept() 返回 -> 对端 %s:%d" % addr)
        log("SERVER", "注意：accept 之前内核已完成三次握手，连接早已在 backlog 队列里")
        data = conn.recv(BUF)
        log("SERVER", "recv() 收到 %d 字节: %r" % (len(data), data))
        conn.sendall(b"echo:" + data)
        conn.close()
        log("SERVER", "close() 本端主动关闭，开始四次挥手")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.05)

    cli = socket.create_connection((HOST, port))
    log("CLIENT", "connect() 成功：本地 %s:%d -> 远端 %s:%d" % (
        cli.getsockname() + cli.getpeername()))
    log("CLIENT", "SO_SNDBUF = %d 字节（内核发送缓冲区，应用 write 成功≠对端收到）"
        % cli.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
    log("CLIENT", "SO_RCVBUF = %d 字节（接收缓冲区，窗口 rwnd 的上限来源之一）"
        % cli.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
    cli.sendall(b"hello tcp")
    log("CLIENT", "sendall() 把数据交给内核就返回，注意它不等待 ACK")
    data = cli.recv(BUF)
    log("CLIENT", "recv() 收到: %r" % data)
    cli.close()
    t.join(1)
    srv.close()
    port_hint(port)
    print("结论：TCP 的 connect() 内部完成了三次握手；应用层看到的永远是“字节流”。")


# ---------------------------------------------------------------- 2. UDP
def demo_udp():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((HOST, 0))
    port = srv.getsockname()[1]
    log("SERVER", "UDP 绑定 %s:%d（没有 listen / accept / connect）" % (HOST, port))

    stop = threading.Event()
    srv.settimeout(0.3)

    def serve():
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(BUF)
            except socket.timeout:
                continue
            seq = int(data.split(b":")[0])
            if seq == 3:
                log("SERVER", "模拟丢包：收到 seq=%d，故意不回复" % seq)
                continue
            srv.sendto(b"ack:%d" % seq, addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.settimeout(1.0)
    log("CLIENT", "发送前不需要握手，直接 sendto")
    lost = []
    for seq in range(1, 6):
        cli.sendto(b"%d:payload" % seq, (HOST, port))
        log("CLIENT", "sendto(seq=%d) 已发出" % seq)
        try:
            data, addr = cli.recvfrom(BUF)
            log("CLIENT", "recvfrom 收到 %r（一个数据报 = 一条完整消息）" % data)
        except socket.timeout:
            lost.append(seq)
            log("CLIENT", "seq=%d 超时：UDP 不会自动重传，丢了就是丢了" % seq)
    cli.close()
    stop.set()
    t.join(0.6)
    srv.close()
    print()
    print("结果：丢失的序号 = %s。要可靠，必须在应用层自己做序号 + 确认 + 重传（QUIC/KCP 的思路）。"
          % lost)
    print("同时注意 UDP 保留消息边界：一次 recvfrom 对应一个数据报，不会出现 TCP 那种粘包。")


# ---------------------------------------------------------------- 3. 粘包/拆包
def demo_framing():
    srv, port = tcp_server()
    msg = b"hello"
    # 长度前缀：4 字节大端长度 + 负载
    frame = struct.pack("!I", len(msg)) + msg

    def serve():
        for _ in range(2):                      # 两个客户端各服务一次
            conn, _addr = srv.accept()
            # 两条“应用消息”拼在一起只调用一次 sendall
            conn.sendall(frame + frame)
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    # 客户端 A：朴素 recv，把两条消息当成一坨
    a = socket.create_connection((HOST, port))
    got = a.recv(BUF)
    log("NAIVE", "一次 recv(4096) 收到 %d 字节: %r" % (len(got), got))
    log("NAIVE", "两条消息被合并了（粘包）——TCP 是字节流，不保留消息边界")
    a.close()

    # 客户端 B：长度前缀分帧
    b = socket.create_connection((HOST, port))
    for i in range(2):
        raw_len = recv_exact(b, 4)
        (length,) = struct.unpack("!I", raw_len)
        payload = recv_exact(b, length)
        log("FRAME", "第 %d 条消息: %r（先读 4 字节长度，再读正文）" % (i + 1, payload))
    b.close()
    t.join(1)
    srv.close()
    print()
    print("结论：分帧方案有三种 —— 固定长度 / 分隔符（如 \\r\\n）/ 长度前缀（最通用）。")
    print("      UDP 不需要分帧，因为数据报本身就有边界。")


# ---------------------------------------------------------------- 4. 吞吐对比
def demo_bench(n=3000, size=64):
    payload = b"x" * size

    # TCP echo
    srv, port = tcp_server()

    def tcp_echo():
        conn, _ = srv.accept()
        while True:
            d = conn.recv(BUF)
            if not d:
                break
            conn.sendall(d)

    t1 = threading.Thread(target=tcp_echo, daemon=True)
    t1.start()
    cli = socket.create_connection((HOST, port))
    t0 = time.perf_counter()
    for _ in range(n):
        cli.sendall(payload)
        recv_exact(cli, size)
    tcp_elapsed = time.perf_counter() - t0
    cli.close()
    t1.join(0.6)
    srv.close()
    time.sleep(0.05)

    # UDP echo
    usrv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usrv.bind((HOST, 0))
    uport = usrv.getsockname()[1]

    ustop = threading.Event()
    usrv.settimeout(0.3)

    def udp_echo():
        while not ustop.is_set():
            try:
                d, addr = usrv.recvfrom(BUF)
            except socket.timeout:
                continue
            usrv.sendto(d, addr)

    t2 = threading.Thread(target=udp_echo, daemon=True)
    t2.start()
    ucli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ucli.settimeout(2.0)
    t0 = time.perf_counter()
    for _ in range(n):
        ucli.sendto(payload, (HOST, uport))
        ucli.recvfrom(BUF)
    udp_elapsed = time.perf_counter() - t0
    ucli.close()
    ustop.set()
    t2.join(0.6)
    usrv.close()

    print("回环 127.0.0.1，每个包 %d 字节，各 %d 次往返：" % (size, n))
    print("  TCP 用时 %.3f s  ->  %.0f 次/秒" % (tcp_elapsed, n / tcp_elapsed))
    print("  UDP 用时 %.3f s  ->  %.0f 次/秒" % (udp_elapsed, n / udp_elapsed))
    print()
    print("注意：回环几乎不丢包，这个对比只反映“系统调用 + 协议栈”的开销差异，")
    print("      不代表公网表现。真实网络里 UDP 丢了不会重传，TCP 会重传但延迟上升。")


# ---------------------------------------------------------------- 5. 监听端口
def demo_listen(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as exc:
        print("绑定端口 %d 失败：%s" % (port, exc))
        return
    srv.listen(4)
    print("已在 0.0.0.0:%d 监听，等待一个连接……" % port)
    port_hint(port)
    print("可以另开终端执行：curl -v http://127.0.0.1:%d/" % port)
    print("或：python -c \"import socket;s=socket.create_connection(('127.0.0.1',%d));print(s.getsockname())\"" % port)
    conn, addr = srv.accept()
    log("SERVER", "accept 对端 %s:%d（三次握手已完成）" % addr)
    data = conn.recv(BUF)
    log("SERVER", "收到 %d 字节" % len(data))
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
    conn.close()
    srv.close()
    log("SERVER", "已关闭连接")


# ---------------------------------------------------------------- 入口
def main():
    parser = argparse.ArgumentParser(
        description="TCP / UDP 动手实验（配合 tcp-udp-lab.html 与系统学习手册）")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("tcp", help="TCP 回显：connect/accept/send/recv")
    sub.add_parser("udp", help="UDP：无连接 + 应用层丢包不重传")
    sub.add_parser("framing", help="TCP 粘包/拆包与长度前缀分帧")
    sub.add_parser("bench", help="TCP vs UDP 回环吞吐对比")
    p_listen = sub.add_parser("listen", help="监听一个端口，配合 netstat/Wireshark")
    p_listen.add_argument("port", nargs="?", type=int, default=9000, help="监听端口，默认 9000")

    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        print()
        print("建议顺序：tcp -> udp -> framing -> bench，配合浏览器里的交互实验室一起看。")
        return
    if args.cmd == "tcp":
        demo_tcp()
    elif args.cmd == "udp":
        demo_udp()
    elif args.cmd == "framing":
        demo_framing()
    elif args.cmd == "bench":
        demo_bench()
    elif args.cmd == "listen":
        demo_listen(args.port)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已中断")
        sys.exit(0)
