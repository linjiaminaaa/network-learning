#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
帧同步（Lockstep）真实 UDP 演示 —— 真实 socket、真实多进程、真实丢包与真实分歧。

一、它演示什么
    1. 一个「帧服务器进程」+ 3 个「客户端进程」，全部走真实的 UDP socket（127.0.0.1 随机端口）。
    2. 逻辑层用 Q16.16 定点数（自己实现加减乘除、开方），跑一个 2D 弹球 + 碰撞的小物理。
    3. 每帧广播「帧号 + 该帧所有玩家输入 + 冗余窗口」，客户端按输入逐帧确定性模拟。
    4. 客户端每 50 帧上报一次状态校验和，帧服务器负责比对 —— 这就是 desync 检测。
    5. 反例：同一套物理，用 float 跑三端会分歧（第 7 帧就出现 1 ULP 差异，500 帧后放大到 3.6），
       用定点数跑三端全程逐位一致。

二、子命令
    python lockstep_demo.py demo       # 真实 UDP 跑 200 帧，打印每 50 帧三端校验和（默认）
    python lockstep_demo.py desync     # 反例：float 会分歧 vs 定点不会（各跑 500 帧）
    python lockstep_demo.py jitter     # 30% 丢包 + 50–150ms 随机延迟：冗余帧 + 等帧卡顿
    python lockstep_demo.py catchup    # 一个客户端落后 60 帧后快进追帧
    python lockstep_demo.py replay     # 录制输入序列 -> 回放 -> 校验和一致
    python lockstep_demo.py bandwidth  # 锁步 vs 状态同步带宽估算对比表
    python lockstep_demo.py all        # 依次跑完以上全部

三、只用 Python 3.7+ 标准库；Windows 用 spawn 启动子进程，所有 worker 都是模块顶层函数。

四、本文件里的关键机制（代码里会标注 ←）
    · 确定性执行（定点数 + 固定运算顺序）
    · 输入帧广播 + 冗余帧（每包带最近 3 帧输入）
    · 未确认输入重发（帧服务器广播过的帧 = 已确认）
    · 历史帧补发 / 快进追帧
    · 校验和比对与 desync 判定
"""

import argparse
import heapq
import math
import multiprocessing as mp
import queue
import random
import socket
import struct
import sys
import time
import traceback
from dataclasses import dataclass

# ---------------------------------------------------------------- 常量
HOST = "127.0.0.1"
MAGIC = b"LOCK"
HEADER = struct.Struct("!4sBBH")          # magic, type, client_id, payload_len

MSG_JOIN = 1          # 客户端 -> 服务器：请求加入
MSG_JOIN_ACK = 2      # 服务器 -> 客户端：允许加入
MSG_INPUT = 3         # 客户端 -> 服务器：一包输入（含最近若干帧 + 未确认重发）
MSG_FRAME = 4         # 服务器 -> 客户端：一包帧数据（冗余窗口 / 历史帧补发）
MSG_CHECKSUM = 5      # 客户端 -> 服务器：状态校验和
MSG_CATCHUP = 6       # 客户端 -> 服务器：请求 [from, to] 的历史帧输入
MSG_END = 7           # 服务器 -> 客户端：本局结束
MSG_DONE = 8          # 客户端 -> 服务器：客户端已跑完
MSG_START = 9         # 服务器 -> 客户端：约定的开始时刻（所有进程共用 monotonic 时钟）

N_CLIENTS = 3
WIN = 3               # 冗余窗口：每个帧包携带最近 3 帧输入
MAX_RESEND = 8        # 最多重发多少帧「未被服务器确认」的旧输入
MAX_ENTRIES = 14      # 单个输入包最多带多少帧输入
TICK = 0.05          # 20 Hz（与状态同步演示的 tick 率一致，便于对比）
SEED = 20261101
TIMEOUT = 45.0        # 父进程看门狗

# Q16.16 定点数：低 16 位是小数
FX = 1 << 16
WORLD_W = 8 * FX
BALL_R = (11 * FX) // 20          # 0.55
ACCEL = (5 * FX) // 100           # 0.05
FRICTION_SHIFT = 5
N_BALLS = 5
IP_UDP = 28                       # IPv4(20) + UDP(8)，带宽估算用


try:                              # Python 3.8+ 自带；3.7 退回纯整数牛顿迭代
    from math import isqrt
except ImportError:               # pragma: no cover
    def isqrt(n):
        if n < 2:
            return n
        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x


# ================================================================
# 1. 通用工具：日志队列、结果队列、会丢包会延迟的 UDP 发送器
# ================================================================
def log_to(log_q, tag, msg):
    """子进程统一把日志塞进队列，父进程负责按顺序打印（避免多进程输出交错）。"""
    try:
        log_q.put((tag, msg))
    except Exception:
        pass


def build_packet(msg_type, client_id, payload=b""):
    return HEADER.pack(MAGIC, msg_type, client_id, len(payload)) + payload


def parse_packet(data):
    if len(data) < HEADER.size:
        return None
    magic, msg_type, cid, plen = HEADER.unpack_from(data, 0)
    if magic != MAGIC:
        return None
    body = data[HEADER.size:HEADER.size + plen]
    if len(body) != plen:
        return None
    return msg_type, cid, body


class JitterOutbox:
    """把 UDP 发送包装成「可丢包、可随机延迟」的发送队列。

    丢包 / 延迟都在应用层做，这样演示不依赖外部 tc/netem，Windows 上也能跑。
    UDP 本身不重传，所以这里丢掉的包就是真丢了 —— 后续靠帧同步自己的冗余补回来。
    """

    def __init__(self, sock, loss=0.0, delay_min=0.0, delay_max=0.0, rng=None):
        self.sock = sock
        self.loss = loss
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.rng = rng or random.Random()
        self._heap = []
        self._seq = 0
        self.sent_packets = 0
        self.sent_bytes = 0
        self.dropped_packets = 0

    def send(self, data, addr):
        if self.loss > 0 and self.rng.random() < self.loss:
            self.dropped_packets += 1
            return
        if self.delay_max > 0:
            due = time.monotonic() + self.rng.uniform(self.delay_min, self.delay_max)
            heapq.heappush(self._heap, (due, self._seq, data, addr))
            self._seq += 1
        else:
            self._raw(data, addr)

    def _raw(self, data, addr):
        try:
            self.sock.sendto(data, addr)
            self.sent_packets += 1
            self.sent_bytes += len(data)
        except OSError:
            self.dropped_packets += 1

    def flush(self, now=None):
        now = time.monotonic() if now is None else now
        while self._heap and self._heap[0][0] <= now:
            _, _, data, addr = heapq.heappop(self._heap)
            self._raw(data, addr)

    def pending(self):
        return len(self._heap)


def section(index, title):
    print()
    print("=" * 76)
    print("=== 第 %d 节 / 6：%s" % (index, title))
    print("=" * 76)


def conclusion(text):
    print()
    print("[结论] " + text)
    print()


# ================================================================
# 2. 定点数工具 + 确定性物理世界
# ================================================================
def fx(v):
    """浮点常量 -> Q16.16（只在初始化常量时使用）。"""
    return int(round(v * FX))


def fx_mul(a, b):
    return (a * b) >> 16


def fx_div(a, b):
    return (a << 16) // b


def fx_sqrt(a):
    """Q16.16 的整数开方：sqrt(a / 2^16) * 2^16 = sqrt(a << 16)。全程整数，无浮点。"""
    if a <= 0:
        return 0
    return isqrt(a << 16)


# 初始状态是固定的整数「地图」：不经过浮点库，任何平台、任何编译器结果都一样。
# （真实游戏里这相当于关卡/出生点数据，从文件读进来，三端完全相同。）
INITIAL_BALLS = (
    (fx(2.0), fx(4.0), fx(0.36), fx(0.03)),
    (fx(6.0), fx(4.0), fx(-0.36), fx(0.03)),
    (fx(4.0), fx(2.0), fx(0.03), fx(0.33)),
    (fx(4.0), fx(6.0), fx(-0.03), fx(-0.33)),
    (fx(2.5), fx(2.5), fx(0.30), fx(0.28)),
)


@dataclass
class World:
    """5 个球的 2D 弹球世界。坐标/速度全部是 Q16.16 整数。"""
    balls: list


def create_world():
    return World([list(b) for b in INITIAL_BALLS])


def _bounce_walls(b):
    if b[0] < BALL_R:
        b[0] = 2 * BALL_R - b[0]
        b[2] = -b[2]
    elif b[0] > WORLD_W - BALL_R:
        b[0] = 2 * (WORLD_W - BALL_R) - b[0]
        b[2] = -b[2]
    if b[1] < BALL_R:
        b[1] = 2 * BALL_R - b[1]
        b[3] = -b[3]
    elif b[1] > WORLD_W - BALL_R:
        b[1] = 2 * (WORLD_W - BALL_R) - b[1]
        b[3] = -b[3]


def _collide_balls(balls, variant=0):
    """等质量弹性碰撞。norm/vn 全部走整数，结果完全可复现。

    ← 这就是帧同步的「确定性执行」机制：同一份代码 + 整数运算 => 三端逐位相同。
    """
    two_r = 2 * BALL_R
    for i in range(N_BALLS):
        for j in range(i + 1, N_BALLS):
            a = balls[i]
            b = balls[j]
            dx = b[0] - a[0]
            dy = b[1] - a[1]
            if variant == 1:
                d2 = ((dy * dy) >> 16) + ((dx * dx) >> 16)      # 加法交换顺序，整数下等价
            else:
                d2 = ((dx * dx) >> 16) + ((dy * dy) >> 16)
            if d2 == 0 or d2 >= two_r * two_r:
                continue
            d = fx_sqrt(d2)
            if d == 0:
                continue
            if variant == 2:
                nx = (dx * FX) // d                              # 与 dx << 16 等价，写法不同
                ny = (dy * FX) // d
            else:
                nx = (dx << 16) // d
                ny = (dy << 16) // d
            overlap = two_r - d
            half = overlap >> 1
            a[0] -= (nx * half) >> 16
            a[1] -= (ny * half) >> 16
            b[0] += (nx * half) >> 16
            b[1] += (ny * half) >> 16
            rvx = b[2] - a[2]
            rvy = b[3] - a[3]
            vn = ((rvx * nx) >> 16) + ((rvy * ny) >> 16)
            if vn < 0:
                imp_x = (vn * nx) >> 16
                imp_y = (vn * ny) >> 16
                a[2] += imp_x
                a[3] += imp_y
                b[2] -= imp_x
                b[3] -= imp_y


def step_world(world, inputs, variant=0):
    """推进一帧。inputs = [玩家0, 玩家1, 玩家2] 的按键位掩码。"""
    balls = world.balls
    if variant == 0:
        for i in range(3):
            b = balls[i]
            bits = inputs[i]
            if bits & 1:
                b[2] -= ACCEL
            if bits & 2:
                b[2] += ACCEL
            if bits & 4:
                b[3] -= ACCEL
            if bits & 8:
                b[3] += ACCEL
        for b in balls:
            b[2] -= b[2] >> FRICTION_SHIFT
            b[3] -= b[3] >> FRICTION_SHIFT
            b[0] += b[2]
            b[1] += b[3]
    elif variant == 1:
        for i in range(3):
            b = balls[i]
            bits = inputs[i]
            if bits & 1:
                b[2] += -ACCEL
            if bits & 2:
                b[2] += ACCEL
            if bits & 4:
                b[3] += -ACCEL
            if bits & 8:
                b[3] += ACCEL
        for b in balls:
            b[2] += -(b[2] >> FRICTION_SHIFT)
            b[3] += -(b[3] >> FRICTION_SHIFT)
            b[0] = b[2] + b[0]
            b[1] = b[3] + b[1]
    else:
        for i in range(3):
            b = balls[i]
            bits = inputs[i]
            b[2] += (ACCEL if bits & 2 else 0) - (ACCEL if bits & 1 else 0)
            b[3] += (ACCEL if bits & 8 else 0) - (ACCEL if bits & 4 else 0)
        for b in balls:
            b[2] += -((b[2] >> FRICTION_SHIFT))
            b[3] += -((b[3] >> FRICTION_SHIFT))
            b[0] += b[2]
            b[1] += b[3]
    for b in balls:
        _bounce_walls(b)
    _collide_balls(balls, variant)


def fnv1a64(data):
    h = 0xcbf29ce484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def world_checksum(world):
    """世界状态校验和：把 5 个球的 20 个定点整数打包后取 FNV-1a 64。

    ← 这就是帧同步的「desync 检测」机制：每端算哈希，比对哈希就知道有没有分歧。
    """
    raw = b"".join(struct.pack("<4i", *b) for b in world.balls)
    return fnv1a64(raw)


def make_input(frame, player, seed=SEED):
    """伪随机按键输入：三端对同一帧算出同一个输入（真实游戏里来自玩家按键）。"""
    h = (frame * 2654435761 + player * 40503 + seed * 2246822519) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 1274126177) & 0xFFFFFFFF
    h ^= h >> 16
    return h & 0x0F


# ================================================================
# 3. 反例用的浮点世界：三种常见的「平台/编译器差异」
# ================================================================
@dataclass
class FloatWorld:
    balls: list


F32 = struct.Struct("<f")


def _to_f32(v):
    return F32.unpack(F32.pack(v))[0]


def create_float_world():
    return FloatWorld([[v / FX for v in b] for b in INITIAL_BALLS])


def float_step(world, inputs, flavor):
    """与定点版同一套物理公式，但用 float 实现。

    flavor 模拟三种真实存在的「等价但不同」的实现：
      sqrt    : sqrt(dx*dx + dy*dy)
      hypot   : math.hypot(dx, dy)（库实现，舍入不同）
      float32 : 中间量强制 32 位浮点（某些平台/精度设置）
    """
    balls = world.balls
    accel = ACCEL / FX
    for i in range(3):
        b = balls[i]
        bits = inputs[i]
        if bits & 1:
            b[2] -= accel
        if bits & 2:
            b[2] += accel
        if bits & 4:
            b[3] -= accel
        if bits & 8:
            b[3] += accel
    for b in balls:
        b[2] -= b[2] / 32.0
        b[3] -= b[3] / 32.0
        b[0] += b[2]
        b[1] += b[3]
        r = BALL_R / FX
        w = WORLD_W / FX
        if b[0] < r:
            b[0] = 2 * r - b[0]
            b[2] = -b[2]
        elif b[0] > w - r:
            b[0] = 2 * (w - r) - b[0]
            b[2] = -b[2]
        if b[1] < r:
            b[1] = 2 * r - b[1]
            b[3] = -b[3]
        elif b[1] > w - r:
            b[1] = 2 * (w - r) - b[1]
            b[3] = -b[3]
    _float_collide(balls, flavor)


def _float_collide(balls, flavor):
    r = BALL_R / FX
    two_r = 2 * r
    for i in range(N_BALLS):
        for j in range(i + 1, N_BALLS):
            a = balls[i]
            b = balls[j]
            dx = b[0] - a[0]
            dy = b[1] - a[1]
            if flavor == "sqrt":
                d2 = dx * dx + dy * dy
                d = math.sqrt(d2)
            elif flavor == "hypot":
                d = math.hypot(dx, dy)
                d2 = d * d
            else:
                dx = _to_f32(dx)
                dy = _to_f32(dy)
                d2 = _to_f32(_to_f32(dx * dx) + _to_f32(dy * dy))
                d = _to_f32(math.sqrt(d2))
            if d == 0 or d2 >= two_r * two_r:
                continue
            nx = dx / d
            ny = dy / d
            if flavor == "float32":
                nx = _to_f32(nx)
                ny = _to_f32(ny)
            half = (two_r - d) / 2
            a[0] -= nx * half
            a[1] -= ny * half
            b[0] += nx * half
            b[1] += ny * half
            rvx = b[2] - a[2]
            rvy = b[3] - a[3]
            vn = rvx * nx + rvy * ny
            if vn < 0:
                a[2] += vn * nx
                a[3] += vn * ny
                b[2] -= vn * nx
                b[3] -= vn * ny


def run_fixed_trajectory(frames, variant=0):
    world = create_world()
    out = []
    for f in range(frames):
        step_world(world, [make_input(f, p) for p in range(3)], variant)
        out.append(tuple(v for b in world.balls for v in b))
    return out


def run_float_trajectory(frames, flavor):
    world = create_float_world()
    out = []
    for f in range(frames):
        float_step(world, [make_input(f, p) for p in range(3)], flavor)
        out.append(tuple(v for b in world.balls for v in b))
    return out


def _max_diff(a, b):
    return max(abs(x - y) for x, y in zip(a, b))


def _first_diff(ra, rb):
    for i, (a, b) in enumerate(zip(ra, rb)):
        if a != b:
            return i
    return None


# ================================================================
# 4. 帧服务器进程
# ================================================================
@dataclass
class SessionConfig:
    frames: int = 200
    tick: float = TICK
    n_clients: int = N_CLIENTS
    input_delay: int = 2
    loss: float = 0.0
    delay_min: float = 0.0
    delay_max: float = 0.0
    report_every: int = 50
    seed: int = SEED
    freeze_at: int = -1
    freeze_len: int = 0
    freeze_client: int = 0
    end_timeout: float = 2.0
    start_delay: float = 0.25
    redundant: bool = True          # 是否开启冗余帧 / 未确认输入重发（对照组用 False）
    fallback_timeout: float = 2.0   # 等输入超过这个时长就用「上一帧输入」代填

    def to_dict(self):
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


CLIENT_NAMES = ["A", "B", "C"]


class FrameServer:
    def __init__(self, sock, cfg, log_q):
        self.sock = sock
        self.cfg = cfg
        self.log_q = log_q
        rng = random.Random(cfg.seed ^ 0x5EED)
        self.outbox = JitterOutbox(sock, cfg.loss, cfg.delay_min, cfg.delay_max, rng)
        self.addrs = {}
        self.inputs = {}
        self.history = {}
        self.reports = {}
        self.comparisons = []
        self.first_mismatch = None
        self.done = set()
        self.completed = -1
        self.stalls = []
        self.stall_ms = 0.0
        self.max_lag_ms = 0.0
        self.fallback_frames = 0
        self.fallback_log_count = 0
        self.catchup_served = 0
        self.catchup_log_count = 0
        self.missing_inputs = 0
        self.entries_received = 0
        self.duplicate_entries = 0
        self.start = None
        self.start_at = None
        self.elapsed = 0.0

    def log(self, msg):
        log_to(self.log_q, "帧服务器", msg)

    # -------------------------------------------------- 收包
    def _drain(self):
        for _ in range(128):
            try:
                data, addr = self.sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            parsed = parse_packet(data)
            if not parsed:
                continue
            mtype, cid, payload = parsed
            if mtype == MSG_JOIN:
                self._on_join(cid, addr)
            elif mtype == MSG_INPUT:
                self._on_input(cid, payload)
            elif mtype == MSG_CHECKSUM:
                self._on_checksum(cid, payload)
            elif mtype == MSG_CATCHUP:
                self._on_catchup(cid, payload)
            elif mtype == MSG_DONE:
                self.done.add(cid)

    def _on_join(self, cid, addr):
        if cid < 0 or cid >= self.cfg.n_clients:
            return
        if cid not in self.addrs:
            self.addrs[cid] = addr
            self.log("客户端 %s 已加入（来源 %s:%d）" % (CLIENT_NAMES[cid], addr[0], addr[1]))
        self.outbox.send(build_packet(MSG_JOIN_ACK, cid), addr)
        if self.start_at is not None:          # 迟到的客户端也能拿到统一起始时刻
            self.outbox.send(build_packet(MSG_START, 0, struct.pack("!d", self.start_at)), addr)

    def _on_input(self, cid, payload):
        if not payload:
            return
        count = payload[0]
        pos = 1
        for _ in range(count):
            if pos + 5 > len(payload):
                break
            frame, bits = struct.unpack_from("!IB", payload, pos)
            pos += 5
            if frame >= self.cfg.frames:
                continue
            slot = self.inputs.setdefault(frame, [None] * self.cfg.n_clients)
            self.entries_received += 1
            if slot[cid] is None:
                slot[cid] = bits
            else:
                self.duplicate_entries += 1

    def _on_checksum(self, cid, payload):
        if len(payload) < 12:
            return
        frame, cs = struct.unpack("!IQ", payload[:12])
        if frame >= self.cfg.frames:
            return
        self.reports.setdefault(frame, {})[cid] = cs
        if len(self.reports[frame]) == self.cfg.n_clients:
            vals = [self.reports[frame][i] for i in range(self.cfg.n_clients)]
            ok = len(set(vals)) == 1
            self.comparisons.append((frame, ok, tuple(vals)))
            names = CLIENT_NAMES
            self.log("第 %d 帧三端校验和：A=%016x B=%016x C=%016x → %s" % (
                frame + 1, vals[0], vals[1], vals[2], "一致" if ok else "分歧！"))
            if not ok and self.first_mismatch is None:
                self.first_mismatch = (frame, tuple(vals))
                self.log("！检测到 desync：第 %d 帧三端校验和不一致" % (frame + 1))

    def _on_catchup(self, cid, payload):
        if len(payload) < 8 or cid not in self.addrs:
            return
        from_frame, to_frame = struct.unpack("!II", payload[:8])
        last = min(to_frame, self.completed)
        if last < from_frame:
            return
        sent = 0
        start = from_frame
        while start <= last:
            chunk_end = min(start + 8, last + 1)
            entries = []
            for fr in range(start, chunk_end):
                if fr in self.history:
                    entries.append((fr, self.history[fr]))
            if entries:
                body = struct.pack("!IB", entries[-1][0], len(entries))
                for fr, vals in entries:
                    body += struct.pack("!I", fr) + bytes(vals)
                self.outbox.send(build_packet(MSG_FRAME, 0, body), self.addrs[cid])
                sent += len(entries)
            start = chunk_end
        self.catchup_served += sent
        self.catchup_log_count += 1
        if self.catchup_log_count <= 4:
            self.log("客户端 %s 请求历史帧 [%d, %d]，补发 %d 帧" % (
                CLIENT_NAMES[cid], from_frame + 1, last + 1, sent))

    # -------------------------------------------------- 收齐/广播
    def _has_all(self, frame):
        slot = self.inputs.get(frame)
        return bool(slot) and all(v is not None for v in slot)

    def _fill_fallback(self, frame):
        slot = self.inputs.setdefault(frame, [None] * self.cfg.n_clients)
        for cid in range(self.cfg.n_clients):
            if slot[cid] is not None:
                continue
            self.missing_inputs += 1
            found = 0
            for back in range(frame - 1, max(-1, frame - 50), -1):
                old = self.inputs.get(back)
                if old and old[cid] is not None:
                    found = old[cid]
                    break
            slot[cid] = found
        self.fallback_frames += 1
        self.fallback_log_count += 1
        if self.fallback_log_count <= 3:
            self.log("！第 %d 帧等输入超过 %.1f 秒，用上一帧输入填充（真实项目里这会直接 desync，"
                     "所以正式做法是客户端重发直到被确认）" % (
                         frame + 1, self.cfg.fallback_timeout))

    def _broadcast_window(self, frame):
        """把最近 WIN 帧的输入打成一个包广播给所有客户端。

        ← 这就是帧同步的「输入帧广播」+「冗余帧」机制：
          同一帧的输入会在连续 3 个包里重复出现，丢一个包还有两个包兜底。
        """
        lo = max(0, frame - ((WIN if self.cfg.redundant else 1) - 1))
        entries = [(fr, self.history[fr]) for fr in range(lo, frame + 1)]
        body = struct.pack("!IB", frame, len(entries))
        for fr, vals in entries:
            body += struct.pack("!I", fr) + bytes(vals)
        packet = build_packet(MSG_FRAME, 0, body)
        for cid in self.addrs:
            self.outbox.send(packet, self.addrs[cid])

    # -------------------------------------------------- 主流程
    def run(self):
        self._handshake()
        self._announce_start()
        for frame in range(self.cfg.frames):
            deadline = self.start_at + frame * self.cfg.tick
            while True:                              # 等到本帧该广播的时刻
                now = time.monotonic()
                self._drain()
                self.outbox.flush(now)
                if now >= deadline:
                    break
                time.sleep(min(0.001, max(0.0, deadline - now)))
            wait_from = time.monotonic()
            while not self._has_all(frame):          # 等齐 3 个客户端的输入
                self._drain()
                self.outbox.flush()
                if time.monotonic() - wait_from > self.cfg.fallback_timeout:
                    self._fill_fallback(frame)
                    break
                time.sleep(0.001)
            lag = time.monotonic() - deadline
            if lag > self.cfg.tick * 0.5:
                self.stalls.append((frame, lag))
                self.stall_ms += lag * 1000.0
                self.max_lag_ms = max(self.max_lag_ms, lag * 1000.0)
            self.history[frame] = tuple(self.inputs[frame])
            self.completed = frame
            self._broadcast_window(frame)
            if frame == 0:
                self.log("开始逐帧广播：%d Hz，每包带最近 %d 帧输入（冗余帧），"
                         "客户端 %d 个" % (int(round(1.0 / self.cfg.tick)), WIN, self.cfg.n_clients))
            if (frame + 1) % 50 == 0:
                self.log("已广播 %d/%d 帧；晚于调度时刻 %d 次，最大等帧 %.0f ms" % (
                    frame + 1, self.cfg.frames, len(self.stalls), self.max_lag_ms))
        self.elapsed = time.monotonic() - self.start_at
        self._finish()

    def _handshake(self):
        deadline = time.monotonic() + 10.0
        while len(self.addrs) < self.cfg.n_clients:
            if time.monotonic() > deadline:
                raise RuntimeError("等待 %d 个客户端加入超时（已加入 %d 个）" % (
                    self.cfg.n_clients, len(self.addrs)))
            self._drain()
            self.outbox.flush()
            time.sleep(0.002)
        # 约定一个所有进程共用的绝对起始时刻（time.monotonic 在本机各进程是同一时钟），
        # 三端从同一帧号、同一墙钟时刻起步，避免一开始就互相追帧。
        self.start_at = time.monotonic() + self.cfg.start_delay
        self.start = self.start_at
        self.log("集齐 %d 个客户端，%.0f ms 后开始逐帧推进" % (
            self.cfg.n_clients, self.cfg.start_delay * 1000))

    def _announce_start(self):
        """广播统一起始时刻；多发几次，丢包也能收到。"""
        packet = build_packet(MSG_START, 0, struct.pack("!d", self.start_at))
        for _ in range(6):
            for cid in self.addrs:
                self.outbox.send(packet, self.addrs[cid])
            self._drain()
            self.outbox.flush()
            time.sleep(0.03)
        while time.monotonic() < self.start_at:
            self._drain()
            self.outbox.flush()
            time.sleep(0.001)

    def _finish(self):
        self.log("全部 %d 帧广播完成，用时 %.2f s；等待客户端确认收尾" % (
            self.cfg.frames, self.elapsed))
        end_deadline = time.monotonic() + self.cfg.end_timeout
        next_end = 0.0
        while len(self.done) < self.cfg.n_clients and time.monotonic() < end_deadline:
            now = time.monotonic()
            if now >= next_end:
                packet = build_packet(MSG_END, 0, struct.pack("!I", self.cfg.frames))
                for cid in self.addrs:
                    self.outbox.send(packet, self.addrs[cid])
                next_end = now + 0.2
            self._drain()
            self.outbox.flush(now)
            time.sleep(0.001)
        self.log("收尾完成（收到 %d/%d 个客户端的 DONE）" % (
            len(self.done), self.cfg.n_clients))


# ================================================================
# 5. 客户端进程
# ================================================================
class LockstepClient:
    def __init__(self, sock, cid, cfg, log_q):
        self.sock = sock
        self.cid = cid
        self.cfg = cfg
        self.log_q = log_q
        rng = random.Random(cfg.seed ^ (0xC0FFEE + cid * 977))
        self.outbox = JitterOutbox(sock, cfg.loss, cfg.delay_min, cfg.delay_max, rng)
        self.world = create_world()
        self.expected = 0
        self.buffer = {}
        self.checksums = {}
        self.confirmed = -1
        self.server_max = -1
        self.send_tick = 0
        self.start = None
        self.start_at = None
        self.joined = False
        self.end_received = False
        self.server_addr = None
        self.entries_sent = 0
        self.packets_received = 0
        self.last_step = None
        self.max_wait_ms = 0.0
        self.stall_count = 0
        self.step_count = 0
        self.catchup_requests = 0
        self.last_catchup_req = 0.0
        self.last_progress = time.monotonic()
        self.catchup = None
        self.freeze_at = cfg.freeze_at if cid == cfg.freeze_client else -1
        self.freeze_len = cfg.freeze_len if cid == cfg.freeze_client else 0
        self.freeze_active = False
        self.freeze_done = False
        self.freeze_until = 0.0
        self.in_catchup = False
        self.wall_deadline = time.monotonic() + 20.0

    def log(self, msg):
        log_to(self.log_q, "客户端 %s" % CLIENT_NAMES[self.cid], msg)

    # -------------------------------------------------- 加入
    def _join(self, port):
        """加入帧服务器，并等待服务器广播的统一起始时刻。

        ← 这就是帧同步的「统一时钟/帧号起点」机制：三端必须从同一帧号同一时刻起步，
          否则客户端要么跑太快（重发范围变大、带宽上升），要么跑太慢（一开始就追帧）。
        """
        self.server_addr = (HOST, port)
        deadline = time.monotonic() + 10.0
        next_send = 0.0
        while self.start_at is None:
            now = time.monotonic()
            if now > deadline:
                raise RuntimeError("加入帧服务器超时（没收到 START）")
            if now >= next_send:
                self.outbox.send(build_packet(MSG_JOIN, self.cid), self.server_addr)
                next_send = now + 0.1
            self.outbox.flush(now)
            self._drain()
            time.sleep(0.002)
        while time.monotonic() < self.start_at:
            self.outbox.flush()
            self._drain()
            time.sleep(0.001)

    # -------------------------------------------------- 收包
    def _drain(self):
        for _ in range(256):
            try:
                data, _addr = self.sock.recvfrom(65535)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            self.packets_received += 1
            parsed = parse_packet(data)
            if not parsed:
                continue
            mtype, _cid, payload = parsed
            if mtype == MSG_JOIN_ACK:
                self.joined = True
            elif mtype == MSG_START:
                if len(payload) >= 8:
                    self.start_at = struct.unpack("!d", payload[:8])[0]
            elif mtype == MSG_FRAME:
                self._on_frame(payload)
            elif mtype == MSG_END:
                self.end_received = True

    def _on_frame(self, payload):
        if len(payload) < 5:
            return
        frame_no, count = struct.unpack_from("!IB", payload, 0)
        pos = 5
        max_seen = self.server_max
        for _ in range(count):
            if pos + 7 > len(payload):
                break
            fr = struct.unpack_from("!I", payload, pos)[0]
            pos += 4
            vals = tuple(payload[pos:pos + 3])
            pos += 3
            max_seen = max(max_seen, fr)
            if fr >= self.expected and fr not in self.buffer and len(vals) == 3:
                self.buffer[fr] = vals
        if max_seen > self.server_max:
            self.server_max = max_seen
        # 帧服务器广播过 f => 说明 f 及之前的所有输入都已被服务器确认
        self.confirmed = max(self.confirmed, frame_no)

    # -------------------------------------------------- 发送输入
    def _sender(self, now):
        """按墙钟节奏产生并发送输入。

        ← 这就是帧同步的「输入延迟 + 未确认输入重发」机制：
          - 输入延迟：第 t 时刻的按键安排到第 t+D 帧生效，用几帧的延迟换网络抖动余量；
          - 重发：没被服务器在广播帧号里确认过的输入，每帧都随包重发，
            配合每包 3 帧的冗余窗口，30% 丢包也能被补回来。
        """
        target_tick = int((now - self.start) / self.cfg.tick)
        while self.send_tick <= target_tick:
            self._send_input(self.send_tick)
            self.send_tick += 1

    def _send_input(self, tick_index):
        ahead = tick_index + self.cfg.input_delay
        if not self.cfg.redundant:
            # 对照组：不冗余、不重发，每帧输入只发一次（丢就丢了）
            if not (0 <= ahead < self.cfg.frames):
                return
            entries = [ahead]
        else:
            frames = set()
            # 1) 最近 3 帧的「滚动窗口」（冗余帧）
            for k in (ahead - 2, ahead - 1, ahead):
                if 0 <= k < self.cfg.frames:
                    frames.add(k)
            # 2) 最老的 4 帧「尚未被确认」的输入：帧服务器卡在哪一帧，就从哪一帧继续重发
            for k in range(self.confirmed + 1, min(self.confirmed + 5, ahead + 1)):
                if 0 <= k < self.cfg.frames:
                    frames.add(k)
            entries = sorted(frames)[:MAX_ENTRIES]
        if not entries:
            return
        body = struct.pack("!B", len(entries))
        for fr in entries:
            body += struct.pack("!IB", fr, make_input(fr, self.cid, self.cfg.seed))
        self.outbox.send(build_packet(MSG_INPUT, self.cid, body), self.server_addr)
        self.entries_sent += len(entries)

    def _send_checksum(self, frame):
        cs = self.checksums.get(frame)
        if cs is None:
            return
        self.outbox.send(build_packet(MSG_CHECKSUM, self.cid, struct.pack("!IQ", frame, cs)),
                         self.server_addr)

    # -------------------------------------------------- 模拟
    def _step_ready(self):
        while self.expected in self.buffer:
            inputs = self.buffer.pop(self.expected)
            step_world(self.world, inputs)
            cs = world_checksum(self.world)
            self.checksums[self.expected] = cs
            now = time.monotonic()
            if self.last_step is not None and not self.in_catchup:
                wait = (now - self.last_step - self.cfg.tick) * 1000.0
                if wait > self.cfg.tick * 500.0:      # 超过半个帧长
                    self.stall_count += 1
                    self.max_wait_ms = max(self.max_wait_ms, wait)
            self.last_step = now
            self.last_progress = now
            self.step_count += 1
            self.expected += 1
            if self.expected % self.cfg.report_every == 0:
                self._send_checksum(self.expected - 1)

    def _request_catchup(self, now, force=False):
        if not force and now - self.last_catchup_req < 0.1:
            return
        self.last_catchup_req = now
        to_frame = max(self.server_max, self.expected)
        payload = struct.pack("!II", self.expected, to_frame)
        self.outbox.send(build_packet(MSG_CATCHUP, self.cid, payload), self.server_addr)
        self.catchup_requests += 1

    def _maybe_request_catchup(self, now):
        if self.server_max > self.expected and self.expected not in self.buffer:
            self._request_catchup(now)
        elif now - self.last_progress > 0.2 and self.expected < self.cfg.frames:
            # 长时间没有任何新帧：很可能是最后几帧的广播全丢了，主动向服务器要历史帧
            self._request_catchup(now)

    # -------------------------------------------------- 卡顿与追帧
    def _maybe_start_freeze(self, now):
        if self.freeze_at < 0 or self.freeze_done or self.freeze_active:
            return False
        if self.expected >= self.freeze_at:
            self.freeze_active = True
            self.freeze_until = now + self.freeze_len * self.cfg.tick
            self.log("模拟卡顿：暂停消费帧/模拟 %d 帧（约 %.1f s），但输入发送照常进行" % (
                self.freeze_len, self.freeze_len * self.cfg.tick))
            return True
        return False

    def _resume_from_freeze(self):
        """快进追帧：把积压帧按顺序补跑一遍。

        ← 这就是帧同步的「快进追帧」机制：
          帧号是绝对的，服务器保留历史帧输入；落后端只需把错过的帧按顺序补跑，
          状态由确定性逻辑重算 —— 要追的不是「状态」，而是「输入序列」。
        """
        self.freeze_active = False
        self.freeze_done = True
        self.in_catchup = True
        t0 = time.monotonic()
        before = self.expected
        self.sock.setblocking(False)
        self._drain()
        self.sock.settimeout(0.0)
        target = self.server_max
        if self.expected not in self.buffer and target > self.expected:
            self._request_catchup(time.monotonic(), force=True)
        deadline = time.monotonic() + 3.0
        while self.expected <= target and time.monotonic() < deadline:
            if self.expected in self.buffer:
                self._drain()
                self._step_ready()
            else:
                self._drain()
                if self.expected not in self.buffer:
                    self._request_catchup(time.monotonic(), force=True)
                time.sleep(0.001)
        self.in_catchup = False
        elapsed = time.monotonic() - t0
        frames = self.expected - before
        fps = frames / elapsed if elapsed > 0 else 0.0
        self.catchup = {
            "frames": frames,
            "elapsed_ms": elapsed * 1000.0,
            "fps": fps,
            "realtime_s": frames * self.cfg.tick,
        }
        self.last_step = time.monotonic()
        self.log("快进追帧：补跑 %d 帧，耗时 %.1f ms（约 %.0f 帧/秒）；"
                 "实时逐帧播放需要 %.2f s" % (frames, elapsed * 1000.0, fps,
                                          frames * self.cfg.tick))

    # -------------------------------------------------- 主循环
    def run(self, port):
        self._join(port)
        self.start = self.start_at              # 与帧服务器、其他客户端使用同一个起始时刻
        self.log("已加入帧服务器，从统一时刻开始本地定点模拟（输入延迟 %d 帧 = %d ms；"
                 "每包带最近 %d 帧输入）" % (
                     self.cfg.input_delay, int(self.cfg.input_delay * self.cfg.tick * 1000), WIN))
        while self.expected < self.cfg.frames:
            if time.monotonic() > self.wall_deadline:
                raise RuntimeError("等待帧数据超时（已推进 %d/%d 帧）" % (
                    self.expected, self.cfg.frames))
            now = time.monotonic()
            self._sender(now)
            self.outbox.flush(now)
            if self.freeze_active:
                if now < self.freeze_until:
                    time.sleep(0.002)
                    continue
                self._resume_from_freeze()
                continue
            if self._maybe_start_freeze(now):
                continue
            self._drain()
            self._step_ready()
            self._maybe_request_catchup(now)
            time.sleep(0.001)
        # 收尾：把 DONE 重发几次（UDP 会丢），服务器收到即可退出
        packet = build_packet(MSG_DONE, self.cid)
        for _ in range(5):
            self.outbox.send(packet, self.server_addr)
            self.outbox.flush()
            self._drain()
            time.sleep(0.02)
        for _ in range(50):                 # 让带延迟的包发完
            self.outbox.flush()
            self._drain()
            time.sleep(0.01)
        self.log("跑完 %d 帧，最终校验和 0x%016x" % (
            len(self.checksums), self.checksums.get(self.cfg.frames - 1, 0)))


# ================================================================
# 6. worker 入口（必须是模块顶层函数，Windows spawn 才能 pickle）
# ================================================================
def _make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    except OSError:
        pass
    sock.setblocking(False)
    return sock


def server_worker(port_q, log_q, res_q, cfg_dict):
    cfg = SessionConfig.from_dict(cfg_dict)
    result = {"role": "server", "error": None}
    sock = None
    try:
        sock = _make_socket()
        sock.bind((HOST, 0))
        port_q.put(sock.getsockname()[1])
        server = FrameServer(sock, cfg, log_q)
        server.run()
        result.update({
            "frames_done": server.completed + 1,
            "elapsed": server.elapsed,
            "ideal_elapsed": cfg.frames * cfg.tick,
            "stall_count": len(server.stalls),
            "stall_ms": server.stall_ms,
            "max_lag_ms": server.max_lag_ms,
            "missing_inputs": server.missing_inputs,
            "extra_ms": max(0.0, (server.elapsed - cfg.frames * cfg.tick) * 1000.0),
            "fallback_frames": server.fallback_frames,
            "packets_out": server.outbox.sent_packets,
            "bytes_out": server.outbox.sent_bytes,
            "dropped_out": server.outbox.dropped_packets,
            "comparisons": server.comparisons,
            "first_mismatch": server.first_mismatch,
            "catchup_served": server.catchup_served,
            "entries_received": server.entries_received,
            "duplicate_entries": server.duplicate_entries,
            "ended": len(server.done),
        })
    except Exception:
        result["error"] = traceback.format_exc()
        try:
            log_to(log_q, "帧服务器", "异常退出：" + result["error"].splitlines()[-1])
        except Exception:
            pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        try:
            res_q.put(result)
        except Exception:
            pass
        time.sleep(0.05)


def client_worker(cid, port, log_q, res_q, cfg_dict):
    cfg = SessionConfig.from_dict(cfg_dict)
    result = {"role": "client", "client_id": cid, "error": None}
    sock = None
    try:
        sock = _make_socket()
        sock.bind((HOST, 0))
        client = LockstepClient(sock, cid, cfg, log_q)
        client.run(port)
        result.update({
            "frames_done": len(client.checksums),
            "checksums": client.checksums,
            "final_checksum": client.checksums.get(cfg.frames - 1),
            "packets_sent": client.outbox.sent_packets,
            "bytes_sent": client.outbox.sent_bytes,
            "dropped_sent": client.outbox.dropped_packets,
            "entries_sent": client.entries_sent,
            "max_wait_ms": client.max_wait_ms,
            "stall_count": client.stall_count,
            "catchup_requests": client.catchup_requests,
            "catchup": client.catchup,
            "end_received": client.end_received,
            "confirmed": client.confirmed,
            "elapsed": (time.monotonic() - client.start) if client.start else 0.0,
        })
    except Exception:
        result["error"] = traceback.format_exc()
        try:
            log_to(log_q, "客户端 %s" % CLIENT_NAMES[cid],
                   "异常退出：" + result["error"].splitlines()[-1])
        except Exception:
            pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        try:
            res_q.put(result)
        except Exception:
            pass
        time.sleep(0.05)


# ================================================================
# 7. 父进程：启动进程、收集日志与结果
# ================================================================
def _drain_logs(log_q, timeout=0.05):
    got = False
    while True:
        try:
            tag, msg = log_q.get(timeout=timeout if not got else 0.01)
        except queue.Empty:
            break
        print("[%s] %s" % (tag, msg), flush=True)
        got = True
    return got


def run_session(cfg, notes=None, timeout=TIMEOUT):
    """启动 1 个帧服务器进程 + n 个客户端进程，跑完一局，返回结果字典列表。"""
    cfg_dict = cfg.to_dict()
    ctx = mp.get_context("spawn")
    log_q = ctx.Queue()
    res_q = ctx.Queue()
    port_q = ctx.Queue()
    server = ctx.Process(target=server_worker, args=(port_q, log_q, res_q, cfg_dict),
                         name="frame-server")
    server.daemon = True
    server.start()
    try:
        port = port_q.get(timeout=10.0)
    except queue.Empty:
        print("[错误] 帧服务器 10 秒内没有上报端口")
        if server.is_alive():
            server.terminate()
        _drain_logs(log_q, 0.1)
        return []
    print("[配置] 真实 UDP：127.0.0.1:%d；帧服务器进程 + %d 个客户端进程；"
          "帧率 %d Hz，共 %d 帧" % (port, cfg.n_clients, int(round(1.0 / cfg.tick)),
                                   cfg.frames))
    for line in (notes or []):
        print("[配置] " + line)
    clients = []
    for cid in range(cfg.n_clients):
        p = ctx.Process(target=client_worker, args=(cid, port, log_q, res_q, cfg_dict),
                        name="client-%d" % cid)
        p.daemon = True
        p.start()
        clients.append(p)
        time.sleep(0.02)
    procs = [server] + clients
    deadline = time.monotonic() + timeout
    results = []

    def _collect():
        # 必须边等边收结果：Windows 管道缓冲区很小，子进程写结果时如果父进程不读，
        # 子进程的队列 feeder 线程会卡住，进而卡在进程退出的 finalizer 上。
        while True:
            try:
                results.append(res_q.get(timeout=0.01))
            except queue.Empty:
                return

    while True:
        _drain_logs(log_q)
        _collect()
        if not any(p.is_alive() for p in procs):
            break
        if time.monotonic() > deadline:
            print("[超时] 会话超过 %.0f s 仍未结束，强制结束子进程（存活：%s）" % (
                timeout, [p.name for p in procs if p.is_alive()]))
            for p in procs:
                if p.is_alive():
                    p.terminate()
            break
        time.sleep(0.005)
    for p in procs:
        try:
            p.join(3.0)
        except Exception:
            pass
    _drain_logs(log_q, 0.05)
    _collect()
    return results


def split_results(results):
    server = None
    clients = []
    for r in results:
        if not isinstance(r, dict):
            continue
        if r.get("role") == "server":
            server = r
        elif r.get("role") == "client":
            clients.append(r)
    clients.sort(key=lambda r: r.get("client_id", 0))
    return server, clients


def report_errors(results):
    bad = [r for r in results if isinstance(r, dict) and r.get("error")]
    for r in bad:
        print("[错误] %s：" % r.get("role"), flush=True)
        for line in r["error"].strip().splitlines()[-4:]:
            print("        " + line, flush=True)
    return not bad


def reference_checksums(frames, seed):
    """父进程用同一份定点逻辑离线复算一遍参考轨迹，用来交叉验证客户端。"""
    world = create_world()
    out = []
    for f in range(frames):
        step_world(world, [make_input(f, p, seed) for p in range(3)])
        out.append(world_checksum(world))
    return out


def print_consistency(clients, frames, seed):
    """比对三端校验和，并与离线参考模型逐帧对比，返回是否完全一致。"""
    ref = reference_checksums(frames, seed)
    maps = []
    all_ok = True
    for c in clients:
        cs = {int(k): int(v) for k, v in (c.get("checksums") or {}).items()}
        maps.append(cs)
        missing = frames - len(cs)
        diffs = [f for f in range(frames) if f in cs and cs[f] != ref[f]]
        ok = (missing == 0 and not diffs)
        all_ok = all_ok and ok
        print("[校验] 客户端 %s：完成 %d/%d 帧；与离线参考模型不一致 %d 帧%s" % (
            CLIENT_NAMES[c.get("client_id", 0)], len(cs), frames, len(diffs),
            "" if ok else "  ← 异常"))
    cross = 0
    common = set(maps[0]) if maps else set()
    for m in maps[1:]:
        common &= set(m)
    for f in common:
        if len({m[f] for m in maps}) > 1:
            cross += 1
    print("[校验] 三端逐帧互相比较：共同帧 %d 个，不一致 %d 帧" % (len(common), cross))
    return all_ok and cross == 0


# ================================================================
# 8. 各子命令
# ================================================================
def run_demo():
    section(1, "真实 UDP 锁步跑 200 帧：帧服务器 + 3 个客户端进程")
    cfg = SessionConfig(frames=200, tick=TICK, n_clients=3, input_delay=2, report_every=50)
    notes = [
        "逻辑层：Q16.16 定点数弹球物理，三端同代码 => 可复现",
        "网络层：UDP 广播输入帧，每包带最近 %d 帧输入（冗余帧）" % WIN,
        "校验层：客户端每 %d 帧上报状态校验和，帧服务器负责比对（服务器不跑物理）" % cfg.report_every,
    ]
    results = run_session(cfg, notes)
    server, clients = split_results(results)
    if not report_errors(results) or server is None or len(clients) < cfg.n_clients:
        conclusion("会话没有完整跑完，请检查上面的错误信息。")
        return False
    print()
    print("[统计] 帧服务器：广播 %d 帧，用时 %.2f s（理想 %.2f s）；"
          "发送 %d 包 / %d 字节；晚于调度时刻 %d 次（最大等帧 %.0f ms）" % (
              server["frames_done"], server["elapsed"], server["ideal_elapsed"],
              server["packets_out"], server["bytes_out"], server["stall_count"],
              server["max_lag_ms"]))
    print("[统计] 冗余输入：服务器收到 %d 个输入条目（其中重复重发 %d 个，去重后每玩家每帧 1 个）" % (
        server["entries_received"], server["duplicate_entries"]))
    for c in clients:
        print("[统计] 客户端 %s：发送输入 %d 包 / %d 字节；最大等帧 %.0f ms；"
              "最终校验和 0x%016x" % (
                  CLIENT_NAMES[c["client_id"]], c["packets_sent"], c["bytes_sent"],
                  c["max_wait_ms"], c.get("final_checksum") or 0))
    print()
    ok = print_consistency(clients, cfg.frames, cfg.seed)
    if ok:
        conclusion("200 帧三端状态校验和逐帧一致，且与离线参考模型一致 → 无 desync。"
                   "帧同步同步的是「输入 + 确定性执行」，不是「状态」。")
    else:
        conclusion("检测到分歧：三端校验和不一致 → 判定 desync。")
    return ok


def run_desync():
    section(2, "反例：同一个物理逻辑，float 三端会分歧，定点三端不会（各 500 帧）")
    frames = 500
    variants = (("A", "sqrt", "sqrt(dx*dx+dy*dy)"),
                ("B", "hypot", "math.hypot(dx, dy)（库实现，舍入不同）"),
                ("C", "float32", "碰撞计算强制 32 位浮点（移动端/旧平台的精度差异）"))
    float_runs = {name: run_float_trajectory(frames, flavor) for name, flavor, _ in variants}
    fixed_runs = {name: run_fixed_trajectory(frames, variant)
                  for name, variant in (("A", 0), ("B", 1), ("C", 2))}
    print("[说明] 三个 float 客户端模拟三种真实存在的实现差异：")
    for name, _flavor, desc in variants:
        print("         %s = %s" % (name, desc))
    print("       三个定点客户端用不同的整数写法（换加法顺序、减法改加负数、乘 65536 代替左移），")
    print("       验证「整数运算精确 => 写法不同也不影响结果」。")
    print()
    div = {}
    for pa, pb in (("A", "B"), ("A", "C")):
        d = _first_diff(float_runs[pa], float_runs[pb])
        div[(pa, pb)] = d
        if d is None:
            print("[float] %s vs %s 首次分歧：无" % (pa, pb))
        else:
            print("[float] %s vs %s 首次分歧：第 %d 帧，最大偏差 %.3e（1 ULP 量级）" % (
                pa, pb, d + 1, _max_diff(float_runs[pa][d], float_runs[pb][d])))
    fixed_first = None
    for pa, pb in (("A", "B"), ("A", "C"), ("B", "C")):
        d = _first_diff(fixed_runs[pa], fixed_runs[pb])
        if d is not None:
            fixed_first = (pa, pb, d)
            break
    print("[定点] A/B/C 首次分歧：%s" % (
        "无" if fixed_first is None else "第 %d 帧（%s vs %s）" % (
            fixed_first[2] + 1, fixed_first[0], fixed_first[1])))
    print()
    print("  帧号    float A-B 最大偏差    float A-C 最大偏差    定点三端最大偏差")
    for frame in (50, 100, 200, 300, 400, 500):
        idx = min(frame, frames) - 1
        dab = _max_diff(float_runs["A"][idx], float_runs["B"][idx])
        dac = _max_diff(float_runs["A"][idx], float_runs["C"][idx])
        dfix = 0
        for pa, pb in (("A", "B"), ("A", "C"), ("B", "C")):
            dfix = max(dfix, _max_diff(fixed_runs[pa][idx], fixed_runs[pb][idx]))
        print("  %4d    %-20.6e  %-21.6e  %d" % (frame, dab, dac, dfix))
    print()
    ac = div[("A", "C")]
    ab = div[("A", "B")]
    if ac is not None:
        first_bits = ("，即使最温和的 B（换用 hypot）也在第 %d 帧出现 %.2e 的差异"
                      % (ab + 1, _max_diff(float_runs["A"][ab], float_runs["B"][ab]))) \
            if ab is not None else ""
        conclusion("float 版第 %d 帧校验和分歧：客户端 C 与 A 偏移 %.2e，"
                   "到第 500 帧放大到 %.3f%s —— 判定 desync。"
                   "三端收到的输入完全相同，分歧来自浮点执行的舍入，不是网络。"
                   % (ac + 1, _max_diff(float_runs["A"][ac], float_runs["C"][ac]),
                      _max_diff(float_runs["A"][-1], float_runs["C"][-1]), first_bits))
    conclusion("定点版 500 帧三端逐帧校验和全部一致（最大偏差 0）。"
               "整数加、减、乘、整除、开方都没有舍入歧义，所以三端跑出同一串状态。"
               "这就是锁步必须用定点/整数逻辑、并且锁死客户端版本的原因。")
    return True


def run_jitter():
    section(3, "30% 丢包 + 50–150ms 随机延迟：冗余帧补发与「等帧卡顿」")
    frames = 80
    base = dict(frames=frames, tick=TICK, n_clients=3, input_delay=2,
                loss=0.30, delay_min=0.05, delay_max=0.15, report_every=50,
                end_timeout=4.0, seed=SEED)
    notes = [
        "应用层注入：上行/下行各 30% 丢包，50–150 ms 随机延迟（UDP 不会自动重传）",
        "冗余：每包带最近 %d 帧输入 + 未被确认的旧输入持续重发" % WIN,
    ]
    results = run_session(SessionConfig(redundant=True, **base), notes)
    server, clients = split_results(results)
    if not report_errors(results) or server is None or len(clients) < 3:
        conclusion("会话没有完整跑完，请检查上面的错误信息。")
        return False
    extra_frames = server["extra_ms"] / (TICK * 1000.0)
    print()
    print("[统计] 会话实际用时 %.2f s（理想 %.2f s）：总等帧延迟 +%.0f ms ≈ %.1f 个帧时长" % (
        server["elapsed"], server["ideal_elapsed"], server["extra_ms"], extra_frames))
    print("[统计] 帧服务器：%d/%d 帧晚于调度时刻才凑齐输入，最大单帧等帧 %.0f ms（≈ %.1f 帧）；"
          "缺失输入条目 %d 个" % (
              server["stall_count"], frames, server["max_lag_ms"],
              server["max_lag_ms"] / (TICK * 1000.0), server["missing_inputs"]))
    print("[统计] 上行丢包（客户端侧）：%d 个包；下行丢包（服务器侧）：%d 个包" % (
        sum(c["dropped_sent"] for c in clients), server["dropped_out"]))
    for c in clients:
        ratio = c["entries_sent"] / float(frames) if frames else 0.0
        print("[统计] 客户端 %s：输入条目 %d 个（每帧唯一输入 1 个 → 冗余 %.1f 倍）；"
              "最大等帧 %.0f ms，等帧超标 %d 次；补帧请求 %d 次" % (
                  CLIENT_NAMES[c["client_id"]], c["entries_sent"], ratio,
                  c["max_wait_ms"], c["stall_count"], c["catchup_requests"]))
    if server["catchup_served"]:
        print("[统计] 帧服务器按请求补发历史帧：%d 帧" % server["catchup_served"])
    print()
    ok = print_consistency(clients, frames, base["seed"])

    # ---- 对照实验：同样的丢包/延迟，但关掉冗余帧与输入重发 ----
    print()
    print("[对照] 再跑一局：同样的 30% 丢包 + 50–150 ms 延迟，但关闭冗余帧/输入重发，"
          "帧数减到 30 控制耗时")
    ctrl_cfg = SessionConfig(redundant=False, fallback_timeout=0.12,
                             **dict(base, frames=30, end_timeout=3.5))
    ctrl_results = run_session(ctrl_cfg, ["关闭冗余：每帧输入只发 1 次，帧包只带当前 1 帧"])
    ctrl_server, ctrl_clients = split_results(ctrl_results)
    ctrl_ok = bool(ctrl_server) and not any(r.get("error") for r in ctrl_results)
    if ctrl_ok:
        ctrl_claim = ctrl_clients[0]["checksums"] if ctrl_clients else {}
        print()
        print("[对照] 关闭冗余：%d/%d 帧因缺输入等了 %.0f ms 后被「上一帧输入」代填，"
              "缺失输入条目 %d 个；会话用时 %.2f s（理想 %.2f s）" % (
                  ctrl_server["fallback_frames"], ctrl_cfg.frames,
                  ctrl_cfg.fallback_timeout * 1000.0, ctrl_server["missing_inputs"],
                  ctrl_server["elapsed"], ctrl_server["ideal_elapsed"]))
        print("[对照] 开启冗余：缺失输入条目 %d 个，会话用时 %.2f s（理想 %.2f s）" % (
              server["missing_inputs"], server["elapsed"], server["ideal_elapsed"]))
    else:
        print("[对照] 关闭冗余的对照组没能完整跑完（本身就说明没冗余时更容易崩）")
    print()
    print("[原理] 本例输入延迟只有 %d 帧（%d ms），小于网络抖动上限（150 ms），"
          "所以帧服务器几乎每帧都要等输入；" % (
              base["input_delay"], int(base["input_delay"] * TICK * 1000)))
    print("       把输入延迟调大（例如 4 帧 = %d ms）可以把等帧压到接近 0，代价是操作延迟增加。"
          % int(4 * TICK * 1000))
    print("       真实项目会按 RTT 自适应调整输入延迟，并用冗余帧扛住丢包。")
    if ok:
        conclusion("30%% 丢包、50–150 ms 抖动下，冗余帧 + 未确认输入重发让 %d 帧全部送达"
                   "（缺失输入条目 0），最终三端校验和仍一致；会话总时长只比理想多 %.0f ms。"
                   "对照实验里关掉冗余后，有 %d 帧缺输入只能靠上一帧代填 —— "
                   "帧同步宁可「卡」也不「错」，冗余就是拿带宽换确定性。"
                   % (frames, server["extra_ms"],
                      ctrl_server["fallback_frames"] if ctrl_ok else -1))
    else:
        conclusion("有客户端的帧校验和与参考模型不符 → 判定 desync。")
    return ok


def run_catchup():
    section(4, "落后 60 帧后重新加入：快进追帧演示")
    frames = 200
    cfg = SessionConfig(frames=frames, tick=TICK, n_clients=3, input_delay=2,
                        freeze_at=40, freeze_len=60, freeze_client=0, report_every=50)
    freeze_seconds = 60 * TICK
    notes = [
        "客户端 A 在第 40 帧后暂停消费/模拟 60 帧（%.1f s），但输入发送照常（模拟输入线程还在跑）"
        % freeze_seconds,
        "客户端 B/C 正常推进；服务器保留历史帧输入，A 恢复后按顺序补跑",
    ]
    results = run_session(cfg, notes)
    server, clients = split_results(results)
    if not report_errors(results) or server is None or len(clients) < cfg.n_clients:
        conclusion("会话没有完整跑完，请检查上面的错误信息。")
        return False
    print()
    print("[统计] 帧服务器：广播 %d 帧，用时 %.2f s；晚于调度时刻 %d 次，最大等帧 %.0f ms" % (
        server["frames_done"], server["elapsed"], server["stall_count"],
        server["max_lag_ms"]))
    ca = clients[0].get("catchup") if clients else None
    if ca:
        print("[统计] 客户端 A 快进：补跑 %d 帧，耗时 %.1f ms，速度约 %.0f 帧/秒" % (
            ca["frames"], ca["elapsed_ms"], ca["fps"]))
        if ca["elapsed_ms"] > 0:
            print("[统计] 实时播放这 %d 帧需要 %.2f s → 快进比实时快 %.0f 倍" % (
                ca["frames"], ca["realtime_s"], ca["fps"] * cfg.tick))
    print("[统计] 服务器历史帧补发：%d 帧" % server["catchup_served"])
    print()
    ok = print_consistency(clients, cfg.frames, cfg.seed)
    if ok:
        conclusion("客户端 A 用 %.1f ms 追回了 60 帧（约 %.0f 帧/秒，实时需要 %.2f s）；"
                   "追帧后它的状态校验和与 B/C 及参考模型逐帧一致。"
                   "追帧的本质：补跑「错过的输入序列」，状态由确定性逻辑重算，"
                   "不需要传整份世界快照。"
                   % (ca["elapsed_ms"] if ca else 0.0, ca["fps"] if ca else 0.0,
                      ca["realtime_s"] if ca else freeze_seconds))
    else:
        conclusion("追帧后校验和不一致 → 判定 desync。")
    return ok


def run_replay():
    section(5, "录制输入序列 → 回放 → 校验和一致（回放的本质是输入序列）")
    frames = 300
    seed = SEED
    inputs = [[make_input(f, p, seed) for p in range(3)] for f in range(frames)]

    world = create_world()
    recorded = []
    for f in range(frames):
        step_world(world, inputs[f])
        recorded.append(world_checksum(world))
    blob = bytes(bytearray([v for frame in inputs for v in frame]))
    per_minute = len(blob) / float(frames) * 20 * 60 / 1024.0
    print("[录制] 录制 %d 帧 × 3 名玩家 = %d 字节输入（每帧每玩家 1 字节位掩码），"
          "按 20 Hz 回放约 %.1f KB/分钟" % (frames, len(blob), per_minute))
    print("[录制] 最后一帧校验和 0x%016x" % recorded[-1])

    world2 = create_world()
    replayed = []
    for f in range(frames):
        step_world(world2, inputs[f])
        replayed.append(world_checksum(world2))
    replay_ok = recorded == replayed
    print("[回放] 重新从初始状态跑一遍同一串输入：%d/%d 帧校验和一致" % (
        sum(1 for a, b in zip(recorded, replayed) if a == b), frames))

    tampered = [list(t) for t in inputs]
    tampered[150][1] ^= 0x01               # 只改第 150 帧玩家 B 的一个 bit
    world3 = create_world()
    changed = []
    for f in range(frames):
        step_world(world3, tampered[f])
        changed.append(world_checksum(world3))
    diff_frame = _first_diff(recorded, changed)
    print("[反证] 只翻转第 151 帧玩家 B 的一个输入 bit：从第 %d 帧起校验和开始不同"
          "（之后永久不同）" % (diff_frame + 1 if diff_frame is not None else -1))
    print("[结论0] 回放文件很小：%d 字节 = %d 帧输入。回放时重跑同一份确定性逻辑即可，"
          "不需要录状态。" % (len(blob), frames))
    ok = replay_ok and diff_frame == 150
    if ok:
        conclusion("输入序列回放与原始录制逐帧校验和一致；改动任意一帧输入，"
                   "后续轨迹立刻偏离 —— 说明状态的唯一变量就是输入。")
    else:
        conclusion("回放校验失败（不应该发生），请检查逻辑。")
    return ok


def _lockstep_up_bytes(entries=4):
    return IP_UDP + HEADER.size + 1 + entries * 5


def _lockstep_down_bytes(window=WIN, players=3):
    return IP_UDP + HEADER.size + 4 + 1 + window * (4 + players)


def _snapshot_down_bytes(entities):
    return IP_UDP + HEADER.size + 2 + entities * 9          # 9 B/实体：x,y,vx,vy 各 int16 + flags


def _delta_down_bytes(entities, dirty_ratio=0.4):
    dirty = max(1, int(entities * dirty_ratio))
    return IP_UDP + HEADER.size + 2 + dirty * 7             # 索引 2 + 掩码 1 + 位置增量 4


def run_bandwidth():
    section(6, "带宽估算：锁步 vs 状态同步（模型估算）")
    print("[说明] 按本文件实际协议格式 + IPv4(20) + UDP(8) 头估算，不含以太网头；"
          "锁步 3 名玩家；状态同步按 20 Hz。")
    print("[说明] 状态同步：全量 = 每实体 9 字节（int16 量化位置/速度 + flags）；"
          "增量 = 每帧约 40% 实体变化，每个变化实体 7 字节。")
    print()
    input_wire = IP_UDP + HEADER.size + 6
    rows = []
    for hz in (20, 60):
        down = _lockstep_down_bytes() * hz / 1024.0
        up = _lockstep_up_bytes() * hz / 1024.0
        rows.append(("锁步（3 玩家，冗余 3 帧）", "-", "%d Hz" % hz,
                     _lockstep_down_bytes(), down, up))
    for n in (10, 50, 200):
        size = _snapshot_down_bytes(n)
        rows.append(("状态同步·全量 %3d 实体" % n, n, "20 Hz", size, size * 20 / 1024.0,
                     input_wire * 20 / 1024.0))
    for n in (10, 50, 200):
        size = _delta_down_bytes(n)
        rows.append(("状态同步·增量 %3d 实体" % n, n, "20 Hz", size, size * 20 / 1024.0,
                     input_wire * 20 / 1024.0))
    print("  %-26s %6s %8s %12s %16s %16s" % (
        "方案", "实体数", "帧率", "每帧包(字节)", "下行 KB/s/客户端", "上行 KB/s/客户端"))
    print("  " + "-" * 92)
    for name, ent, hz, size, down, up in rows:
        print("  %-26s %6s %8s %12d %16.2f %16.2f" % (name, ent, hz, size, down, up))
    print()
    conclusion("锁步带宽几乎与实体数无关，只跟玩家数和帧率有关：3 人 20 Hz 约 1.1 KB/s；"
               "状态同步随实体数线性增长，200 实体全量 20 Hz 约 35 KB/s/客户端，"
               "增量编码能省掉大部分（前提是世界大部分实体是静止/低变化）。"
               "选择依据：谁权威、能接受多少延迟、实体多少。")
    return True


def run_all():
    t0 = time.monotonic()
    marks = [
        ("demo    真实 UDP 锁步 200 帧", run_demo),
        ("desync  float 分歧 vs 定点一致", run_desync),
        ("jitter  丢包/延迟下的冗余与卡顿", run_jitter),
        ("catchup 落后 60 帧快进追帧", run_catchup),
        ("replay  输入录制与回放", run_replay),
        ("bandwidth 带宽估算对比", run_bandwidth),
    ]
    results = []
    for name, fn in marks:
        try:
            results.append((name, fn()))
        except Exception:
            print("[错误] %s 运行异常：" % name)
            traceback.print_exc()
            results.append((name, False))
    elapsed = time.monotonic() - t0
    print()
    print("=" * 76)
    print("=== 总结（全部子命令耗时 %.1f s）" % elapsed)
    print("=" * 76)
    for name, ok in results:
        print("  [%s] %s" % ("通过" if ok else "失败", name))
    all_ok = all(ok for _, ok in results)
    if all_ok:
        conclusion("6 个演示全部通过：锁步在真实 UDP 上 200 帧无 desync；"
                   "同一逻辑用 float 会分歧、用定点不会；30% 丢包下靠冗余帧扛住；"
                   "落后 60 帧能毫秒级快进追回；回放只需输入序列；带宽按实体数线性增长。")
    else:
        conclusion("有演示失败，见上面的错误信息。")
    return all_ok


# ================================================================
# 9. 入口
# ================================================================
def main():
    if not sys.stdout.isatty():                     # Windows 管道输出默认 GBK，统一成 UTF-8
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(
        description="帧同步（Lockstep）真实 UDP 演示（纯标准库，Windows/macOS/Linux 可跑）")
    parser.add_argument("cmd", nargs="?", default="demo",
                        choices=["demo", "desync", "jitter", "catchup", "replay",
                                 "bandwidth", "all"],
                        help="要运行的演示（默认 demo）")
    args = parser.parse_args()
    try:
        ok = {
            "demo": run_demo,
            "desync": run_desync,
            "jitter": run_jitter,
            "catchup": run_catchup,
            "replay": run_replay,
            "bandwidth": run_bandwidth,
            "all": run_all,
        }[args.cmd]()
    except KeyboardInterrupt:
        print("\n已中断")
        return 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
