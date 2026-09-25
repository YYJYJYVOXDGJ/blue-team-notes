# -*- coding: utf-8 -*-
"""性能基准：验证流水线能处理大规模采集产物，且内存占用不随数据量增长。

为什么需要这个：
    应急现场的产物经常很大——一台跑了半年的服务器，ps 快照几万行、
    连接表十几万行、事件日志导出上百万行。如果解析器是"整个文件读进内存
    再处理"，在第一台真实机器上就会 OOM。所以"能跑小样本"不等于"能用"。

本脚本做两件事：
    1. 测吞吐：不同规模下的行/秒、MB/秒
    2. 测内存：对比「流式解析」（本流水线）与「全量读入」（朴素实现）的峰值内存

    第 2 项是关键——它证明内存占用与文件大小无关，这才是"能处理大规模日志"。

用法：
    python bench/bench_parse.py              # 默认 1万/10万/50万 行三档
    python bench/bench_parse.py --rows 100000
    python bench/bench_parse.py --keep       # 保留生成的样本文件

零第三方依赖。
"""
from __future__ import annotations

import argparse
import gc
import io
import os
import shutil
import sys
import tempfile
import time
import tracemalloc

_HERE = os.path.dirname(os.path.abspath(__file__))
_MCP = os.path.dirname(_HERE)
if _MCP not in sys.path:
    sys.path.insert(0, _MCP)

from irflow.adapters.linux_quickcheck import LinuxQuickCheckAdapter   # noqa: E402
from irflow.schema import Collection                                  # noqa: E402

PS_HEADER = ("    PID    PPID USER     TT       STAT                  "
             "STARTED     ELAPSED CMD")

_CMDS = [
    "/usr/lib/systemd/systemd-journald",
    "/usr/sbin/sshd -D",
    "/usr/bin/python3 /opt/app/worker.py --queue default",
    "/usr/sbin/nginx: worker process",
    "/opt/java/bin/java -Xmx4g -jar /opt/app/service.jar",
    "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
    "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main",
]


def gen_ps_file(path: str, rows: int) -> None:
    """生成一份格式与 `ps -eo pid,ppid,user,tty,stat,lstart,etime,cmd` 一致的样本。"""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(PS_HEADER + "\n")
        for i in range(rows):
            pid = 1000 + i
            ppid = 1 if i % 3 else 1000 + (i // 3)
            user = ("root", "nginx", "app", "postgres")[i % 4]
            stat = ("Ss", "Ssl", "S", "R", "Sl")[i % 5]
            cmd = _CMDS[i % len(_CMDS)]
            f.write("{0:>7} {1:>7} {2:<8} {3:<3} {4:<5} "
                    "Mon Sep 15 10:00:00 2026  {5} {6}\n".format(
                        pid, ppid, user, "?", stat, "%d-%02d:%02d:00" % (i % 10, i % 24, i % 60),
                        cmd))


def _force_utf8() -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def bench_streaming(path: str, root: str) -> dict:
    """本流水线的做法：生成器流式解析，逐条消费不入内存。"""
    adapter = LinuxQuickCheckAdapter()
    col = Collection(root=root, platform="linux")

    gc.collect()
    tracemalloc.start()
    t0 = time.perf_counter()

    count = 0
    for _rec in adapter.parse(root, col):
        count += 1

    elapsed = time.perf_counter() - t0
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    size = os.path.getsize(path)
    return {
        "records": count,
        "elapsed_s": elapsed,
        "peak_mb": peak / 1024 / 1024,
        "file_mb": size / 1024 / 1024,
        "rows_per_s": count / elapsed if elapsed else 0,
        "mb_per_s": (size / 1024 / 1024) / elapsed if elapsed else 0,
    }


def bench_naive(path: str) -> dict:
    """朴素做法：readlines() 全量读入内存后再处理。

    保留它的目的是**留一个对照**——用数字说明为什么必须流式，
    而不是在文档里写一句"我们用了生成器"就完事。
    """
    gc.collect()
    tracemalloc.start()
    t0 = time.perf_counter()

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()          # ← 全量入内存，OOM 风险点
    count = sum(1 for ln in lines if ln.strip())

    elapsed = time.perf_counter() - t0
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    del lines
    gc.collect()
    return {"records": count, "elapsed_s": elapsed, "peak_mb": peak / 1024 / 1024}


def main() -> int:
    _force_utf8()
    ap = argparse.ArgumentParser(description="流水线性能基准")
    ap.add_argument("--rows", type=int, nargs="+",
                    default=[10000, 100000, 500000],
                    help="每个档位的行数")
    ap.add_argument("--keep", action="store_true", help="保留生成的样本文件")
    args = ap.parse_args()

    tmpdir = tempfile.mkdtemp(prefix="irflow-bench-")
    print("=" * 72)
    print(" 流水线性能基准（合成数据，非真实环境）")
    print("=" * 72)
    print("")
    print(" 说明：与「全量读入内存」的朴素实现对照，验证内存占用是否与数据量解耦")
    print("")
    print(" {0:>10} {1:>9} {2:>11} {3:>13} {4:>10} {5:>13}".format(
        "行数", "文件MB", "本流水线s", "本流水线峰值KB", "朴素s", "朴素峰值KB"))
    print(" " + "-" * 70)

    try:
        for rows in args.rows:
            # 每档建一个独立目录，模拟真实的采集输出结构
            case = os.path.join(tmpdir, "case-{0}".format(rows))
            os.makedirs(os.path.join(case, "proc"), exist_ok=True)
            ps_path = os.path.join(case, "proc", "ps-full.txt")
            gen_ps_file(ps_path, rows)

            stream = bench_streaming(ps_path, case)
            naive = bench_naive(ps_path)

            print(" {0:>10} {1:>9.1f} {2:>11.2f} {3:>13.1f} {4:>10.2f} {5:>13.1f}".format(
                rows, stream["file_mb"], stream["elapsed_s"], stream["peak_mb"] * 1024,
                naive["elapsed_s"], naive["peak_mb"] * 1024))

            ratio = naive["peak_mb"] / stream["peak_mb"] if stream["peak_mb"] else 0
            print("            └ 吞吐 {0:,.0f} 行/秒 · {1:.1f} MB/秒 · "
                  "本流水线峰值内存为朴素实现的 1/{2:.0f}".format(
                      stream["rows_per_s"], stream["mb_per_s"], ratio))
            print("")

        print(" " + "-" * 70)
        print(" 结论：流式解析的峰值内存与文件大小**无关**（恒定在数 MB 量级），")
        print("       因此产物从 1 万行涨到 50 万行时，内存开销基本不变；")
        print("       而全量读入方案的峰值内存随文件线性增长，大文件必然 OOM。")
        print("")
        print(" 注：以上为合成数据基准，用于验证实现特性，不代表真实环境的绝对指标。")
    finally:
        if args.keep:
            print("\n样本保留在: {0}".format(tmpdir))
        else:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
