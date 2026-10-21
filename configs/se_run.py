"""
gem5 SE-mode configuration for the JCEN side-channel detection experiments.

Runs a single statically-linked workload binary on a configurable
out-of-order core and dumps+resets statistics at a fixed tick interval,
so that each run yields a *time series* of microarchitectural counters
(the temporal features) in addition to the end-of-run aggregate stats.

Invoke via gem5, not plain python:

    gem5.opt configs/se_run.py \
        --binary workloads/bin/aes_ttable_fr \
        --l1d 32kB --l1i 32kB --l2 128kB --l2-assoc 8 --line-size 64 \
        --interval 100000 --max-intervals 256 \
        --outdir data/raw/aes_ttable_fr_small_s0

Tested against the gem5 stdlib API (v22+/v23). Adjust imports if your
gem5 is older (the classic `configs/example/se.py` style still works).
"""
import argparse
import m5
from m5.objects import (
    System, SrcClockDomain, VoltageDomain, AddrRange, Process, Root,
    SystemXBar, L2XBar, MemCtrl, DDR3_1600_8x8, Cache, DerivO3CPU,
    TimingSimpleCPU, SEWorkload,
)


# ---- simple cache classes (classic memory system) -------------------------
class L1Cache(Cache):
    assoc = 8
    tag_latency = 2
    data_latency = 2
    response_latency = 2
    mshrs = 16
    tgts_per_mshr = 20


class L1I(L1Cache):
    pass


class L1D(L1Cache):
    pass


class L2Cache(Cache):
    tag_latency = 20
    data_latency = 20
    response_latency = 20
    mshrs = 20
    tgts_per_mshr = 12


def parse_size(s):
    return s  # gem5 accepts "32kB" style strings directly for size params


def build_system(args):
    system = System()
    system.clk_domain = SrcClockDomain(clock=args.clock,
                                       voltage_domain=VoltageDomain())
    system.mem_mode = "timing"
    system.mem_ranges = [AddrRange("512MB")]

    cpu_cls = DerivO3CPU if args.cpu == "o3" else TimingSimpleCPU
    system.cpu = cpu_cls()

    system.membus = SystemXBar()

    # L1s
    system.cpu.icache = L1I(size=args.l1i, assoc=args.l1_assoc)
    system.cpu.dcache = L1D(size=args.l1d, assoc=args.l1_assoc)
    system.cpu.icache_port = system.cpu.icache.cpu_side
    system.cpu.dcache_port = system.cpu.dcache.cpu_side

    # L2 behind a crossbar
    system.l2bus = L2XBar()
    system.cpu.icache.mem_side = system.l2bus.cpu_side_ports
    system.cpu.dcache.mem_side = system.l2bus.cpu_side_ports
    system.l2cache = L2Cache(size=args.l2, assoc=args.l2_assoc)
    system.l2cache.cpu_side = system.l2bus.mem_side_ports
    system.l2cache.mem_side = system.membus.cpu_side_ports

    system.cache_line_size = args.line_size

    system.cpu.createInterruptController()
    # x86 interrupt wiring
    for ic in system.cpu.interrupts:
        ic.pio = system.membus.mem_side_ports
        ic.int_requestor = system.membus.cpu_side_ports
        ic.int_responder = system.membus.mem_side_ports

    system.mem_ctrl = MemCtrl()
    system.mem_ctrl.dram = DDR3_1600_8x8(range=system.mem_ranges[0])
    system.mem_ctrl.port = system.membus.mem_side_ports
    system.system_port = system.membus.cpu_side_ports

    # gem5 v23 requires an SEWorkload on the system before the process runs.
    system.workload = SEWorkload.init_compatible(args.binary)

    process = Process()
    process.cmd = [args.binary] + args.args
    system.cpu.workload = process
    system.cpu.createThreads()
    return system


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--args", nargs="*", default=[])
    p.add_argument("--cpu", choices=["o3", "simple"], default="o3")
    p.add_argument("--clock", default="3GHz")
    p.add_argument("--l1i", default="32kB")
    p.add_argument("--l1d", default="32kB")
    p.add_argument("--l1-assoc", type=int, default=8)
    p.add_argument("--l2", default="128kB")
    p.add_argument("--l2-assoc", type=int, default=8)
    p.add_argument("--line-size", type=int, default=64)
    p.add_argument("--interval", type=int, default=100000,
                   help="dump+reset stats every N ticks (temporal sampling)")
    p.add_argument("--max-intervals", type=int, default=256)
    args = p.parse_args()

    system = build_system(args)
    root = Root(full_system=False, system=system)
    m5.instantiate()

    # Interval loop: simulate `interval` ticks, dump+reset, repeat.
    # Each dumpstats() appends a block to stats.txt -> one time step.
    n = 0
    exit_event = None
    while n < args.max_intervals:
        exit_event = m5.simulate(args.interval)
        cause = exit_event.getCause()
        if cause != "simulate() limit reached":
            break  # workload finished (exit syscall) before the cap
        m5.stats.dump()
        m5.stats.reset()
        n += 1
    # final partial interval
    m5.stats.dump()
    print(f"[se_run] intervals={n} last_cause={exit_event.getCause() if exit_event else 'none'}")


main()  # gem5 execs this file; no __main__ guard needed
