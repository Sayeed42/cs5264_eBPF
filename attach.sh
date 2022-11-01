#!/bin/bash
echo 1 > /proc/sys/kernel/bpf_stats_enabled
./mem_comp &
cat /sys/kernel/debug/tracing/trace_pipe &
