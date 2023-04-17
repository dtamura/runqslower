// +build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "runqslower.h"

#define TASK_RUNNING 0

const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;

typedef struct {
    __u64 ts;
    int target_cpu;
} waking_up_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, waking_up_info_t);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct task_struct___o {
    volatile long int state;
} __attribute__((preserve_access_index));

struct task_struct___x {
    unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task) {
    struct task_struct___x *t = task;

    if (bpf_core_field_exists(t->__state))
        return BPF_CORE_READ(t, __state);
    return BPF_CORE_READ((struct task_struct___o *)task, state);
}

/* record enqueue timestamp */
static int __attribute__((unused)) trace_enqueue(u32 tgid, u32 pid) {
    u64 ts;

    if (!pid)
        return 0;
    if (targ_tgid && targ_tgid != tgid)
        return 0;
    if (targ_pid && targ_pid != pid)
        return 0;

    waking_up_info_t *valp;
    valp = bpf_map_lookup_elem(&start, &pid);
    if (valp == NULL) {
        ts = bpf_ktime_get_ns();
        waking_up_info_t val;
        __builtin_memset(&val, 0, sizeof(val));
        val.ts = ts;
        bpf_map_update_elem(&start, &pid, &val, 0);
    }
    return 0;
}

static int trace_enqueue2(u32 pid, int target_cpu) {

    u64 ts = bpf_ktime_get_ns();
    waking_up_info_t val;
    __builtin_memset(&val, 0, sizeof(val));
    val.ts = ts;
    val.target_cpu = target_cpu;
    bpf_map_update_elem(&start, &pid, &val, 0);

    return 0;
}

static int handle_switch(void *ctx, struct task_struct *prev,
                         struct task_struct *next) {
    struct event event = {};
    u64 ts, delta_us;
    waking_up_info_t *valp;
    u32 pid;

    u64 switch_ts = bpf_ktime_get_ns();

    /* ivcsw: treat like an enqueue event and store timestamp */
    if (get_task_state(prev) == TASK_RUNNING)
        trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

    pid = BPF_CORE_READ(next, pid);

    /* fetch timestamp and calculate delta */
    valp = bpf_map_lookup_elem(&start, &pid);
    if (valp == NULL) {
        return 0; /* missed enqueue */
    }
    ts = valp->ts;

    delta_us = (switch_ts - ts) / 1000;
    if (min_us && delta_us <= min_us)
        return 0;

    event.pid = pid;
    event.prev_pid = BPF_CORE_READ(prev, pid);
    event.delta_us = delta_us;
    event.switch_time = switch_ts;
    event.target_cpu = valp->target_cpu;
    bpf_probe_read_kernel_str(&event.task, sizeof(event.task), next->comm);
    bpf_probe_read_kernel_str(&event.prev_task, sizeof(event.prev_task),
                              prev->comm);

    /* output */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                          sizeof(event));

    bpf_map_delete_elem(&start, &pid);
    return 0;
}

/* ref: /sys/kernel/tracing/events/sched/sched_wakeup/format */
struct sched_wakeup_args {
    unsigned long pad; /* The first 8 bytes is not allowed to read */

    char comm[TASK_COMM_LEN];
    pid_t pid;
    int prio;
    int success;
    int target_cpu;
};

SEC("tracepoint/sched_wakeup")
int tp_sched_wakeup(struct sched_wakeup_args *ctx) {
    return trace_enqueue2(ctx->pid, ctx->target_cpu);
}
SEC("tracepoint/sched_wakeup_new")
int tp_sched_wakeup_new(struct sched_wakeup_args *ctx) {
    return trace_enqueue2(ctx->pid, ctx->target_cpu);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next) {
    return handle_switch(ctx, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
