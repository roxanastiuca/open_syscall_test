#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    char filename[256];
    long ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB ring buffer
} events SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_sys_enter_open(struct trace_event_raw_sys_enter* ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (char *)ctx->args[1]);
    e->ret = 0;  // Initialize ret to 0 as we're only entering

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_sys_exit_open(struct trace_event_raw_sys_exit* ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->filename[0] = '\0';  // Empty filename for exit event
    // e->ret = ctx->ret;
    bpf_probe_read_kernel(&e->ret, sizeof(e->ret), &ctx->ret);
    // long ret = ctx->ret;
    // bpf_probe_read(&e->ret, sizeof(e->ret), &ret);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
