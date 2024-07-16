#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include "bpf_program.skel.h"  // Include the generated vmlinux.h

static volatile bool exiting = false;

struct event {
    char filename[256];
    long ret;
};

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;

    if (e->ret == 0) {
        printf("sys_enter_open: filename=%s\n", e->filename);
    } else {
        printf("sys_exit_open: ret=%ld\n", e->ret);
    }
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_program_bpf *obj;
    int err;

    // libbpf_set_strict_mode(LIBBPF_STRICT_ALL); // TODO: check if this is necessary
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);

    obj = bpf_program_bpf__open_opts(&open_opts);
    if (!obj) {
        fprintf(stderr, "ERROR: opening BPF object failed\n");
        return 1;
    }

    err = bpf_program_bpf__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }
    
    err = bpf_program_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "ERROR: attaching BPF program failed\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: creating ring buffer failed\n");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Poll ring buffer
    while (!exiting) {
        err = ring_buffer__poll(rb, 10000);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ERROR: polling ring buffer failed\n");
            break;
        }
    }

    // Clean up
    ring_buffer__free(rb);
    bpf_program_bpf__destroy(obj);

    printf("Exiting\n");
    return 0;
}
