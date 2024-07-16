
build:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf_program.bpf.c -o bpf_program.bpf.o
	bpftool gen skeleton bpf_program.bpf.o > bpf_program.skel.h
	clang -o loader loader.c -lbpf

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
