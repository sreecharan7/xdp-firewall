#/bin/bash

if [[ ! -f "vmlinux.h" ]]; then
    echo "generating vmlinux...";
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h        
fi

clang -O2 -g -target bpf -c xdp.bpf.c -o xdp.bpf.o   

llvm-strip -g xdp.bpf.o 

bpftool gen skeleton xdp.bpf.o > xdp.bpf.skel.h   

gcc -O2 -g  xdp-firewall.c -o xdp-firewall.out -lbpf  
