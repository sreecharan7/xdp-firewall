#include "vmlinux.h"
#include<bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800


char LICENSE[] SEC("license") ="GPL";


struct ip_port_state_key{
    u32 ip;
    u16 port;
    u16 proto;
    u32 status;
};

struct{
    __uint(type,BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries,1024);
    __type(key,struct ip_port_state_key);
    __type(value,u64);
} pkt_cnt SEC(".maps");


SEC("xdp")
int xdp_attach(struct xdp_md *ctx){
    void *data=(void *)(long)ctx->data;
    void *data_end=(void *)(long)ctx->data_end;
    struct ethhdr *eth =data;

    if((void *)(eth+1)>data_end)return XDP_PASS;
    if(eth->h_proto!=bpf_htons(ETH_P_IP))return XDP_PASS;

    struct iphdr *ip=data+sizeof(*eth);

    if((void * )(ip+1)>data_end)return XDP_PASS;
    
    struct ip_port_state_key key={};

    key.ip=ip->saddr;
    key.proto=ip->protocol;

    void *l4=(void *)ip+ip->ihl*4;

    if(ip->protocol==IPPROTO_TCP){
        struct tcphdr *tcp=l4;
        if((void *)(tcp+1)>data_end)return XDP_PASS;
        key.port=tcp->source;
    }
    else if(ip->protocol==IPPROTO_UDP){
        struct udphdr *udp=l4;
        if((void *)(udp+1)>data_end)return XDP_PASS;
        key.port=udp->source;
    }
    else return XDP_PASS;

    key.status=1;

    u64 *val=bpf_map_lookup_elem(&pkt_cnt,&key);

    if(val){
        (*val)++;
    }else{
        u64 one=1;
        bpf_map_update_elem(&pkt_cnt,&key,&one,BPF_ANY);
    }
    return XDP_PASS;
}