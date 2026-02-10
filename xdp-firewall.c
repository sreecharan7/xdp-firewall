#include<stdio.h>
#include<signal.h>
#include<arpa/inet.h>
#include <net/if.h>
#include<unistd.h>

#include<bpf/bpf.h>
#include "xdp.bpf.skel.h"

static volatile int running = 1;

static void signal_handler(int sig){
    running=0;
}

struct ip_port_state_key{
    __u32 ip;
    __u16 port;
    __u16 proto;
    __u32 status;
};

int main(){
    signal(SIGINT,signal_handler);
    struct xdp_bpf *skel;
    int err;

    skel=xdp_bpf__open_and_load();

    if(!skel){
        fprintf(stderr,"failed to open/load the xdp");
        return 1;
    }

    int ifindex=if_nametoindex("wlp0s20f3");

    if(bpf_program__attach_xdp(
        skel->progs.xdp_attach,
        ifindex
    )==NULL){
        fprintf(stderr,"failed to attach xdp to the network interface");
        return 1;
    }

    int map_fd=bpf_map__fd(skel->maps.pkt_cnt);
    int numcpus = libbpf_num_possible_cpus();

    uint64_t *val;
    val=calloc(numcpus,sizeof(uint64_t));
    
    if(!val)goto cleanup;
    struct ip_port_state_key key;
    struct ip_port_state_key next_key;
    int has_key=0;
    while (running)
    {
        has_key=0;
        while(bpf_map_get_next_key(map_fd,(has_key==0?NULL:&key),&next_key)==0){
            key=next_key;
            has_key=1;
            if(bpf_map_lookup_elem(map_fd,&key,val)==0){
                uint64_t sum=0;
                for(int i=0;i<numcpus;i++){
                    sum+=val[i];
                }
                struct in_addr a;
                a.s_addr=key.ip;
                printf("%s:%d proto=%d -> %llu\n",
                   inet_ntoa(a),
                   key.port,
                   key.proto,
                   sum);
            }
        }
        printf("-----------\n");
        sleep(2);
    }
cleanup:
    xdp_bpf__destroy(skel);
    return 0;
}