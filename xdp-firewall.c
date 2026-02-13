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

struct ip_proto_block_key{
    __u32 ip;
    __u16 port;
    __u16 proto;
};

void fill_key(struct ip_proto_block_key *key,
    const char *ip,
    uint16_t port,
    const char *proto)
{
    memset(key, 0, sizeof(*key));

    inet_pton(AF_INET,ip,&key->ip);

    // key->port=htons(port);
    key->port=(port);

    if(strcmp(proto,"tcp")==0){
        key->proto=IPPROTO_TCP;
    }else if(strcmp(proto,"udp")==0){
        key->proto=IPPROTO_UDP;
    }
}
void block_ip_proto(const char *ip,
    uint16_t port,
    const char *proto,
    int map_fd
)
{
    struct ip_proto_block_key key={};
    fill_key(&key,ip,port,proto);
    __u64 init=0;
    printf("ip=%d port=%d proto=%d\n",key.ip,key.port,key.proto);
    bpf_map_update_elem(map_fd,&key,&init,BPF_ANY);
}

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

    struct ip_proto_block_key block_key={};

    

    int map_fd=bpf_map__fd(skel->maps.pkt_cnt);
    int block_map_fd=bpf_map__fd(skel->maps.pkt_block);

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
                printf("%s:%d proto=%d -> %llu (%d)\n",
                   inet_ntoa(a),
                   key.port,
                   key.proto,
                   sum,
                   key.status);
            }
        }
        printf("-----------\n");
        sleep(2);
    }
cleanup:
    xdp_bpf__destroy(skel);
    return 0;
}