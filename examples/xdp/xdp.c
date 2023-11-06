//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct netpacket {
    u8 iph_len;
    u8 ip_ver; // ip 版本
    u8 tran_proto; // ip上层的协议
    __be32 src_ip; // 源地址
    __be32 dst_ip; // 目的地址
    __be16 src_port; // 源端口
    __be16 dst_port; // 目标端口
};
// Force emitting struct event into the ELF.
const struct netpacket *unused __attribute__((unused));

#define MAX_MAP_ENTRIES 16
#define BUF_SIZE 32

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} messages SEC(".maps");

struct tran_h {
    __be16 source;
    __be16 dest;
};

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);

    // 不是tcp 跳过
    if(ip->protocol != 6) return 1;

    struct tran_h* tcph = data + sizeof(struct ethhdr) + (ip->ihl * 4);
    struct netpacket* packet = bpf_ringbuf_reserve(&messages, sizeof(struct netpacket), 0);

    // 目标 ip = 192.168.1.33 目标端口 = 80 -> 把目标端口改写成 37700
    // 源 ip = 192.168.1.33 源端口 = 37700 -> 把源端口改写成 80
    if (packet) {
        packet->iph_len = ip->ihl * 4;
        packet->ip_ver = ip->version;
        packet->src_ip = ip->saddr;
        packet->dst_ip = ip->daddr;
        packet->tran_proto = ip->protocol;
        
        if( ((u64) tcph)  + 4 <= (u64) data_end )  {
            packet->src_port = tcph->source;
            packet->dst_port = tcph->dest;
        }

        bpf_ringbuf_submit(packet, 0);
    }


	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
