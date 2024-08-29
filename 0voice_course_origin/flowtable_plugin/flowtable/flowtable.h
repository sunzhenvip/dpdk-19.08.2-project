


#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/pool.h>
#include <vppinfra/bihash_8_8.h>



#define foreach_flowtable_error				\
 _(THRU, "Flowtable packets gone thru") \
 _(FLOW_CREATE, "Flowtable packets which created a new flow") \
 _(FLOW_HIT, "Flowtable packets with an existing flow") 


typedef enum {

#define _(sym,str) FLOWTABLE_ERROR_##sym,
	foreach_flowtable_error
#undef _

	FLOWTABLE_N_ERROR

} flowtable_error_t;


typedef enum {

	FT_NEXT_IP4,
	FT_NEXT_DROP,
	FT_NEXT_ETHERNET_INPUT,
	FT_NEXT_LOAD_BALANCER,
	FT_NEXT_INTERFACE_OUTPUT,
	FT_NEXT_N_NEXT
	
} flowtable_next_t;


typedef struct {

	u64 hash;

	u32 cached_next_node;
	u16 offloaded;

	u16 sig_len;

	union {
		struct {
			ip6_address_t src, dst;
			u8 proto;
			u16 src_port, dst_port;
		} ip6;

		struct {
			ip4_address_t src, dst;
			u8 proto;
			u16 src_port, dst_port;
		} ip4;
		u8 data[32];
	} signature;

	u64 last_ts;

	struct {
		u32 straight;
		u32 reverse;
	} packet_stats;

	union {
		struct {

			u32 SYN:1;
			u32 SYN_ACK:1;
			u32 SYN_ACK_ACK:1;

			u32 FIN:1;
			u32 FIN_ACK:1;
			u32 FIN_ACK_ACK:1;

			u32 last_seq_number, last_ack_number;

		} tcp;
		
		struct {

			uword flow_info_ptr;
			u32 sw_if_index_dst;
			u32 sw_if_index_rev;
			u32 sw_if_index_current;
			
		} lb;

		u8 flow_data[CLIB_CACHE_LINE_BYTES];
	} ;

} flow_info_t;


typedef struct {

	flow_info_t *flows;

	BVT(clib_bihash) flows_ht;

	vlib_main_t *vlib_main;
	vnet_main_t *vnet_main;

	u32 ethernet_input_next_index;

} flowtable_main_t;


#define FM_NUM_BUCKETS	4
#define FM_MEMORY_SIZE		(256<<16)



flowtable_main_t flowtable_main;

extern vlib_node_registration_t flowtable_node;

int flowtable_enable(flowtable_main_t *fm, u32 sw_if_index, int enable);



