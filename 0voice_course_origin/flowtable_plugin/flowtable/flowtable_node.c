

#include "flowtable.h"
#include <vnet/plugin/plugin.h>

#include <arpa/inet.h>


vlib_node_registration_t flowtable_node;


typedef struct {
  u64 hash;
  u32 sw_if_index;
  u32 next_index;
  u32 offloaded;
} flow_trace_t;



static u8 *format_flowtable_getinfo (u8 * s, va_list * args) {

	CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  	CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  	flow_trace_t *t = va_arg(*args, flow_trace_t*);

	s = format(s, "FlowInfo - sw_if_index %d, hash = 0x%x, next_index = %d, offload = %d",
			t->sw_if_index,
			t->hash, t->next_index, t->offloaded);

	return s;

}


u64 hash4(ip4_address_t ip_src, ip4_address_t ip_dst, u8 protocol, u16 port_src, u16 port_dst) {

	return ip_src.as_u32 ^ ip_dst.as_u32 ^ protocol ^ port_src ^ port_dst;

}

static uword flowtable_getinfo (struct vlib_main_t * vm,
				      struct vlib_node_runtime_t * node, struct vlib_frame_t * frame) {

	u32 n_left_from, *from, *to_next;
    u32 next_index  = node->cached_next_index;

    from        = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;

    while(n_left_from > 0){
            u32 n_left_to_next;
            vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

            while(n_left_from > 0 && n_left_to_next > 0){
                    vlib_buffer_t  *b0;
                    u32             bi0, next0 = 0;

                    bi0 = to_next[0] = from[0];
                    from           += 1;
                    to_next        += 1;
                    n_left_to_next -= 1;
                    n_left_from    -= 1;

                    b0 = vlib_get_buffer(vm, bi0);
                    
					ip4_header_t *ip0 = vlib_buffer_get_current(b0);
					ip4_address_t ip_src = ip0->src_address;
					ip4_address_t ip_dst = ip0->dst_address;
					u32 sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

					struct in_addr addr;
					addr.s_addr = ip_src.as_u32;
					printf("sw_if_index0: %d, ip_src: %s ", sw_if_index0, inet_ntoa(addr));
					
					addr.s_addr = ip_dst.as_u32;
					printf(" ip_dst: %s \n", inet_ntoa(addr));
/*
					if (ip_src.as_u32 % 2) {
						next0 = FT_NEXT_LOAD_BALANCER;
					}
                  */ 
                    vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                            to_next, n_left_to_next, bi0, next0);
            }

            vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;

}

static char *flowtable_error_strings[] = {
#define _(sym,string) string,
  foreach_flowtable_error
#undef _
};


VLIB_REGISTER_NODE(flowtable_node) = {

	.function = flowtable_getinfo,
	.name = "flow-table",
	.vector_size = sizeof(u32),
	.format_trace = format_flowtable_getinfo,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_errors = FLOWTABLE_N_ERROR,
	.error_strings = flowtable_error_strings,
	.n_next_nodes = FT_NEXT_N_NEXT,
	.next_nodes = {
		[FT_NEXT_IP4]    = "ip4-lookup",
		[FT_NEXT_DROP] = "error-drop",
		[FT_NEXT_ETHERNET_INPUT] = "ethernet-input",
		[FT_NEXT_LOAD_BALANCER] = "load-balance",
		[FT_NEXT_INTERFACE_OUTPUT] = "interface-output",
	}
};




VLIB_PLUGIN_REGISTER() = {

	.version = "1.0",
	.description = "sample of flowtable",

};


static clib_error_t *flowtable_init(vlib_main_t *vm) {

	clib_error_t *error = 0;

	flowtable_main_t *fm = &flowtable_main;
	fm->vnet_main = vnet_get_main();
	fm->vlib_main = vm;

	flow_info_t *flow;
	pool_get_aligned(fm->flows, flow, CLIB_CACHE_LINE_BYTES);
	pool_put(fm->flows, flow);

	BV(clib_bihash_init)(&fm->flows_ht, "flow hash table", FM_NUM_BUCKETS, FM_MEMORY_SIZE);

	return error;
}

VLIB_INIT_FUNCTION(flowtable_init);


