#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <pktdump/pktdump.h>

#include <arpa/inet.h>

typedef enum
{
  CK_SAMPLE_NEXT_IP4,
  CK_SAMPLE_DROP,
  CK_SAMPLE_NEXT_N,
} ck_sample_next_t;

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 new_src_mac[6];
  u8 new_dst_mac[6];
} ck_sample_trace_t;

#define foreach_ck_sample_error \
_(SHOWED, "show packets processed")

typedef enum
{
#define _(sym,str) SAMPLE_ERROR_##sym,
  foreach_ck_sample_error
#undef _
    SAMPLE_N_ERROR,
} ck_ssample_error_t;


static char *ck_sample_error_strings[] = {
#define _(sym, str) str,
        foreach_ck_sample_error
#undef _
};

extern vlib_node_registration_t ck_sample_node;

static u8 *
format_ck_sample_trace (u8 * s, va_list * args)
{
        s = format(s, "To Do!\n");
        return s;
}

static uword ck_sample_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node,
        vlib_frame_t * frame)
{
        u32 n_left_from, *from, *to_next;
        ck_sample_next_t     next_index;

        from        = vlib_frame_vector_args(frame);
        n_left_from = frame->n_vectors;
        next_index  = node->cached_next_index;

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

                        vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                to_next, n_left_to_next, bi0, next0);
                }

                vlib_put_next_frame(vm, node, next_index, n_left_to_next);
        }

        return frame->n_vectors;
}


VLIB_REGISTER_NODE (bridge_node) = {
        .name		= "bridge-node",
        .function       = ck_sample_node_fn,
        .vector_size    = sizeof(u32),
        .format_trace   = format_ck_sample_trace,
        .type           = VLIB_NODE_TYPE_INTERNAL,
        .n_errors       = ARRAY_LEN(ck_sample_error_strings),
        .error_strings  = ck_sample_error_strings,
        .n_next_nodes   = CK_SAMPLE_NEXT_N,
        .next_nodes     = {
                [CK_SAMPLE_NEXT_IP4]    = "ip4-lookup",
                [CK_SAMPLE_DROP]        = "error-drop",
        },
};





