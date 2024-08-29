

#define debug		printf			

#define foreach_loadbalancer_error  _(PROCESSED, "Loadbalancer packets gone thru") 



typedef enum {

#define _(sym,str) LOADBALANCER_ERROR_##sym,

	foreach_loadbalancer_error
#undef _

	LOADBALANCER_N_ERROR
	
} loadbalancer_error_t;

typedef struct {

	vlib_main_t *vlib_main;
	vnet_main_t *vnet_main;

} loadbalancer_main_t;


typedef struct {

	loadbalancer_main_t *lbm;

	u32 sw_if_index_source;
	u32 *sw_if_target;
	u32 last_target_index;

} loadbalancer_runtime_t;


loadbalancer_main_t loadbalancer_main;


extern vlib_node_registration_t loadbalancer_node;



