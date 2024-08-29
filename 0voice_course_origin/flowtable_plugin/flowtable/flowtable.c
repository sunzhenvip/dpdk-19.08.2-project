


#include "flowtable.h"
#include <vnet/plugin/plugin.h>



int flowtable_enable(flowtable_main_t *fm, u32 sw_if_index, int enable) {

	u32 node_index = enable ? flowtable_node.index : ~0;
	
	printf("debug:[%s:%s:%d] node_index:%d\n", __FILE__, __func__, __LINE__, flowtable_node.index);
	
	return vnet_hw_interface_rx_redirect_to_node(fm->vnet_main, sw_if_index, node_index);
}


static clib_error_t *flowtable_command_enable_fn (struct vlib_main_t * vm,
		unformat_input_t * input, struct vlib_cli_command_t * cmd) {

	flowtable_main_t *fm = &flowtable_main;

	u32 sw_if_index = ~0;
	int enable_disable = 1;

	while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {

		if (unformat(input, "disable")) {
			enable_disable = 0;
		} else if (unformat(input, "%U", unformat_vnet_sw_interface, fm->vnet_main, &sw_if_index))
			;
		else break;
	}

	if (sw_if_index == ~0) {
		return clib_error_return(0, "No Interface specified");
	}

	int rv = flowtable_enable(fm, sw_if_index, enable_disable);
	if (rv) {
		if (rv == VNET_API_ERROR_INVALID_SW_IF_INDEX) {
			return clib_error_return(0, "Invalid interface");
		} else if (rv == VNET_API_ERROR_UNIMPLEMENTED) {
			return clib_error_return (0, "Device driver doesn't support redirection");
		} else {
			return clib_error_return (0, "flowtable_enable_disable returned %d", rv);
		}
	}

	return 0;
}



VLIB_CLI_COMMAND(flowtable_interface_enable_disable_command) = {

	.path = "flowtable",
	.short_help = "flowtable <interface> [disable]",
	.function = flowtable_command_enable_fn,

};


