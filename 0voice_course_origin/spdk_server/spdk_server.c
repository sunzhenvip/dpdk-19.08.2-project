


#include "spdk/stdinc.h"
#include "spdk/thread.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/string.h"

#include "spdk/log.h"
#include "spdk/sock.h"



//
#define ADDR_STR_LEN		INET6_ADDRSTRLEN
#define BUFFER_SIZE			1024

static char *g_host;
static int g_port;
static char *g_sock_impl_name;
static bool g_running;

struct server_context_t {

	char *host;
	int port;
	char *sock_impl_name;

	int bytes_in;
	int bytes_out;
	
	struct spdk_sock *sock;
	struct spdk_sock_group *group;

};


// printf();
// debug

static void spdk_server_shutdown_callback(void) {

	g_running = false;

}

// -H 0.0.0.0 -P 8888 
static int spdk_server_app_parse(int ch, char *arg) {

	printf("spdk_server_app_parse: %s\n", arg);
	switch (ch) {

	case 'H':
		g_host = arg;
		break;

	case 'P':
		g_port = spdk_strtol(arg, 10);
		if (g_port < 0) {
			SPDK_ERRLOG("Invalid port ID\n");
			return g_port;
		}
		break;

	case 'N':
		g_sock_impl_name = arg; //-N posix or -N uring
		break;

	default:
		return -EINVAL;

	}

	return 0;
}


// help
static void spdk_server_app_usage(void) {

	printf("-H host_addr \n");
	printf("-P host_port \n");
	printf("-N sock_impl \n");

}

static void spdk_server_callback(void *arg, struct spdk_sock_group *group, struct spdk_sock *sock) {

	struct server_context_t *ctx = arg;
	char buf[BUFFER_SIZE];
	struct iovec iov;
	
	ssize_t n =  spdk_sock_recv(sock, buf, sizeof(buf));
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			SPDK_ERRLOG("spdk_sock_recv failed, errno %d: %s",
				errno, spdk_strerror(errno));
			return ;
		}
		
		SPDK_ERRLOG("spdk_sock_recv failed, errno %d: %s",
				errno, spdk_strerror(errno));
	} else if (n == 0) {

		SPDK_NOTICELOG("Connection closed\n");
		spdk_sock_group_remove_sock(group, sock);
		spdk_sock_close(&sock);

		return ;

	} else { 

		ctx->bytes_in += n;

		iov.iov_base = buf;
		iov.iov_len = n;

		int n = spdk_sock_writev(sock, &iov, 1);
		if (n > 0) {
			ctx->bytes_out += n;
		}
		return ;
	}  

	// assert(0);
	
	return ;
}


// 
static int spdk_server_accept(void *arg) {

	struct server_context_t *ctx = arg;
	char saddr[ADDR_STR_LEN], caddr[ADDR_STR_LEN];
	uint16_t sport, cport;
	int count = 0;

	printf("spdk_server_accept\n");
	if (!g_running) {
		//...
	} 

	while (1) {
		// accept
		struct spdk_sock *client_sock = spdk_sock_accept(ctx->sock);
		if (client_sock == NULL)	{
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				
			}
			break;
		}

		//getpeeraddr();
		int rc = spdk_sock_getaddr(client_sock, saddr, sizeof(saddr), &sport, 
				caddr, sizeof(caddr), &cport);
		if (rc < 0) {

			SPDK_ERRLOG("Cannot get connection address\n");
			spdk_sock_close(&ctx->sock);
			return SPDK_POLLER_IDLE;

		}

		rc = spdk_sock_group_add_sock(ctx->group, client_sock, 
			spdk_server_callback, ctx);
		if (rc < 0) {

			SPDK_ERRLOG("Cannot get connection address\n");
			spdk_sock_close(&client_sock);
			return SPDK_POLLER_IDLE;

		}

		count ++;

	}

	return count > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}


static int spdk_server_group_poll(void *arg) {

	struct server_context_t *ctx = arg;

	int rc = spdk_sock_group_poll(ctx->group);
	if (rc < 0) {
		SPDK_ERRLOG("Failed to poll sock_group = %p\n", ctx->group);
	}
	return rc > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}


// spdk sock 
static int spdk_server_listen(struct server_context_t *ctx) {

	ctx->sock = spdk_sock_listen(ctx->host, ctx->port, ctx->sock_impl_name);
	if (ctx->sock == NULL) {
		SPDK_ERRLOG("Cannot create server socket");
		return -1;
	}

	ctx->group = spdk_sock_group_create(NULL); //epoll

	g_running = true;

	SPDK_POLLER_REGISTER(spdk_server_accept, ctx, 2000 * 1000);
	SPDK_POLLER_REGISTER(spdk_server_group_poll, ctx, 0);

	printf("spdk_server_listen\n");

	return 0;
}


static void sdpk_server_start(void *arg) {

	struct server_context_t *ctx = arg;
	
	printf("sdpk_server_start\n");
	int rc = spdk_server_listen(ctx);
	if (rc) {
		spdk_app_stop(-1);
	}

	return ;
}


// rte_eal_init();
// ./sdpk_server -H 0.0.0.0 -P 8888 , -N 

// epoll, 
// reactor

// context --> 
// ntyco

int main(int argc, char *argv[]) {

	struct spdk_app_opts opts = {};

	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "spdk_server";
	opts.shutdown_cb = spdk_server_shutdown_callback;

	printf("spdk_app_parse_args\n");
	spdk_app_parse_args(argc, argv, &opts, "H:P:N:SVzZ", NULL,
		spdk_server_app_parse, spdk_server_app_usage);

	printf("spdk_app_parse_args 11\n");
	struct server_context_t server_context = {};
	server_context.host = g_host;
	server_context.port = g_port;
	server_context.sock_impl_name = g_sock_impl_name;

	printf("host: %s, port: %d, impl_name: %s\n", g_host, g_port, g_sock_impl_name);
	//sdpk_server_start(&server_context);

	int rc = spdk_app_start(&opts, sdpk_server_start, &server_context); // ?
	if (rc) {
		SPDK_ERRLOG("Error starting application\n");
	}

	spdk_app_fini();

}


