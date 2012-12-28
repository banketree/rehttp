#include <string.h>
#include <re.h>

typedef enum {
    START,
    ESTAB,
    SENT,
    END
} req_state;

struct request {
    struct tcp_conn *tcp;
    char *host;
    char meth[5];
    char *path;
    struct sa dest;
    req_state state;
};

static void signal_handler(int sig)
{
    re_printf("terminating on signal %d...\n", sig);
    re_cancel();
}

static void tcp_estab_handler(void *arg)
{
    re_printf("estab!\n");
    struct request * request = arg;
    struct mbuf *mb;

    mb = mbuf_alloc(1024);
    mbuf_printf(mb, "%s %s HTTP/1.1\r\n", request->meth, request->path);
    mbuf_printf(mb, "Host: %s\r\n", request->host);
    mbuf_write_str(mb, "\r\n\r\n");

    mb->pos = 0;

    tcp_send(request->tcp, mb);
    mem_deref(mb);

}

static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
    struct request *request = arg;
    re_printf("recv data\n");
    re_printf("response: %b\n", mbuf_buf(mb), mbuf_get_left(mb));

    mem_deref(request);

    re_cancel();
}

static void tcp_close_handler(int err, void *arg)
{
    re_printf("close %d\n", err);
}

static void destructor(void *arg)
{

    struct request * request = arg;
    mem_deref(request->tcp);
    mem_deref(request->host);
    mem_deref(request->path);
    re_printf("dealloc connection\n");
}

void http_send(struct request *request)
{
    tcp_connect(&request->tcp, &request->dest, 
		    tcp_estab_handler,
		    tcp_recv_handler,
		    tcp_close_handler,
		    request);
}

void http_init(struct request **rpp, char *host, char *path)
{
    struct request *request;

    request = mem_zalloc(sizeof(*request), destructor);

    str_dup(&request->host, host);
    str_dup(&request->path, path);
    memcpy(&request->meth, "GET", 4);
    request->meth[4] = 0;

    sa_decode(&request->dest, "46.182.27.206:80", 16);

    *rpp = request;

}

int main(int argc, char *argv[])
{
    int err;
    struct sa laddr;
    struct tls *tlsp = NULL;

    err = libre_init();

    err = net_default_source_addr_get(AF_INET, &laddr);

    char k[] = "user.cert";

    err = tls_alloc(&tlsp, TLS_METHOD_SSLV23, k, NULL);

    re_printf("enter loop\n");

    struct request *request;
    http_init(&request, "enodev.org", "/");
    http_send(request);

    err = re_main(signal_handler);

    goto out;

fail:
    re_printf("failed\n");
out:
    re_printf("exit\n");

    mem_deref(tlsp);

    libre_close();

    /* check for memory leaks */
    tmr_debug();
    mem_debug();


}

