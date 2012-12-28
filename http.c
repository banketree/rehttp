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
    mbuf_write_str(mb, "GET / HTTP/1.1\r\n");
    mbuf_write_str(mb, "Host: enodev.org\r\n");
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
    re_printf("dealloc connection\n");
}

void request()
{
    struct sa dest;
    struct request *request;

    request = mem_zalloc(sizeof(*request), destructor);
    sa_decode(&dest, "46.182.27.206:80", 17);

    tcp_connect(&request->tcp, &dest, 
		    tcp_estab_handler,
		    tcp_recv_handler,
		    tcp_close_handler,
		    request);

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
    request();
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

