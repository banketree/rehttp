#include <string.h>
#include <re.h>
#include "http.h"

static void signal_handler(int sig)
{
    re_printf("terminating on signal %d...\n", sig);
    re_cancel();
}

int main(int argc, char *argv[])
{
    int err;
    struct httpc app;

    err = libre_init();

    char k[] = "user.cert";

    err = tls_alloc(&app.tls, TLS_METHOD_SSLV23, k, NULL);
    tls_add_ca(app.tls, "ca.cert");

    re_printf("enter loop\n");

    struct sa nsv[16];
    uint32_t nsc = ARRAY_SIZE(nsv);

    err = dns_srv_get(NULL, 0, nsv, &nsc);

    err = dnsc_alloc(&app.dnsc, NULL, nsv, nsc);

    struct request *request;
    http_init(&app, &request, "https://texr.enodev.org/api/contacts");
    http_send(request);

    err = re_main(signal_handler);

    goto out;

fail:
    re_printf("failed\n");
out:
    re_printf("exit\n");

    mem_deref(app.dnsc);
    mem_deref(app.tls);

    libre_close();

    /* check for memory leaks */
    tmr_debug();
    mem_debug();


}

