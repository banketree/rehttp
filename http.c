#include <string.h>
#include <re.h>
#include "http.h"

typedef enum {
    START,
    RESOLVED,
    ESTAB,
    SENT,
    END
} req_state;

typedef void (err_h)(int err, void *arg);

struct request {
    struct httpc *app;
    struct tcp_conn *tcp;
    struct tls_conn *ssl;
    struct dns_query *dnsq;

    char *host;
    char meth[5];
    char *path;
    struct sa dest;
    req_state state;
    int secure;
    int port;

    struct list addrl;
    struct list srvl;
    struct list cachel;
    err_h *err_h;
};

int addr_lookup(struct request *request, char *name);
void http_send(struct request *request);

int parse_headers(char *start, int len, const char **body){
    int hlen = 0, hvlen = -1, *ct;
    int br=0;
    char *p = start;
    char *header = start;
    char *header_val = NULL;
    ct = &hlen;
    while(len) {
	switch(*p) {
	case '\n':
	case '\r':
		br++;
		break;
	case ':':
		ct = &hvlen;
	default:
		br = 0;
	}
	if(br) {
	    if(hlen>4) {
                re_printf("h %b\n", header, hlen);
		re_printf("v %b\n", header+hlen+2, hvlen);
	    }
	    header = p+1;
	    hlen = -1;
	    hvlen = -1;
	    ct = &hlen;

	    header_val = NULL;
	}
	p++;
	(*ct)++;
	len--;

	if(br>3)
	    *body = p;
    }

    return 0;
}

static void tcp_estab_handler(void *arg)
{
    re_printf("estab!\n");
    int ok;
    struct request * request = arg;
    struct mbuf *mb;

    char CN[256];

    if(request->secure) {
	ok = tls_verify_cert(request->ssl, CN, sizeof(CN));
	if(ok!=0)
            goto fail;

	ok = strcmp(request->host, CN);
	if(ok!=0)
	    goto fail;
    }

    mb = mbuf_alloc(1024);
    mbuf_printf(mb, "%s %s HTTP/1.1\r\n", request->meth, request->path);
    mbuf_printf(mb, "Host: %s\r\n", request->host);
    mbuf_write_str(mb, "Connection: close\r\n");
    mbuf_write_str(mb, "\r\n\r\n");

    mb->pos = 0;

    tcp_send(request->tcp, mb);
    mem_deref(mb);

    return;

fail:
    re_printf("ssl fail\n");
}

static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
    struct request *request = arg;
    int ok, tmp;

    struct pl ver;
    struct pl code;
    struct pl phrase;
    struct pl headers;
    struct pl body;

    re_printf("recv data\n");

    ok = re_regex((const char*)mbuf_buf(mb), mbuf_get_left(mb),
	"HTTP/[^ \t\r\n]+ [0-9]+ [^ \t\r\n]+\r\n[^]1",
	&ver, &code, &phrase, &headers);
    // XXX: check ok
    // XXX: check headers.l
    headers.l = mbuf_get_left(mb) - (headers.p - (const char*)mbuf_buf(mb));
    parse_headers((char*)headers.p, headers.l, &body.p);
    tmp = body.p - headers.p;
    body.l = headers.l - tmp;
    headers.l = tmp-2;
    re_printf("decode %d\n", ok);
    re_printf("body %r\n", &body);
    re_printf("headers: %r\n", &headers);

}

static void tcp_close_handler(int err, void *arg)
{
    struct request *request = arg;
    if(err!=0) {
	if(request->err_h)
            request->err_h(err, NULL);
	else
            re_printf("http(tcp) failed with err %d\n", err);
    }
    mem_deref(request);
}

static void destructor(void *arg)
{

    struct request * request = arg;
    mem_deref(request->tcp);
    if(request->ssl)
	mem_deref(request->ssl);
    mem_deref(request->host);
    mem_deref(request->path);

    list_flush(&request->cachel);
    list_flush(&request->addrl);
    list_flush(&request->srvl);

    re_printf("dealloc connection\n");
}

static bool rr_append_handler(struct dnsrr *rr, void *arg)
{
	struct list *lst = arg;

	switch (rr->type) {

	case DNS_TYPE_A:
	case DNS_TYPE_AAAA:
	case DNS_TYPE_SRV:
		if (rr->le.list)
			break;

		list_append(lst, &rr->le, mem_ref(rr));
		break;
	}

	return false;
}

static int request_next(struct request *req, struct sa* dst)
{
	struct dnsrr *rr;
	int err = 0;

	rr = list_ledata(req->addrl.head);

	switch (rr->type) {

	case DNS_TYPE_A:
		sa_set_in(dst, rr->rdata.a.addr, req->port);
		break;

	case DNS_TYPE_AAAA:
		sa_set_in6(dst, rr->rdata.aaaa.addr, req->port);
		break;

	default:
		return EINVAL;
	}

	list_unlink(&rr->le);
	mem_deref(rr);

	return err;
}


static void addr_handler(int err, const struct dnshdr *hdr, struct list *ansl,
			 struct list *authl, struct list *addl, void *arg)
{
	struct request *req = arg;
	int ok;
	(void)hdr;
	(void)authl;
	(void)addl;

	dns_rrlist_apply2(ansl, NULL, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_CLASS_IN,
			  false, rr_append_handler, &req->addrl);


	ok = request_next(req, &req->dest);
	mem_deref(req->dnsq);

	re_printf("dns ok %d dst %j\n", ok, &req->dest);
	if(ok)
	    goto fail;

	req->state = RESOLVED;
	http_send(req);
	return;
fail:
        re_printf("cant resolve %s\n", req->host);
}



int addr_lookup(struct request *request, char *name)
{
    int ok;
    ok = dnsc_query(&request->dnsq, request->app->dnsc,
		    name,
		    DNS_TYPE_A, DNS_CLASS_IN, true,
		    addr_handler, request);

    return ok;

}

void http_resolve(struct request *request)
{
    addr_lookup(request, request->host);
}


void http_send(struct request *request)
{
    int ok;

    if(request->state == START) {
        http_resolve(request);
        return;
    }
    tcp_connect(&request->tcp, &request->dest, 
		    tcp_estab_handler,
		    tcp_recv_handler,
		    tcp_close_handler,
		    request);

    if(request->secure) {
        ok = tls_start_tcp(&request->ssl, request->app->tls, request->tcp, 0);
	re_printf("start ssl %d\n", ok);
    }
}

struct url {
    struct pl scheme;
    struct pl host;
    struct pl path;
    int port;
};

int url_decode(struct url* url, struct pl *pl)
{
    int ok;
    ok = re_regex(pl->p, pl->l,
        "[^:]+://[^/]+[^]*", &url->scheme,
	&url->host, &url->path);
    url->port = 0;
    return 0;
}

void http_init(struct httpc *app, struct request **rpp, char *str_uri)
{
    int ok;
    struct request *request;
    struct pl pl_uri;
    struct url url;

    *rpp = NULL;

    pl_uri.p = NULL;
    str_dup((char**)&pl_uri.p, str_uri);
    pl_uri.l = strlen(str_uri);

    ok = url_decode(&url, &pl_uri);
    re_printf("decode %d uri %r\n", ok, &pl_uri);

    if(ok!=0)
        goto err_uri;

    request = mem_zalloc(sizeof(*request), destructor);

    pl_strdup(&request->host, &url.host);
    pl_strdup(&request->path, &url.path);
    request->secure = !pl_strcmp(&url.scheme, "https");
    memcpy(&request->meth, "GET", 4);
    request->meth[4] = 0;

    if(url.port)
	request->port = url.port;
    else
        request->port = request->secure ? 443 : 80;

    re_printf("secure: %d port %d\n", request->secure, request->port);
    sa_init(&request->dest, AF_INET);
    ok = sa_set_str(&request->dest, request->host, request->port);

    request->state = ok ? START : RESOLVED;

    request->app = app;
    *rpp = request;

err_uri:
    if(pl_uri.p)
        mem_deref((void*)pl_uri.p);

    return;
}
