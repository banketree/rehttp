#include <string.h>
#include <re.h>
#include "http.h"
#include "request.h"

#define HDR_HASH_SIZE 32

#define DEBUG_MODULE "http"
#define DEBUG_LEVEL 5
#include <re_dbg.h>

int addr_lookup(struct request *request, char *name);
void http_send(struct request *request);
void write_auth(struct request *req, struct mbuf *mb);

static void dummy_err(int err, void *arg) {
    re_printf("http err %d\n", err);
}

static void http_done(struct request *req, int code, void *arg) {
    re_printf("done %d body %r\n", code, &req->body);
}

void hdr_destruct(void *arg) {
    struct http_hdr *hdr = arg;
    hash_unlink(&hdr->he);

}

void hdr_destruct2(void *arg) {
    struct http_hdr *hdr = arg;
    hash_unlink(&hdr->he);

    mem_deref((void*)hdr->name.p);
    mem_deref((void*)hdr->val.p);
}

void hdr_add(struct request *req, enum http_hdr_id id, struct pl *name, struct pl *val)
{
    struct http_hdr *hdr;
    switch(id) {
    case HTTP_CONTENT_LENGTH:
        req->clen = pl_u32(val);
        break;
    case HTTP_WWW_AUTH:
        req->www_auth.l = val->l;
        req->www_auth.p = val->p;
        break;
    default:
        ;;
    }

    hdr = mem_zalloc(sizeof(struct http_hdr), hdr_destruct);
    hdr->name.l = name->l;
    hdr->name.p = name->p;
    hdr->val.l = val->l;
    hdr->val.p = val->p;

    hash_append(req->hdrht, id, &hdr->he, hdr);
}

int parse_headers(struct request *req, char *start, size_t len, struct pl *body)
{
    int br=0;
    size_t *ct;
    enum http_hdr_id id;
    char *p = start;
    struct pl header, hval;
    header.p = start;
    header.l = 0;

    hval.p = NULL;
    hval.l = -2;

    ct = &header.l;

    while(len) {
	switch(*p) {
	case '\n':
	case '\r':
	    br++;
	    break;
	case ':':
	    if(ct == &header.l) {
	        ct = &hval.l;
	        hval.p = p+2;
	    }
        default:
	    br = 0;
	}
	if(br) {
	    if(header.l) {
	        id = (enum http_hdr_id)hash_joaat_ci(header.p, header.l) & 0xFFF;
                hdr_add(req, id, &header, &hval);
	    }

	    header.p = p+1;
	    header.l = -1;
	    hval.l = -2;
	    ct = &header.l;

	    hval.p = NULL;
	}
	p++;
	(*ct)++;
	len--;

	if(br>3) {
	    body->p = p;
	    body->l = len;
	}
    }

    return 0;
}

bool hdr_write(struct le *le, void *arg)
{
    struct http_hdr *hdr = le->data;
    struct mbuf *mb = arg;

    mbuf_printf(mb, "%r: %r\r\n", &hdr->name, &hdr->val);

    return false;
}

static void tcp_estab_handler(void *arg)
{
    DEBUG_INFO("connection established\n");
    int ok;
    struct request * request = arg;
    struct mbuf *mb;

    char CN[256];

    if(request->secure) {
	ok = tls_verify_cert(request->ssl, CN, sizeof(CN));
	if(ok!=0)
            goto fail;

	DEBUG_INFO("https CN %s\n", CN);

	ok = strcmp(request->host, CN);
	if(ok!=0)
	    goto fail;
    }

    mb = mbuf_alloc(1024);
    mbuf_printf(mb, "%s %s HTTP/1.1\r\n", request->meth, request->path);
    mbuf_printf(mb, "Host: %s\r\n", request->host);
    write_auth(request, mb);
    mbuf_write_str(mb, "Connection: close\r\n");

    hash_apply(request->hdrht, hdr_write, mb);
    hash_flush(request->hdrht);

    if(request->post) {
        request->post->pos = 0;
        mbuf_printf(mb, "Content-Length: %d\r\n",
            mbuf_get_left(request->post));

	if(request->form)
            mbuf_printf(mb, "Content-Type: "
	        "application/x-www-form-urlencoded\r\n");
        mbuf_printf(mb, "\r\n");
        mbuf_write_mem(mb, mbuf_buf(request->post),
			   mbuf_get_left(request->post));
    } else {
        mbuf_write_str(mb, "\r\n");
    }

    mb->pos = 0;

    tcp_send(request->tcp, mb);
    mem_deref(mb);

    return;

fail:
    DEBUG_WARNING("ssl fail %p %d\n", request->app->tls, ok);
}

static void tcp_recv_handler(struct mbuf *mb, void *arg)
{
    struct request *request = arg;
    int ok;

    struct pl ver;
    struct pl code;
    struct pl phrase;
    struct pl headers;
    struct pl body;

    DEBUG_INFO("recv data[%d]\n", mbuf_get_left(mb));

    if(request->state == STREAM) {
        request->stream_h(request, HTTP_STREAM_DATA, mb, request->arg);
        return;
    }

    if(request->body) {
        ok = mbuf_write_mem(request->body, mbuf_buf(mb), mbuf_get_left(mb));

        goto clen;
    }

    ok = re_regex((const char*)mbuf_buf(mb), mbuf_get_left(mb),
	"HTTP/[^ \t\r\n]+ [0-9]+ [^\t\r\n]+\r\n[^]1",
	&ver, &code, &phrase, &headers);

    // XXX: check ok
    // XXX: check headers.l

    request->status = pl_u32(&code);
    headers.l = mbuf_get_left(mb) - (headers.p - (const char*)mbuf_buf(mb));
    body.l = 0;
    parse_headers(request, (char*)headers.p, headers.l, &body);
    if(body.l) {
        request->body = mbuf_alloc(body.l);
        mbuf_write_mem(request->body, (const unsigned char*)body.p, body.l);
    }

    request->response = mem_ref(mb);

clen:
    if(request->body && request->clen > request->body->end)
	    return;

    if(request->status >= 200 || request->stream_h == NULL) {
        request->done_h(request, request->status, request->arg);
        request->state = END;
        mem_deref(request);
        return;
    }

    request->state = STREAM;
    request->stream_h(request, HTTP_STREAM_EST, mb, request->arg);
}

static void tcp_close_handler(int err, void *arg)
{
    struct request *request = arg;
    if(err!=0) {
        request->err_h(err, request->arg);
        goto out;
    }
    switch(request->state) {
    case END:
        break;
    case STREAM:
        request->stream_h(request, HTTP_STREAM_CLOSE, NULL, request->arg);
        break;
    default:
	    err = (request->status == 200) ? -ECONNRESET : request->status;
            request->err_h(err, request->arg);
    }

out:
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
    hash_flush(request->hdrht);
    mem_deref(request->hdrht);
    mem_deref(request->response);
    if(request->auth)
	request->auth = mem_deref(request->auth);

    if(request->body)
        request->body = mem_deref(request->body);

    if(request->post)
	request->post = mem_deref(request->post);

    list_flush(&request->cachel);
    list_flush(&request->addrl);
    list_flush(&request->srvl);

    DEBUG_INFO("dealloc connection\n");
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
	if(!rr)
            return -ENOENT;

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

	DEBUG_INFO("dns ok %d dst %j\n", ok, &req->dest);
	if(ok)
	    goto fail;

	req->state = RESOLVED;
	http_send(req);
	return;
fail:
        DEBUG_WARNING("cant resolve %s\n", req->host);
        req->err_h(-ENOTCONN, req->arg);
        mem_deref(req);
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
    int ret;
    ret = addr_lookup(request, request->host);
    if(ret == 0)
        return;

    request->err_h(ret, request->arg);
    mem_deref(request);
}


void http_send(struct request *request)
{
    int ok;

    if(request->state == START) {
        ok = sa_decode(&request->dest, request->host, strlen(request->host));
        if(ok == 0) {
            request->state = RESOLVED;
        } else {
            http_resolve(request);
            return;
        }
    }
    tcp_connect(&request->tcp, &request->dest, 
		    tcp_estab_handler,
		    tcp_recv_handler,
		    tcp_close_handler,
		    request);

    if(request->secure) {
        ok = tls_start_tcp(&request->ssl, request->app->tls, request->tcp, 0);
	DEBUG_INFO("start ssl %d\n", ok);
    }
}

void http_post(struct request *request, char* key, char* val)
{
    struct mbuf* mb;
    char *cur;
    int sz;

    memcpy(&request->meth, "POST", 5);
    if(request->post) {
        mb = request->post;
        mbuf_printf(mb, "&");
    } else {
	    mb = mbuf_alloc(1024);
    }

    if(key) {
        mbuf_printf(mb, "%s=", key);

        sz = 0;
        cur = val;
        while(*val) {
            switch(*val) {
            case '+':
            case '&':
                mbuf_write_mem(mb, (const uint8_t *)cur, sz);
                sz = 0;
                mbuf_printf(mb, "%%%02X", *val);
                val ++;
                cur = val;
                break;
            default:
                sz++;
                val++;
            }
        }
        if(cur != val) {
            mbuf_write_mem(mb, (const uint8_t *)cur, sz);
        }

	    request->form = 1;

    } else {
	    mbuf_printf(mb, "%s", val);
    }

    request->post = mb;
}

void http_header(struct request *request, char* hname, char* val)
{
    enum http_hdr_id id;
    struct http_hdr *hdr;
    char *tmp;

    hdr = mem_zalloc(sizeof(struct http_hdr), hdr_destruct2);
    re_sdprintf(&tmp, "%s", hname);
    pl_set_str(&hdr->name, tmp);

    re_sdprintf(&tmp, "%s", val);
    pl_set_str(&hdr->val, tmp);

    id = (enum http_hdr_id)hash_joaat_ci(hdr->name.p, hdr->name.l);
    id &= 0xFFF;

    hash_append(request->hdrht, id, &hdr->he, hdr);
}

struct hdr_fetch {
    char *name;
    char **val;
};

bool hdr_fetch(struct le *le, void *arg)
{
    int err = 0;
    struct http_hdr *hdr = le->data;
    struct hdr_fetch *op = arg;

    if(pl_strcasecmp(&hdr->name, op->name) == 0) {
        err = pl_strdup(op->val, &hdr->val);
        return true;
    }

    return false;
}

int http_response_header(struct request *req, char *name, char **rp)
{
    int err = 0;

    *rp = NULL;
    struct hdr_fetch op;
    op.name = name;
    op.val = rp;

    hash_apply(req->hdrht, hdr_fetch, &op);

    return err;
}

int http_clone(struct request **rp, struct request *req)
{
    struct request *request;
    int ok;

    request = mem_zalloc(sizeof(*request), destructor);
    if(!request)
        return -ENOMEM;

    ok = hash_alloc(&request->hdrht, HDR_HASH_SIZE);
    if(ok!=0)
        goto fail;

    request->err_h = req->err_h;
    request->done_h = req->done_h;
    request->arg = req->arg;

    if(req->post)
        request->post = mem_ref(req->post);
    else
	request->post = NULL;

    request->form = req->form;
    request->host = mem_ref(req->host);
    request->path = mem_ref(req->path);
    request->secure = req->secure;
    request->port = req->port;
    memcpy(&request->meth, &req->meth, 5);
    sa_cpy(&request->dest, &req->dest);
    request->www_auth.p = NULL;
    request->www_auth.l = 0;
    request->auth = NULL;

    // skip network resolution
    request->state = RESOLVED;
    request->app = req->app;

    *rp = request;
    return 0;
fail:
    return ok;

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

    if(ok!=0)
        goto err_uri;

    request = mem_zalloc(sizeof(*request), destructor);
    ok = hash_alloc(&request->hdrht, HDR_HASH_SIZE);
    request->err_h = dummy_err;
    request->done_h = http_done;
    request->post = NULL;
    request->form = 0;
    request->www_auth.p = NULL;
    request->www_auth.l = 0;
    request->auth = NULL;

    request->retry = 0;

    pl_strdup(&request->host, &url.host);
    pl_strdup(&request->path, &url.path);
    request->secure = !pl_strcmp(&url.scheme, "https");
    memcpy(&request->meth, "GET", 4);
    request->meth[4] = 0;

    if(url.port)
	request->port = url.port;
    else
        request->port = request->secure ? 443 : 80;

    DEBUG_INFO("secure: %d port %d\n", request->secure, request->port);
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
void http_cb(struct request* request, void *arg, done_h *dh, err_h *eh)
{
    request->arg = arg;
    if(dh)
        request->done_h = dh;

    if(eh)
        request->err_h = eh;
}

void http_stream(struct request* request, void *arg, stream_h *srh)
{
    request->arg = arg;
    if(srh)
        request->stream_h = srh;
}

int http_stream_send(struct request* request, struct mbuf*mb)
{
    if(request->state == STREAM)
        return tcp_send(request->tcp, mb);

    return -EINVAL;
}

struct mbuf * http_data(struct request *req)
{
    req->body->pos = 0;
    return req->body;
}
