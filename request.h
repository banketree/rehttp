#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

struct http_hdr {
    struct le he;
    struct pl name;
    struct pl val;
    enum http_hdr_id id;
};

typedef enum {
    START,
    RESOLVED,
    ESTAB,
    SENT,
    END
} req_state;

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
    int retry;
    struct mbuf* post;
    int form;

    int status;
    size_t clen;
    struct pl www_auth;
    struct mbuf *body;
    struct mbuf *response;
    struct hash *hdrht;
    struct realm *auth;

    struct list addrl;
    struct list srvl;
    struct list cachel;
    err_h *err_h;
    done_h *done_h;
    void *arg;
};

#endif
