#include <string.h>
#include <re.h>

#ifndef REHTTP_H
#define REHTTP_H

struct request;

struct httpc {
    struct dnsc *dnsc;
    struct tls *tls;
};

enum http_hdr_id {
    HTTP_SERVER=0x3CD,
    HTTP_DATE=0x403,
    HTTP_CONTENT_TYPE=0x329,
    HTTP_CONTENT_LENGTH=0xF15,
    HTTP_WWW_AUTH=0xACB,
    HTTP_CONNECTION=0x361,
};

typedef void (err_h)(int err, void *arg);
typedef void (done_h)(struct request* req, int code, void *arg);

void http_init(struct httpc *app, struct request **rpp, char *str_uri);
void http_send(struct request *request);
void http_post(struct request *request, char* key, char* val);
void http_header(struct request *request, char* hname, char* val);
int http_auth(struct request *request, char* login, char*password);
void http_cb(struct request* request, void *arg, done_h *dh, err_h *eh);
int http_clone(struct request **rp, struct request *req);

struct pl * http_data(struct request *req);

#endif
