#include <string.h>
#include <re.h>

#ifndef REHTTP_H
#define REHTTP_H

struct request;

struct httpc {
    struct dnsc *dnsc;
    struct tls *tls;
};

void http_init(struct httpc *app, struct request **rpp, char *str_uri);
void http_send(struct request *request);

#endif
