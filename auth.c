#include <string.h>
#include <re.h>
#include "http.h"
#include "request.h"

struct realm {
	char *realm;
	char *nonce;
	char *qop;
	char *opaque;
	char *user;
	char *pass;
	uint32_t nc;
	enum sip_hdrid hdr;
};

static void realm_destructor(void *arg)
{
	struct realm *realm = arg;

	mem_deref(realm->realm);
	mem_deref(realm->nonce);
	mem_deref(realm->qop);
	mem_deref(realm->opaque);
	mem_deref(realm->user);
	mem_deref(realm->pass);
}

static int mkdigest(uint8_t *digest, const struct realm *realm,
		    const char *met, const char *uri, uint64_t cnonce)
{
	uint8_t ha1[MD5_SIZE], ha2[MD5_SIZE];
	int err;

	err = md5_printf(ha1, "%s:%s:%s",
			 realm->user, realm->realm, realm->pass);
	if (err)
		return err;

	err = md5_printf(ha2, "%s:%s", met, uri);
	if (err)
		return err;

	if (realm->qop)
		return md5_printf(digest, "%w:%s:%08x:%016llx:auth:%w",
				  ha1, sizeof(ha1),
				  realm->nonce,
				  realm->nc,
				  cnonce,
				  ha2, sizeof(ha2));
	else
		return md5_printf(digest, "%w:%s:%w",
				  ha1, sizeof(ha1),
				  realm->nonce,
				  ha2, sizeof(ha2));
}

void write_auth(struct request *req, struct mbuf *mb)
{
    int err;
    struct realm *realm;
    uint8_t digest[MD5_SIZE];
    uint64_t cnonce;

    if(!req->auth)
        return;

    realm = req->auth;
    cnonce = rand_u64();

    err = mkdigest(digest, realm, req->meth, req->path, cnonce);

    err |= mbuf_write_str(mb, "Authorization: ");

    err |= mbuf_printf(mb, "Digest username=\"%s\"", realm->user);
    err |= mbuf_printf(mb, ", realm=\"%s\"", realm->realm);
    err |= mbuf_printf(mb, ", nonce=\"%s\"", realm->nonce);
    err |= mbuf_printf(mb, ", uri=\"%s\"", req->path);
    err |= mbuf_printf(mb, ", response=\"%w\"",
            digest, sizeof(digest));

    if (realm->opaque)
        err |= mbuf_printf(mb, ", opaque=\"%s\"", realm->opaque);

    if (realm->qop) {
        err |= mbuf_printf(mb, ", cnonce=\"%016llx\"", cnonce);
	err |= mbuf_write_str(mb, ", qop=auth");
    	err |= mbuf_printf(mb, ", nc=%08x", realm->nc);
    }
    ++realm->nc;
    err |= mbuf_write_str(mb, "\r\n");
}

int http_auth(struct request *old, struct request **new, char* user, char*password)
{
    int ok;
    struct request *req;
    struct httpauth_digest_chall ch;
    struct realm* realm;

    re_printf("auth %r\n", &old->www_auth);
    if(old->retry)
	return -EACCES;

    ok = httpauth_digest_challenge_decode(&ch, &old->www_auth);
    if(ok!=0)
        return ok;

    if (pl_isset(&ch.algorithm) && pl_strcasecmp(&ch.algorithm, "md5")) {
	ok  = ENOSYS;
	goto out;
    }

    realm = mem_zalloc(sizeof(*realm), realm_destructor);
    ok = pl_strdup(&realm->realm, &ch.realm);
    str_dup(&realm->user, user);
    str_dup(&realm->pass, password);

    ok = pl_strdup(&realm->nonce, &ch.nonce);

    http_clone(&req, old);
    req->auth = realm;
    req->retry = old->retry +1;
    re_printf("resend after auth %d\n", req->retry);
    http_send(req);

    *new = req;
    return 0;
out:
    return ok;
}

