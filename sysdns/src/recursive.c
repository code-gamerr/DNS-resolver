#include "recursive.h"

#include "dns_name.h"
#include "dns_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REC_DEPTH 8
#define REC_HOPS 16

struct rec_ctx {
    struct dns_cache *cache;
    int use_cache;
    char root[16];
    int timeout_ms;
    int attempts;
    int debug;
    int depth;
    char stack[REC_DEPTH][DNS_NAME_CAP];
    int nstack;
    struct dns_result *out;
};

static const char *const k_roots[] = {
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
};

static int on_stack(const struct rec_ctx *ctx, const char *name)
{
    int i;

    for (i = 0; i < ctx->nstack; i++) {
        if (dns_name_eq(ctx->stack[i], name)) {
            return 1;
        }
    }
    return 0;
}

static void copy_answers(struct dns_rr *dst, int *ndst, int cap,
                         const struct dns_rr *src, int nsrc)
{
    int i;

    for (i = 0; i < nsrc && *ndst < cap; i++) {
        dst[(*ndst)++] = src[i];
    }
}

static int count_type(const struct dns_message *msg, uint16_t type)
{
    int i;
    int n = 0;

    for (i = 0; i < msg->nanswer; i++) {
        if (msg->answer[i].type == type) {
            n++;
        }
    }
    return n;
}

static int take_type(const struct dns_message *msg, uint16_t type,
                     struct dns_rr *dst, int cap)
{
    int i;
    int n = 0;

    for (i = 0; i < msg->nanswer && n < cap; i++) {
        if (msg->answer[i].type == type) {
            dst[n++] = msg->answer[i];
        }
    }
    return n;
}

static int glue_ip(const struct dns_message *msg, const char *host, char *ip,
                   size_t cap)
{
    int i;

    for (i = 0; i < msg->nadditional; i++) {
        const struct dns_rr *rr = &msg->additional[i];
        if (rr->kind == DNS_RDATA_A && dns_name_eq(rr->owner, host)) {
            return dns_rr_rdata_text(rr, ip, cap);
        }
    }
    return -1;
}

static int pick_ns(const struct dns_message *msg, const char *qname,
                   char hosts[][DNS_NAME_CAP], int cap)
{
    char best[DNS_NAME_CAP];
    int best_len = -1;
    int i;
    int n = 0;

    best[0] = '\0';
    for (i = 0; i < msg->nauthority; i++) {
        const struct dns_rr *rr = &msg->authority[i];
        int len;
        if (rr->type != DNS_QTYPE_NS || rr->kind != DNS_RDATA_NAME) {
            continue;
        }
        if (!dns_name_suffix(qname, rr->owner)) {
            continue;
        }
        len = (int)strlen(rr->owner);
        if (len > best_len) {
            best_len = len;
            strncpy(best, rr->owner, sizeof(best) - 1u);
            best[sizeof(best) - 1u] = '\0';
        }
    }
    if (best_len < 0) {
        return 0;
    }
    for (i = 0; i < msg->nauthority && n < cap; i++) {
        const struct dns_rr *rr = &msg->authority[i];
        if (rr->type == DNS_QTYPE_NS && dns_name_eq(rr->owner, best)) {
            strncpy(hosts[n], rr->target, DNS_NAME_CAP - 1u);
            hosts[n][DNS_NAME_CAP - 1u] = '\0';
            n++;
        }
    }
    return n;
}

static int ask(struct rec_ctx *ctx, const char *ip, const char *name,
               uint16_t qtype, struct dns_message *msg)
{
    struct dns_endpoint ep;
    int rc;

    if (dns_endpoint_set_ipv4(&ep, ip, DNS_DEFAULT_PORT) != DNS_SOCK_OK) {
        return DNS_SOCK_ERR_ADDR;
    }
    rc = dns_query_server(&ep, name, qtype, 0, ctx->timeout_ms, ctx->attempts,
                          ctx->debug, msg, ctx->out->query, &ctx->out->query_len,
                          ctx->out->response, &ctx->out->response_len);
    if (rc == DNS_MSG_OK) {
        ctx->out->msg = *msg;
        ctx->out->rcode = msg->rcode;
    }
    return rc;
}

static int walk(struct rec_ctx *ctx, const char *name, uint16_t qtype,
                struct dns_rr *acc, int cap, int *nacc);

static int host_to_ip(struct rec_ctx *ctx, const char *host, const char *glue,
                      char *ip, size_t cap)
{
    struct dns_rr got[4];
    int n = 0;

    if (glue != NULL && glue[0] != '\0') {
        strncpy(ip, glue, cap - 1u);
        ip[cap - 1u] = '\0';
        return 0;
    }
    if (walk(ctx, host, DNS_QTYPE_A, got, 4, &n) != 0 || n <= 0) {
        return -1;
    }
    if (got[0].kind != DNS_RDATA_A) {
        return -1;
    }
    return dns_rr_rdata_text(&got[0], ip, cap);
}

static int walk(struct rec_ctx *ctx, const char *name, uint16_t qtype,
                struct dns_rr *acc, int cap, int *nacc)
{
    struct dns_message *msg;
    char start_ip[16];
    int hop;
    int rc;

    if (ctx->depth >= REC_DEPTH || on_stack(ctx, name)) {
        fputs("error: resolution loop or depth limit\n", stderr);
        return -1;
    }
    if (ctx->nstack >= REC_DEPTH) {
        return -1;
    }
    strncpy(ctx->stack[ctx->nstack], name, DNS_NAME_CAP - 1u);
    ctx->stack[ctx->nstack][DNS_NAME_CAP - 1u] = '\0';
    ctx->nstack++;
    ctx->depth++;

    if (ctx->use_cache && ctx->cache != NULL) {
        struct dns_rr hit[DNS_CACHE_RR];
        int n = 0;
        if (dns_cache_lookup(ctx->cache, name, qtype, dns_now_ms(), hit,
                             DNS_CACHE_RR, &n) && n > 0) {
            copy_answers(acc, nacc, cap, hit, n);
            ctx->depth--;
            ctx->nstack--;
            return 0;
        }
    }

    msg = (struct dns_message *)malloc(sizeof(*msg));
    if (msg == NULL) {
        ctx->depth--;
        ctx->nstack--;
        return -1;
    }

    strncpy(start_ip, ctx->root, sizeof(start_ip) - 1u);
    start_ip[sizeof(start_ip) - 1u] = '\0';
    rc = -1;

    for (hop = 0; hop < REC_HOPS; hop++) {
        char hosts[4][DNS_NAME_CAP];
        char hop_ip[64];
        int nh;
        int h;
        int moved = 0;

        rc = ask(ctx, start_ip, name, qtype, msg);
        if (rc != DNS_MSG_OK && hop == 0) {
            size_t r;
            for (r = 0; r < sizeof(k_roots) / sizeof(k_roots[0]); r++) {
                if (strcmp(k_roots[r], start_ip) == 0) {
                    continue;
                }
                rc = ask(ctx, k_roots[r], name, qtype, msg);
                if (rc == DNS_MSG_OK) {
                    strncpy(start_ip, k_roots[r], sizeof(start_ip) - 1u);
                    start_ip[sizeof(start_ip) - 1u] = '\0';
                    break;
                }
            }
        }
        if (rc != DNS_MSG_OK) {
            break;
        }
        if (msg->rcode == 3u) {
            rc = DNS_MSG_OK;
            ctx->out->rcode = 3u;
            break;
        }
        if (msg->rcode != 0u) {
            ctx->out->rcode = msg->rcode;
            break;
        }
        if (count_type(msg, qtype) > 0) {
            struct dns_rr got[DNS_RR_CAP];
            int n = take_type(msg, qtype, got, DNS_RR_CAP);
            copy_answers(acc, nacc, cap, got, n);
            if (ctx->use_cache && ctx->cache != NULL) {
                dns_cache_store(ctx->cache, name, qtype, got, n,
                                dns_rr_min_ttl(got, n), dns_now_ms());
            }
            rc = DNS_MSG_OK;
            break;
        }
        if (qtype != DNS_QTYPE_CNAME && count_type(msg, DNS_QTYPE_CNAME) > 0) {
            struct dns_rr cname;
            int before = *nacc;
            cname = msg->answer[0];
            for (h = 0; h < msg->nanswer; h++) {
                if (msg->answer[h].type == DNS_QTYPE_CNAME) {
                    cname = msg->answer[h];
                    break;
                }
            }
            copy_answers(acc, nacc, cap, &cname, 1);
            rc = walk(ctx, cname.target, qtype, acc, cap, nacc);
            if (rc == 0 && ctx->use_cache && ctx->cache != NULL &&
                *nacc > before) {
                dns_cache_store(ctx->cache, name, qtype, acc + before,
                                *nacc - before, dns_rr_min_ttl(acc, *nacc),
                                dns_now_ms());
            }
            break;
        }

        nh = pick_ns(msg, name, hosts, 4);
        if (nh == 0) {
            rc = -1;
            fputs("error: no referral and no answer\n", stderr);
            break;
        }
        hop_ip[0] = '\0';
        for (h = 0; h < nh; h++) {
            char glue[64];
            glue[0] = '\0';
            if (glue_ip(msg, hosts[h], glue, sizeof(glue)) != 0) {
                glue[0] = '\0';
            }
            if (host_to_ip(ctx, hosts[h], glue, hop_ip, sizeof(hop_ip)) == 0) {
                strncpy(start_ip, hop_ip, sizeof(start_ip) - 1u);
                start_ip[sizeof(start_ip) - 1u] = '\0';
                moved = 1;
                break;
            }
        }
        if (!moved) {
            fputs("error: referral had no usable address\n", stderr);
            rc = -1;
            break;
        }
        if (ctx->debug) {
            printf("referral %s -> %s\n", name, start_ip);
        }
        rc = -1;
    }

    free(msg);
    ctx->depth--;
    ctx->nstack--;
    return rc == DNS_MSG_OK ? 0 : rc;
}

int dns_recursive_lookup(const char *root_ip, const char *name, uint16_t qtype,
                         int timeout_ms, int attempts, int debug, int use_cache,
                         struct dns_cache *cache, struct dns_result *out)
{
    struct rec_ctx ctx;
    uint64_t t0;
    int n = 0;
    int rc;

    if (root_ip == NULL || name == NULL || out == NULL) {
        return DNS_MSG_ERR_ARGS;
    }
    memset(out, 0, sizeof(*out));
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.root, root_ip, sizeof(ctx.root) - 1u);
    ctx.cache = cache;
    ctx.use_cache = use_cache;
    ctx.timeout_ms = timeout_ms;
    ctx.attempts = attempts < 1 ? 1 : attempts;
    ctx.debug = debug;
    ctx.out = out;
    strncpy(out->qname, name, sizeof(out->qname) - 1u);
    out->qtype = qtype;

    t0 = dns_now_ms();
    rc = walk(&ctx, name, qtype, out->answer, DNS_RR_CAP, &n);
    out->nanswer = n;
    out->elapsed_ms = (int)(dns_now_ms() - t0);
    if (rc != 0 && out->rcode == 3u) {
        return 0;
    }
    return rc;
}
