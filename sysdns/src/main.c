#include "dns.h"
#include "dns_cache.h"
#include "dns_encode.h"
#include "dns_parse.h"
#include "dns_resolver.h"
#include "dns_socket.h"
#include "hexdump.h"
#include "recursive.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYSDNS_NAME "sysDNS"
#define SYSDNS_VERSION "1.0.0"
#define CLI_PARSED_QUERY 2
#define DNS_ROOT_HINT "198.41.0.4"

static const char *const k_record_types[] = {
    "A", "AAAA", "CNAME", "MX", "NS", "TXT",
};

struct cli_config {
    const char *domain;
    const char *record_type;
    const char *server;
    int timeout_ms;
    int retries;
    int debug;
    int no_cache;
    int recursive;
};

static void print_help(void)
{
    puts("sysDNS - DNS resolver written in C");
    puts("");
    puts("Usage:");
    puts("  sysdns <domain> [record-type] [options]");
    puts("  sysdns --help");
    puts("  sysdns --version");
    puts("");
    puts("Arguments:");
    puts("  domain        Domain name to look up (e.g. google.com)");
    puts("  record-type   DNS record type (default: A)");
    puts("                Supported: A, AAAA, CNAME, MX, NS, TXT");
    puts("");
    puts("Options:");
    puts("  --server <ip>     DNS server IPv4 (default: 8.8.8.8)");
    puts("  --timeout <ms>    Per-attempt receive timeout (default: 3000)");
    puts("  --retries <n>     Number of attempts (default: 3)");
    puts("  --no-cache        Do not read or write the in-memory cache");
    puts("  --recursive       Resolve from a root server instead of forwarding");
    puts("  --debug           Print header, sections, and raw packets");
    puts("  --help            Show this help");
    puts("  --version         Show version");
    puts("");
    puts("The cache lives only inside this process. A second command cannot");
    puts("see a hit from the first.");
}

static void print_version(void)
{
    puts(SYSDNS_NAME " " SYSDNS_VERSION);
}

static void print_usage_hint(void)
{
    fputs("Try 'sysdns --help' for more information.\n", stderr);
}

static bool str_iequal(const char *a, const char *b)
{
    unsigned char ca;
    unsigned char cb;

    do {
        ca = (unsigned char)*a++;
        cb = (unsigned char)*b++;
        if (toupper(ca) != toupper(cb)) {
            return false;
        }
    } while (ca != '\0');

    return true;
}

static const char *canonical_record_type(const char *input)
{
    size_t i;

    for (i = 0; i < sizeof(k_record_types) / sizeof(k_record_types[0]); i++) {
        if (str_iequal(input, k_record_types[i])) {
            return k_record_types[i];
        }
    }
    return NULL;
}

static int parse_positive_int(const char *s, int *out, long max_v)
{
    char *end = NULL;
    long v;

    if (s == NULL || out == NULL) {
        return -1;
    }
    v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v <= 0L || v > max_v) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int parse_args(int argc, char **argv, struct cli_config *out)
{
    const char *domain = NULL;
    const char *type_arg = NULL;
    int i;

    out->domain = NULL;
    out->record_type = NULL;
    out->server = NULL;
    out->timeout_ms = DNS_DEFAULT_TIMEOUT_MS;
    out->retries = 3;
    out->debug = 0;
    out->no_cache = 0;
    out->recursive = 0;

    if (argc < 2) {
        fputs("error: missing domain name\n", stderr);
        print_usage_hint();
        return EXIT_FAILURE;
    }

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0) {
            print_help();
            return EXIT_SUCCESS;
        }
        if (strcmp(arg, "--version") == 0) {
            print_version();
            return EXIT_SUCCESS;
        }
        if (strcmp(arg, "--debug") == 0) {
            out->debug = 1;
            continue;
        }
        if (strcmp(arg, "--no-cache") == 0) {
            out->no_cache = 1;
            continue;
        }
        if (strcmp(arg, "--recursive") == 0) {
            out->recursive = 1;
            continue;
        }
        if (strcmp(arg, "--server") == 0) {
            if (i + 1 >= argc) {
                fputs("error: --server requires an IPv4 address\n", stderr);
                return EXIT_FAILURE;
            }
            out->server = argv[++i];
            continue;
        }
        if (strcmp(arg, "--timeout") == 0) {
            if (i + 1 >= argc ||
                parse_positive_int(argv[++i], &out->timeout_ms, 600000L) != 0) {
                fputs("error: invalid --timeout value\n", stderr);
                return EXIT_FAILURE;
            }
            continue;
        }
        if (strcmp(arg, "--retries") == 0) {
            if (i + 1 >= argc ||
                parse_positive_int(argv[++i], &out->retries, 8L) != 0) {
                fputs("error: invalid --retries value\n", stderr);
                return EXIT_FAILURE;
            }
            continue;
        }
        if (arg[0] == '-') {
            fprintf(stderr, "error: unknown option '%s'\n", arg);
            print_usage_hint();
            return EXIT_FAILURE;
        }
        if (domain == NULL) {
            domain = arg;
        } else if (type_arg == NULL) {
            type_arg = arg;
        } else {
            fprintf(stderr, "error: unexpected argument '%s'\n", arg);
            print_usage_hint();
            return EXIT_FAILURE;
        }
    }

    if (domain == NULL) {
        fputs("error: missing domain name\n", stderr);
        print_usage_hint();
        return EXIT_FAILURE;
    }
    if (type_arg == NULL) {
        type_arg = "A";
    }
    out->record_type = canonical_record_type(type_arg);
    if (out->record_type == NULL) {
        fprintf(stderr,
                "error: unsupported record type '%s'\n"
                "supported types: A, AAAA, CNAME, MX, NS, TXT\n",
                type_arg);
        return EXIT_FAILURE;
    }
    if (out->server == NULL) {
        out->server = out->recursive ? DNS_ROOT_HINT : DNS_DEFAULT_SERVER;
    }
    out->domain = domain;
    return CLI_PARSED_QUERY;
}

static void print_banner(const struct cli_config *cfg)
{
    puts(SYSDNS_NAME);
    puts("--------------------------------");
    printf("Query: %s\n", cfg->domain);
    printf("Type: %s\n", cfg->record_type);
    printf("Server: %s\n", cfg->server);
    printf("Mode: %s\n", cfg->recursive ? "recursive" : "iterative");
    puts("--------------------------------");
}

static int run_query(const struct cli_config *cfg)
{
    struct dns_cache cache;
    struct dns_endpoint server;
    struct dns_result *result;
    struct dns_rr cached[DNS_CACHE_RR];
    uint8_t tmp[DNS_NAME_WIRE_MAX];
    size_t name_off = 0;
    uint16_t qtype;
    int ncache = 0;
    int rc;
    int en = dns_encode_name(cfg->domain, tmp, &name_off, sizeof(tmp));

    if (en < 0) {
        fprintf(stderr, "error: cannot encode domain: %s\n",
                dns_encode_strerror(en));
        return EXIT_FAILURE;
    }

    qtype = dns_qtype_from_str(cfg->record_type);
    dns_cache_init(&cache);
    print_banner(cfg);

    if (!cfg->no_cache &&
        dns_cache_lookup(&cache, cfg->domain, qtype, dns_now_ms(), cached,
                         DNS_CACHE_RR, &ncache)) {
        puts("");
        puts("ANSWER");
        puts("");
        {
            int i;
            for (i = 0; i < ncache; i++) {
                fputs("    ", stdout);
                dns_rr_print(&cached[i]);
            }
        }
        puts("");
        puts("--------------------------------");
        puts("Query time: 0 ms");
        puts("Cache: HIT");
        puts("--------------------------------");
        return EXIT_SUCCESS;
    }

    if (dns_endpoint_set_ipv4(&server, cfg->server, DNS_DEFAULT_PORT) !=
        DNS_SOCK_OK) {
        fprintf(stderr, "error: invalid --server IPv4 '%s'\n", cfg->server);
        return EXIT_FAILURE;
    }

    result = (struct dns_result *)malloc(sizeof(*result));
    if (result == NULL) {
        fputs("error: out of memory\n", stderr);
        return EXIT_FAILURE;
    }

    if (cfg->recursive) {
        rc = dns_recursive_lookup(cfg->server, cfg->domain, qtype,
                                  cfg->timeout_ms, cfg->retries, cfg->debug,
                                  !cfg->no_cache, &cache, result);
    } else {
        rc = dns_forward_lookup(&server, cfg->domain, qtype, cfg->timeout_ms,
                                cfg->retries, cfg->debug, result);
    }
    if (rc != 0) {
        const char *why = dns_socket_strerror(rc);
        if (rc == DNS_MSG_ERR_FORM || rc == DNS_MSG_ERR_QR ||
            rc == DNS_MSG_ERR_SHORT || rc == DNS_MSG_ERR_ID) {
            why = dns_msg_strerror(rc);
        }
        fprintf(stderr, "error: lookup failed: %s\n", why);
        free(result);
        return EXIT_FAILURE;
    }

    if (cfg->debug && result->response_len > 0u) {
        puts("RAW PACKET");
        hexdump_print(stdout, result->response, result->response_len);
        dns_message_print(&result->msg, 1);
    }

    if (result->rcode != 0u) {
        fprintf(stderr, "error: %s\n", dns_rcode_name(result->rcode));
        free(result);
        return EXIT_FAILURE;
    }

    puts("");
    puts("ANSWER");
    puts("");
    if (result->nanswer == 0) {
        puts("    (no records)");
    } else {
        int i;
        for (i = 0; i < result->nanswer; i++) {
            fputs("    ", stdout);
            dns_rr_print(&result->answer[i]);
        }
        if (!cfg->no_cache) {
            dns_cache_store(&cache, cfg->domain, qtype, result->answer,
                            result->nanswer,
                            dns_rr_min_ttl(result->answer, result->nanswer),
                            dns_now_ms());
        }
    }

    puts("");
    puts("--------------------------------");
    printf("Query time: %d ms\n", result->elapsed_ms);
    printf("Cache: %s\n", cfg->no_cache ? "OFF" : "MISS");
    puts("--------------------------------");
    free(result);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    struct cli_config cfg;
    int rc = parse_args(argc, argv, &cfg);

    if (rc != CLI_PARSED_QUERY) {
        return rc;
    }
    return run_query(&cfg);
}
