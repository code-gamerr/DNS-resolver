#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYSDNS_NAME "sysDNS"
#define SYSDNS_VERSION "0.1.0"

/* RFC 1035: a domain name is at most 255 octets on the wire; the
 * presentation form is typically capped at 253 characters. */
#define DNS_NAME_MAX 253

/* parse_args() returns EXIT_SUCCESS/FAILURE, or this when a query was parsed. */
#define CLI_PARSED_QUERY 2

static const char *const k_record_types[] = {
    "A", "AAAA", "CNAME", "MX", "NS", "TXT",
};

struct cli_config {
    const char *domain;
    const char *record_type; /* canonical uppercase name from k_record_types */
};

static void print_help(void)
{
    puts("sysDNS - DNS resolver written in C");
    puts("");
    puts("Usage:");
    puts("  sysdns <domain> [record-type]");
    puts("  sysdns --help");
    puts("  sysdns --version");
    puts("");
    puts("Arguments:");
    puts("  domain        Domain name to look up (e.g. google.com)");
    puts("  record-type   DNS record type (default: A)");
    puts("                Supported: A, AAAA, CNAME, MX, NS, TXT");
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

static bool domain_is_plausible(const char *domain)
{
    size_t len;

    if (domain == NULL || domain[0] == '\0') {
        return false;
    }

    len = strlen(domain);
    if (len > DNS_NAME_MAX) {
        return false;
    }

    /* Phase 1: reject obvious junk. Strict wire-format checks land in Phase 3. */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)domain[i];
        if (c <= 0x20U || c == 0x7FU) {
            return false;
        }
    }

    return true;
}

static int parse_args(int argc, char **argv, struct cli_config *out)
{
    const char *domain = NULL;
    const char *type_arg = NULL;
    int i;

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
        if (arg[0] == '-' && arg[1] == '-') {
            fprintf(stderr, "error: unknown option '%s'\n", arg);
            print_usage_hint();
            return EXIT_FAILURE;
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

    if (!domain_is_plausible(domain)) {
        fprintf(stderr, "error: invalid domain name '%s'\n", domain);
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

    out->domain = domain;
    return CLI_PARSED_QUERY;
}

static void print_query_stub(const struct cli_config *cfg)
{
    puts(SYSDNS_NAME);
    puts("--------------------------------");
    printf("Query: %s\n", cfg->domain);
    printf("Type: %s\n", cfg->record_type);
    puts("--------------------------------");
    puts("");
    puts("DNS resolution is not implemented yet (Phase 1).");
}

int main(int argc, char **argv)
{
    struct cli_config cfg = {0};
    int rc = parse_args(argc, argv, &cfg);

    if (rc != CLI_PARSED_QUERY) {
        return rc;
    }

    print_query_stub(&cfg);
    return EXIT_SUCCESS;
}
