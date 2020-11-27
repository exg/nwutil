#include <nwutil.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct test {
    const char *uri;
    const char *scheme;
    const char *userinfo;
    const char *host;
    const char *path;
    const char *query;
    const char *fragment;
    int port;
};

static struct test valid_uris[] = {
    {
        "http://test@127.0.0.1",
        "http",
        "test",
        "127.0.0.1",
        "",
        NULL,
        NULL,
        80,
    },
    {
        "https://localhost?x=a&y=b",
        "https",
        NULL,
        "localhost",
        "",
        "x=a&y=b",
        NULL,
        443,
    },
    {
        "http://[3ffe:2a00:100:7031::1]:8080/index.html?",
        "http",
        NULL,
        "3ffe:2a00:100:7031::1",
        "/index.html",
        "",
        NULL,
        8080,
    },
    {
        "http://[3ffe:2a00:100:7031::1%25en0]:8080/index.html?",
        "http",
        NULL,
        "3ffe:2a00:100:7031::1%25en0",
        "/index.html",
        "",
        NULL,
        8080,
    },
    {
        "http://%74est@localhos%74/index.h%74ml",
        "http",
        "%74est",
        "localhos%74",
        "/index.h%74ml",
        NULL,
        NULL,
        80,
    },
};

static const char *invalid_uris[] = {
    "http//test@127.0.0.1",
    "http://test@127.0.0.1foo/bar",
    "https://localhost?foo=bar^",
    "http://[3ffe:2a00:100:7031::1]:8080/index.html^",
    "http://[3ffe:2a00:100:7031::1:8080/index.html?",
    "http://[3ffe:2a00:100:7031::1%25]:8080/index.html?",
};

static bool cmp(nwutil_uri_t *uri, struct test *test)
{
    const char *scheme = nwutil_uri_get_scheme(uri);
    const char *userinfo = nwutil_uri_get_userinfo(uri);
    const char *host = nwutil_uri_get_host(uri);
    const char *path = nwutil_uri_get_path(uri);
    const char *query = nwutil_uri_get_query(uri);
    const char *fragment = nwutil_uri_get_fragment(uri);
    unsigned port;
    bool has_port = nwutil_uri_get_port(uri, &port);

    if (strcmp(scheme, test->scheme))
        return false;
    if (test->userinfo && strcmp(userinfo, test->userinfo))
        return false;
    if (strcmp(host, test->host))
        return false;
    if (strcmp(path, test->path))
        return false;
    if (test->query) {
        if (!query || strcmp(query, test->query))
            return false;
    } else {
        if (query)
            return false;
    }
    if (test->fragment) {
        if (!fragment || strcmp(fragment, test->fragment))
            return false;
    } else {
        if (fragment)
            return false;
    }
    if (test->port != -1) {
        if (!has_port || port != test->port)
            return false;
    } else {
        if (has_port)
            return false;
    }
    return true;
}

static void dump(nwutil_uri_t *uri)
{
    const char *scheme = nwutil_uri_get_scheme(uri);
    const char *userinfo = nwutil_uri_get_userinfo(uri);
    const char *host = nwutil_uri_get_host(uri);
    const char *path = nwutil_uri_get_path(uri);
    const char *query = nwutil_uri_get_query(uri);
    unsigned port;
    bool has_port = nwutil_uri_get_port(uri, &port);

    fprintf(stderr, "  scheme=%s\n", scheme);
    if (userinfo)
        fprintf(stderr, "  userinfo=%s\n", userinfo);
    fprintf(stderr, "  host=%s\n", host);
    fprintf(stderr, "  path=%s\n", path);
    if (query)
        fprintf(stderr, "  query=%s\n", query);
    if (has_port)
        fprintf(stderr, "  port=%u\n", port);
}

static bool test_valid(struct test *test)
{
    fprintf(stderr, "\ninput=%s valid\n", test->uri);
    nwutil_uri_t *uri = nwutil_parse_uri(test->uri);
    bool success = false;
    if (uri) {
        dump(uri);
        success = cmp(uri, test);
        nwutil_uri_destroy(uri);
    }
    return success;
}

static bool test_invalid(const char *str)
{
    fprintf(stderr, "\ninput=%s invalid\n", str);
    nwutil_uri_t *uri = nwutil_parse_uri(str);
    bool success = true;
    if (uri) {
        dump(uri);
        success = false;
        nwutil_uri_destroy(uri);
    }
    return success;
}

int main(int argc, char **argv)
{
    int i;
    for (i = 0; i < sizeof(valid_uris) / sizeof(valid_uris[0]); i++)
        if (!test_valid(&valid_uris[i]))
            return 1;
    for (i = 0; i < sizeof(invalid_uris) / sizeof(invalid_uris[0]); i++)
        if (!test_invalid(invalid_uris[i]))
            return 1;
    return 0;
}
