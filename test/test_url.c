#include <encjson.h>
#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>
#include <nwutil.h>

#include <string.h>

struct test {
    bool failure;
    const char *url;
    size_t url_len;
    const char *base;
    const char *scheme;
    const char *username;
    const char *password;
    const char *host;
    const char *path;
    const char *query;
    const char *fragment;
    int port;
};

static struct test *decode_test(json_thing_t *thing)
{
    json_thing_t *input = json_object_get(thing, "input");
    if (!input || json_thing_type(input) != JSON_STRING)
        return NULL;
    const char *base;
    if (!json_object_get_string(thing, "base", &base))
        return NULL;
    struct test *test = fscalloc(1, sizeof *test);
    test->url = json_string_value(input);
    test->url_len = json_string_length(input);
    test->base = base;
    test->failure = false;
    if (json_object_get_boolean(thing, "failure", &test->failure))
        return test;

    const char *port;
    if (!json_object_get_string(thing, "protocol", &test->scheme) ||
        !json_object_get_string(thing, "username", &test->username) ||
        !json_object_get_string(thing, "password", &test->password) ||
        !json_object_get_string(thing, "hostname", &test->host) ||
        !json_object_get_string(thing, "port", &port) ||
        !json_object_get_string(thing, "pathname", &test->path) ||
        !json_object_get_string(thing, "search", &test->query) ||
        !json_object_get_string(thing, "hash", &test->fragment)) {
        fsfree(test);
        return NULL;
    }
    if (port[0])
        test->port = strtol(port, NULL, 10);
    else
        test->port = -1;
    if (*test->query == '?')
        test->query++;
    if (*test->fragment == '#')
        test->fragment++;
    return test;
}

static void destroy_test(struct test *test)
{
    fsfree(test);
}

static bool cmp(nwutil_url_t *url, struct test *test)
{
    if (!url)
        return test->failure;

    if (test->failure)
        return false;

    const char *scheme = nwutil_url_get_scheme(url);
    const char *username = nwutil_url_get_username(url);
    const char *password = nwutil_url_get_password(url);
    const char *host = nwutil_url_get_host(url);
    const char *path = nwutil_url_get_path(url);
    const char *query = nwutil_url_get_query(url);
    const char *fragment = nwutil_url_get_fragment(url);
    unsigned port;
    if (!nwutil_url_get_port(url, &port))
        port = -1;

    if (!username)
        username = "";

    if (!password)
        password = "";

    if (!host)
        host = "";

    if (!query)
        query = "";

    if (!fragment)
        fragment = "";

    const char *ptr = charstr_skip_prefix(test->scheme, scheme);
    if (!ptr || ptr[0] != ':' || ptr[1])
        return false;
    if (strcmp(username, test->username))
        return false;
    if (strcmp(password, test->password))
        return false;
    if (strcmp(host, test->host))
        return false;
    if (strcmp(path, test->path))
        return false;
    if (strcmp(query, test->query))
        return false;
    if (strcmp(fragment, test->fragment))
        return false;
    if (test->port != port)
        return false;
    return true;
}

static json_thing_t *encode_url(nwutil_url_t *url)
{
    const char *scheme = nwutil_url_get_scheme(url);
    const char *username = nwutil_url_get_username(url);
    const char *password = nwutil_url_get_password(url);
    const char *host = nwutil_url_get_host(url);
    const char *path = nwutil_url_get_path(url);
    const char *query = nwutil_url_get_query(url);
    const char *fragment = nwutil_url_get_fragment(url);
    unsigned port;
    bool has_port = nwutil_url_get_port(url, &port);

    json_thing_t *thing = json_make_object();
    json_add_to_object(thing, "scheme", json_make_string(scheme));
    json_add_to_object(thing, "username", json_make_string(username));
    json_add_to_object(thing, "password", json_make_string(password));
    if (host)
        json_add_to_object(thing, "host", json_make_string(host));
    json_add_to_object(thing, "path", json_make_string(path));
    if (query)
        json_add_to_object(thing, "query", json_make_string(query));
    if (fragment)
        json_add_to_object(thing, "fragment", json_make_string(fragment));
    if (has_port)
        json_add_to_object(thing, "port", json_make_unsigned(port));
    return thing;
}

static bool run_test(struct test *test, json_thing_t *report)
{
    nwutil_url_t *base_url =
        nwutil_parse_url(test->base, strlen(test->base), NULL);
    if (!base_url)
        return false;
    nwutil_url_t *url = nwutil_parse_url(test->url, test->url_len, base_url);
    bool success = cmp(url, test);
    if (!success) {
        json_add_to_object(report, "base", encode_url(base_url));
        if (url)
            json_add_to_object(report, "url", encode_url(url));
    }
    nwutil_url_destroy(base_url);
    if (url)
        nwutil_url_destroy(url);
    return success;
}

static json_thing_t *run_tests(json_thing_t *thing)
{
    json_thing_t *failed = json_make_array();
    const char *section = "";
    for (json_element_t *el = json_array_first(thing); el;
         el = json_element_next(el)) {
        json_thing_t *value = json_element_value(el);
        if (json_thing_type(value) == JSON_STRING)
            section = json_string_value(value);
        else if (json_thing_type(value) == JSON_OBJECT) {
            struct test *test = decode_test(value);
            if (test) {
                json_thing_t *report = json_make_object();
                if (run_test(test, report))
                    json_destroy_thing(report);
                else {
                    json_add_to_object(report, "test", json_clone(value));
                    json_add_to_object(report,
                                       "section",
                                       json_make_string(section));
                    json_add_to_array(failed, report);
                }
                destroy_test(test);
            }
        }
    }
    return failed;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argv[1], "r");
    if (!f)
        return 1;
    json_thing_t *thing = json_utf8_decode_file(f, -1);
    fclose(f);
    if (!thing)
        return 1;
    int status = 1;
    if (json_thing_type(thing) == JSON_ARRAY) {
        json_thing_t *failed = run_tests(thing);
        if (!json_array_first(failed))
            status = 0;
        else
            json_utf8_dump(failed, stdout);
        json_destroy_thing(failed);
    }
    json_destroy_thing(thing);
    return status;
}
