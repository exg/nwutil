#include <stdlib.h>
#include <errno.h>
#include "nwutil.h"

struct nwutil_http_proxy_settings {
    bool use_proxy;
    char *proxy_host;
    unsigned proxy_port;
    char *proxy_user;
    char *proxy_password;
};

static nwutil_http_proxy_settings_t *no_http_proxy()
{
    nwutil_http_proxy_settings_t *settings = malloc(sizeof *settings);
    settings->use_proxy = false;
    settings->proxy_host = NULL;
    settings->proxy_port = 0;
    settings->proxy_user = settings->proxy_password = NULL;
    return settings;
}

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

static char *dict_look_up_string(CFDictionaryRef dict, CFStringRef key)
{
    CFStringRef cf_s;
    if (!CFDictionaryGetValueIfPresent(dict, key, (CFTypeRef *) &cf_s))
        return NULL;
    CFIndex length = CFStringGetLength(cf_s);
    CFIndex size =
        CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    char *s = malloc(size);
    if (!CFStringGetCString(cf_s, s, size, kCFStringEncodingUTF8)) {
        free(s);
        return NULL;
    }
    return s;
}

nwutil_http_proxy_settings_t *parse_proxy(CFDictionaryRef proxy)
{
    CFStringRef proxyType;
    if (!CFDictionaryGetValueIfPresent(proxy, kCFProxyTypeKey,
                                       (CFTypeRef *) &proxyType))
        return NULL;
    if (proxyType != kCFProxyTypeHTTP &&
        proxyType != kCFProxyTypeHTTPS)
        return NULL;

    CFNumberRef cf_port;
    unsigned port;
    if (!CFDictionaryGetValueIfPresent(proxy, kCFProxyPortNumberKey,
                                       (CFTypeRef *) &cf_port) ||
        !CFNumberGetValue(cf_port, kCFNumberIntType, &port))
        return NULL;

    char *host = dict_look_up_string(proxy, kCFProxyHostNameKey);
    if (!host)
        return NULL;

    nwutil_http_proxy_settings_t *settings = malloc(sizeof *settings);
    settings->use_proxy = true;
    settings->proxy_host = host;
    settings->proxy_port = port;
    settings->proxy_user = dict_look_up_string(proxy, kCFProxyUsernameKey);
    settings->proxy_password = dict_look_up_string(proxy, kCFProxyPasswordKey);
    return settings;
}

nwutil_http_proxy_settings_t *http_proxy_settings(const char *url)
{
    CFDictionaryRef proxySettings;
    CFArrayRef proxies;
    CFURLRef cf_url;
    CFIndex i;
    nwutil_http_proxy_settings_t *settings = NULL;
    cf_url = CFURLCreateWithBytes(NULL, (const UInt8 *)url, strlen(url),
                                  kCFStringEncodingUTF8, NULL);
    proxySettings = CFNetworkCopySystemProxySettings();
    proxies = CFNetworkCopyProxiesForURL(cf_url, proxySettings);
    CFRelease(cf_url);
    CFRelease(proxySettings);
    for (i = 0; !settings && i < CFArrayGetCount(proxies); i++)
        settings = parse_proxy(CFArrayGetValueAtIndex(proxies, i));
    CFRelease(proxies);
    if (!settings)
        return no_http_proxy();
    return settings;
}
#endif

nwutil_http_proxy_settings_t *
nwutil_get_global_http_proxy_settings_1(const char *uri)
{
#ifdef __APPLE__
    return http_proxy_settings(uri);
#else
    return no_http_proxy();
#endif
}

bool nwutil_use_http_proxy(nwutil_http_proxy_settings_t *settings)
{
    return settings->use_proxy;
}

const char *nwutil_http_proxy_host(nwutil_http_proxy_settings_t *settings)
{
    return settings->proxy_host;
}

unsigned nwutil_http_proxy_port(nwutil_http_proxy_settings_t *settings)
{
    return settings->proxy_port;
}

const char *nwutil_http_proxy_user(nwutil_http_proxy_settings_t *settings)
{
    return settings->proxy_user;
}

const char *nwutil_http_proxy_password(nwutil_http_proxy_settings_t *settings)
{
    return settings->proxy_password;
}

void nwutil_release_http_proxy_settings(nwutil_http_proxy_settings_t *settings)
{
    free(settings->proxy_host);
    free(settings->proxy_user);
    free(settings->proxy_password);
    free(settings);
}

