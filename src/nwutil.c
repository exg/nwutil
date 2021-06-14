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

static void pac_result_callback(void *client,
                                CFArrayRef proxies,
                                CFErrorRef error)
{
    if (error == NULL)
        *((CFArrayRef *) client) = CFRetain(proxies);
}

static CFArrayRef resolve_pac(CFDictionaryRef proxy,
                              CFURLRef url,
                              CFTimeInterval seconds,
                              bool *timed_out)
{
    CFURLRef script_url;
    if (!CFDictionaryGetValueIfPresent(proxy,
                                       kCFProxyAutoConfigurationURLKey,
                                       (CFTypeRef *) &script_url))
        return NULL;

    CFArrayRef proxies = NULL;
    CFStreamClientContext context = {
        .version = 0,
        .info = &proxies,
        .retain = NULL,
        .release = NULL,
        .copyDescription = NULL,
    };
    CFRunLoopSourceRef source =
        CFNetworkExecuteProxyAutoConfigurationURL(script_url,
                                                  url,
                                                  pac_result_callback,
                                                  &context);
    if (!source)
        return NULL;

    CFStringRef mode = CFSTR("nwutil");
    CFRunLoopAddSource(CFRunLoopGetCurrent(), source, mode);
    CFRunLoopRunResult result = CFRunLoopRunInMode(mode, seconds, true);
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(), source, mode);
    CFRelease(source);
    switch (result) {
        case kCFRunLoopRunTimedOut:
            *timed_out = true;
            return NULL;
        default:
            return proxies;
    }
}

static nwutil_http_proxy_settings_t *find_proxy(CFArrayRef proxies,
                                                CFURLRef url,
                                                double pac_timeout,
                                                bool *timed_out)
{
    *timed_out = false;
    nwutil_http_proxy_settings_t *settings = NULL;
    for (CFIndex i = 0; !settings && i < CFArrayGetCount(proxies); i++) {
        CFDictionaryRef proxy = CFArrayGetValueAtIndex(proxies, i);
        CFStringRef type;
        if (CFDictionaryGetValueIfPresent(proxy,
                                          kCFProxyTypeKey,
                                          (CFTypeRef *) &type)) {
            if (CFEqual(type, kCFProxyTypeHTTP) ||
                CFEqual(type, kCFProxyTypeHTTPS))
                settings = parse_proxy(proxy);
            else if (CFEqual(type, kCFProxyTypeNone))
                settings = no_http_proxy();
            else if (CFEqual(type, kCFProxyTypeAutoConfigurationURL)) {
                if (pac_timeout > 0) {
                    CFArrayRef pac_proxies =
                        resolve_pac(proxy, url, pac_timeout, timed_out);
                    if (pac_proxies) {
                        settings = find_proxy(pac_proxies, url, 0, timed_out);
                        CFRelease(pac_proxies);
                    } else if (*timed_out) {
                        return NULL;
                    }
                }
            }
        }
    }
    return settings;
}

nwutil_http_proxy_settings_t *nwutil_get_global_http_proxy_settings_2(
    const char *url,
    double pac_timeout)
{
    CFDictionaryRef proxySettings;
    CFArrayRef proxies;
    CFURLRef cf_url;
    nwutil_http_proxy_settings_t *settings = NULL;
    cf_url = CFURLCreateWithBytes(NULL, (const UInt8 *)url, strlen(url),
                                  kCFStringEncodingUTF8, NULL);
    proxySettings = CFNetworkCopySystemProxySettings();
    proxies = CFNetworkCopyProxiesForURL(cf_url, proxySettings);
    bool timed_out;
    settings = find_proxy(proxies, cf_url, pac_timeout, &timed_out);
    CFRelease(cf_url);
    CFRelease(proxySettings);
    CFRelease(proxies);
    if (settings)
        return settings;
    if (timed_out) {
        errno = ETIMEDOUT;
        return NULL;
    }
    return no_http_proxy();
}
#else
nwutil_http_proxy_settings_t *nwutil_get_global_http_proxy_settings_2(
    const char *uri,
    double pac_timeout)
{
    return no_http_proxy();
}
#endif

nwutil_http_proxy_settings_t *nwutil_get_global_http_proxy_settings_1(
    const char *uri)
{
    return nwutil_get_global_http_proxy_settings_2(uri, 0);
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

