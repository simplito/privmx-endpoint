#ifndef _PRIVMX_ENDPOINT_ANDROID_INTERFACE_API_
#define _PRIVMX_ENDPOINT_ANDROID_INTERFACE_API_

#ifdef __cplusplus
extern "C" {
#endif

int privmx_endpoint_android_init();
void* privmx_endpoint_android_dlopen(const char *path, int flags);
int privmx_endpoint_android_dlclose(void* handle);
char* privmx_endpoint_android_dlerror(void);
void* privmx_endpoint_android_dlsym(void* handle, const char* symbol);

#ifdef __cplusplus
}
#endif

#endif // _PRIVMX_ENDPOINT_ANDROID_INTERFACE_API_
