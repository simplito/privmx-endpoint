/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/
#include <dlfcn.h>

int privmx_endpoint_android_init() {
    return 1;
}

void* privmx_endpoint_android_dlopen(const char *file, int flags) {
    return dlopen(file, flags);
}

int privmx_endpoint_android_dlclose(void* handle) {
    return dlclose(handle);
}

char* privmx_endpoint_android_dlerror() {
    return dlerror();
}

void* privmx_endpoint_android_dlsym(void* handle, const char* symbol) {
    return dlsym(handle, symbol);
}
