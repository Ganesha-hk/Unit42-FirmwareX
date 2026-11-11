/* SPDX-License-Identifier: MIT. Read-only, synthetic defaults for controlled probes.
 * Link into a controlled service when its nvram_get ABI matches this shim.
 * Never read host configuration or invent vendor peripheral behavior. */
#include <string.h>
#include <errno.h>
const char *nvram_get(const char *key) {
 if (!strcmp(key,"lan_ipaddr")) return "127.0.0.1";
 if (!strcmp(key,"lan_ifname")) return "lo";
 return 0;
}
int nvram_set(const char *key,const char *value) { (void)key;(void)value;errno=EROFS;return -1; }
