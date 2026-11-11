/* SPDX-License-Identifier: MIT. Controlled stub contract probe. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
extern const char *nvram_get(const char *);
extern int nvram_set(const char *,const char *);
int main(void) {
 if(strcmp(nvram_get("lan_ipaddr"),"127.0.0.1") || strcmp(nvram_get("lan_ifname"),"lo"))return 1;
 if(nvram_get("unknown") || nvram_set("lan_ifname","eth0")!=-1 || errno!=EROFS)return 2;
 puts("NVRAM stub contract passed");return 0;
}
