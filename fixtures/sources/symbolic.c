/* SPDX-License-Identifier: MIT. Controlled diagnostic fixture; never run natively. */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#ifndef SOURCE
#define SOURCE 0
#endif
#ifndef SINK
#define SINK 0
#endif
#ifndef REGION
#define REGION 0
#endif
char global_destination[8];
int main(void) {
 char input[32]; char stack_destination[8]; char safe_destination[64];
 char *src=input;
#if SOURCE == 0
 read(0,input,31);input[31]=0;
#elif SOURCE == 1
 recv(0,input,31,0);input[31]=0;
#elif SOURCE == 2
 src=getenv("QUERY_STRING");
#else
 src=getenv("FWX_TEST_ENV");
#endif
#ifdef CHAIN
 char staging[32];memcpy(staging,src,32);src=staging;
#endif
#ifdef NEGATIVE
 src="ABCD";
#endif
#ifdef UNREACHABLE
 if(src[0]=='A' && src[0]=='B') {
#else
 if(src[0]=='A') {
#endif
#if REGION == 0
 char *dst=global_destination;
#elif REGION == 1
 char *dst=stack_destination;
#elif REGION == 2
 char *dst=malloc(8);
#else
 char *dst=safe_destination;
#endif
#if SINK == 0
 strcpy(dst,src);
#elif SINK == 1
 memcpy(dst,src,31);
#elif SINK == 2
 sprintf(dst,"%s",src);
#elif SINK == 3
 system(src);
#elif SINK == 4
 popen(src,"r");
#else
 sprintf(dst,src);
#endif
 }
 return 0;
}
