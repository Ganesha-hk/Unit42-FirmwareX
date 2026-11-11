/* SPDX-License-Identifier: MIT. Controlled symbolic branching/loop/fault probe. */
#include <unistd.h>
volatile int result;
int main(void) {
#ifdef FAULT
 *(volatile int *)0=1;
#else
 unsigned char data[8];read(0,data,7);
#ifdef LOOP
 while(data[0]=='A')result++;
#else
 int x;
 if(data[0]=='A')x=1;else x=2;
 result=x;
 if(data[1]=='B')result+=4;else result+=8;
 if(data[2]=='C')result+=16;else result+=32;
#endif
#endif
 return 0;
}
