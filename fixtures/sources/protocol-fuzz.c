/* SPDX-License-Identifier: MIT. Controlled diagnostic crash fixture only.
 * Negative parsed lengths trigger an intentional null write, never an exploit.
 */
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
__attribute__((noinline)) void controlled_null_write(void){ *(volatile int *)0=1; }
int main(int argc,char **argv){
 if(argc!=2)return 2;
 int udp=!strcmp(argv[1],"upnp"),fd=socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0),one=1;
 setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
 struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_port=htons(18081);addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(fd,(void*)&addr,sizeof(addr)))return 3;
 unsigned char buf[512]={0};int c=fd;ssize_t n;
 if(udp)n=recvfrom(fd,buf,sizeof(buf)-1,0,0,0);
 else {listen(fd,1);c=accept(fd,0,0);n=read(c,buf,sizeof(buf)-1);}
 int crash=0;
 if(n>0){
  if(!strcmp(argv[1],"http")&&strstr((char*)buf,"Content-Length: -1"))crash=1;
  if(udp&&strstr((char*)buf,"MX: -1"))crash=1;
  if(!strcmp(argv[1],"mqtt")&&n>=6&&buf[0]==0x10&&buf[1]==0xff&&buf[2]==0xff&&buf[3]==0xff&&buf[4]==0xff&&buf[5]==1)crash=1;
 }
 if(crash)controlled_null_write();
 if(c!=fd)close(c);close(fd);return 0;
}
