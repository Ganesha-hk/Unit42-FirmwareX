/* SPDX-License-Identifier: MIT. Controlled benign emulation fixture. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/mount.h>
int main(int argc,char **argv) {
 if(argc==1) { puts("FirmwareX controlled fixture"); return 0; }
 if(!strcmp(argv[1],"spin")) { for(;;){} }
 if(!strcmp(argv[1],"sleep")) { sleep(120); return 0; }
 if(!strcmp(argv[1],"memory")) { for(;;) { void *p=malloc(1024*1024); if(!p)return 3; memset(p,1,1024*1024); } }
 if(!strcmp(argv[1],"containment")) {
  int fd=socket(AF_INET,SOCK_DGRAM,0); struct sockaddr_in dst={0};
  dst.sin_family=AF_INET; dst.sin_port=htons(45678); inet_pton(AF_INET,"192.0.2.1",&dst.sin_addr);
  if(sendto(fd,"controlled",10,0,(void*)&dst,sizeof(dst))!=-1 || errno!=ENETUNREACH)return 10;close(fd);
  fd=socket(AF_INET6,SOCK_DGRAM,0);struct sockaddr_in6 dst6={0};dst6.sin6_family=AF_INET6;dst6.sin6_port=htons(45678);inet_pton(AF_INET6,"2001:db8::1",&dst6.sin6_addr);
  if(sendto(fd,"controlled",10,0,(void*)&dst6,sizeof(dst6))!=-1 || errno!=ENETUNREACH)return 11;close(fd);
  fd=socket(AF_INET,SOCK_STREAM,0);inet_pton(AF_INET,"172.17.0.1",&dst.sin_addr);
  if(connect(fd,(void*)&dst,sizeof(dst))!=-1 || errno!=ENETUNREACH)return 12;close(fd);
  if(getuid()==0 || access("/var/run/docker.sock",F_OK)==0 || access("/dev/kvm",F_OK)==0)return 13;
  if(mount("none","/tmp","tmpfs",0,0)!=-1 || errno!=EPERM)return 14;
  puts("containment checks passed");return 0;
 }
 int udp=!strcmp(argv[1],"upnp"), fd=socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0), one=1;
 setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
 struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_port=htons(18080);addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(fd,(void*)&addr,sizeof(addr)))return 2;
 char buf[4096];
 if(udp){ struct sockaddr_in peer; socklen_t len=sizeof(peer); if(recvfrom(fd,buf,sizeof(buf),0,(void*)&peer,&len)>0)sendto(fd,"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n",strlen("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n"),0,(void*)&peer,len); }
 else { listen(fd,1); int c=accept(fd,0,0); if(read(c,buf,sizeof(buf))>0) { if(!strcmp(argv[1],"http"))write(c,"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK",strlen("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"));else { unsigned char ack[]={0x20,2,0,0};write(c,ack,4); } } close(c); }
 close(fd);return 0;
}
