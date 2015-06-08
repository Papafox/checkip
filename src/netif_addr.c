#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "netif_addr.h"
#include "log_msg.h"

static void die(const char* fmt, ...) {
    va_list vl;

    va_start(vl, fmt);
    log_msg(daemon_mode, fmt, vl);
    va_end(vl);
    exit(-1);
}

const char* netif_addr(const char* if_name) {
    // Create an ifreq structure used  calling ioctl
    struct ifreq ifr;
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name)) {
       memcpy(ifr.ifr_name,if_name,if_name_len);
       ifr.ifr_name[if_name_len]=0;
    } else {
       die("interface name is too long");
    }

    // Create an open AF_INET socket
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        die("%s",strerror(errno));
    }

    // Invoke ioctl
    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
       int temp_errno=errno;
       close(fd);
       die("%s",strerror(temp_errno));
    }
    close(fd);

    // Extract the IP address from the ifreq structure
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    return inet_ntoa(ipaddr->sin_addr);
}
