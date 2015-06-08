#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int daemon_mode = 1;

static void log_msg(int daemon_mode, const char *format, ...)
{
    va_list vl;

    va_start(vl, format);
    if(daemon_mode)
       vsyslog(LOG_INFO, format, vl);
    else
       vprintf(format, vl);
    va_end(vl);
}

static void banIP(const char* ipaddr) {
    log_msg(daemon_mode, "IP address %s banned", ipaddr);
    int process_id = fork();
    if (process_id < 0) {
        log_msg(daemon_mode, "iptables fork() failed! - exiting");
    }
    if (process_id != 0)
        return;
    int rc = execl("/sbin/iptables", "iptables", "-I", "INPUT", "-s", ipaddr, "-j", "DROP", (char *)0);
    if (rc != 0)
       log_msg(daemon_mode, "iptables exec() failed (ip = %s rc = %d, errno = %d err = '%s')", ipaddr, rc, errno, strerror(rc));
    exit(0);
}

int main(int argc, char** argv) {
    char* ipaddr = "10.10.10.10";

    banIP(ipaddr);
    exit(0);
}
