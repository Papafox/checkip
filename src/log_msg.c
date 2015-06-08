#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>

#include "log_msg.h"

void log_msg(int daemon_mode, const char *format, ...)
{
    va_list vl;

    va_start(vl, format);
    if(daemon_mode)
       vsyslog(LOG_INFO, format, vl);
    else {
       vprintf(format, vl);
       printf("\n");
    }
    va_end(vl);
}

