#ifndef LOG_MSG_H
#define LOG_MSG_H

void log_msg(int daemon_mode, const char *format, ...);

int daemon_mode;		// Boolean when no terminal available

#endif
