/*************************************************************************\
*                  Copyright (C) Matthew Donald, 2015.                    *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU Lesser General Public License as published   *
* by the Free Software Foundation, either version 3 or (at your option)   *
* any later version. This program is distributed without any warranty.    *
* See the files COPYING.lgpl-v3 and COPYING.gpl-v3 for details.           *
**************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <pcre.h>

#include "mongoose.h"
#include "pidfile.h"
#include "checkip.h"

static bool isLogable(struct mg_connection *conn) {
    uint32_t first_addr = 0x42f94001;		// 66.249.64.1
    uint32_t last_addr = 0x42f95ffe;		// 66.249.95.254

    const char* remote_ip = conn->remote_ip;
    const char* referer = getHeader(conn, "Referer");
    const char* host = getHeader(conn, "Host");
    uint32_t ip = parseIPV4string(remote_ip);
    return (host == NULL || referer != NULL || (ip >= first_addr && ip <= last_addr));
}

static void logGoogle(struct mg_connection *conn) {
    int i;
    for (i = 0; i < 30; i++) {
      if (conn->http_headers[i].name == NULL || conn->http_headers[i].value == NULL || strlen(conn->http_headers[i].name) == 0) break;
      log_msg(daemon_mode, "%s: header %s = '%s'", conn->remote_ip, conn->http_headers[i].name, conn->http_headers[i].value);
    }
 }

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

static const char* getHeader(struct mg_connection *conn, const char* name) {
    int i;
    int size = sizeof(conn->http_headers)/sizeof(conn->http_headers[0]);

    for (i = 0; i < size; i++) {
      if (conn->http_headers[i].name == NULL) break;
      if (strcasecmp(conn->http_headers[i].name, name) == 0)
        return conn->http_headers[i].value;
    }
    return (char*) NULL;
}

static int updateCnt(const char* uri, struct ValidIP* ip, int rc) {
    int count = ip->count;

    if (rc == 200) {
      if (count > 0) count--;
    } else {
      if (count > -1) {
        count += (strstr(uri, "://") == NULL) ? 2 : 10;
      }
    }
    return count;
}

static bool isValidReq(struct mg_connection *conn) {
    // Check that method is GET
    if (!strcmp(conn->request_method, "GET") == 0) return FALSE;

    // Check that it's directed to this host
    const char* host = getHeader(conn, "Host");
    if (host == NULL || strcasecmp(host, HOSTNAME) != 0) return FALSE;

    // Check that there is NO referer
    const char* referer = getHeader(conn, "Referer");
    if (referer != NULL) return FALSE;

    // Check that the URI is a URI, not a URL
    if (strstr(conn->uri, "://") != NULL) return FALSE;

    return TRUE;
}

static void checkip_req(struct mg_connection *conn) {

    // Prevent proxies and browsers from caching response, also include some security headers
    mg_send_header(conn, "Cache-Control", "max-age=0, post-check=0, pre-check=0, no-store, no-cache, must-revalidate");
    mg_send_header(conn, "Pragma", "no-cache");
    mg_send_header(conn, "Content-Type", "text/html");
    mg_send_header(conn, "X-Frame-Options", "DENY");
    mg_send_header(conn, "X-Content-Type-Options", "nosniff");
    mg_send_header(conn, "Server", "wsadmin-CheckIP/" VERSION);

    // Return the remote ipaddr
    mg_printf_data(conn, "<html><head><title>Current IP Check</title></head><body>Current IP Address: %s</body></html>", conn->remote_ip);
}

static void reject_req(struct mg_connection *conn) {

    // Prevent proxies and browsers from caching response, also include some security headers
    mg_send_header(conn, "Cache-Control", "max-age=0, post-check=0, pre-check=0, no-store, no-cache, must-revalidate");
    mg_send_header(conn, "Pragma", "no-cache");
    mg_send_header(conn, "Content-Type", "text/html");
    mg_send_header(conn, "X-Frame-Options", "DENY");
    mg_send_header(conn, "X-Content-Type-Options", "nosniff");
    mg_send_header(conn, "Server", "wsadmin-CheckIP/" VERSION);

    // Return a please go away message
    if (strstr(conn->uri, "://") == NULL)
      mg_printf_data(conn, "<html><head><title>Page not found</title></head><body><p>This page you requested '%s' does not exist</p></body></html>", conn->uri);
    else
      mg_printf_data(conn, "<html><head><title>This is not a proxy</title></head><body><p>This is not an open proxy. Your IP address %s has been banned</p></body></html>", conn->remote_ip);
}

static int ev_handler(struct mg_connection *conn, enum mg_event ev) {
  int result;
  struct ValidIP* ip;

  switch (ev) {
    case MG_AUTH: return MG_TRUE;

    case MG_REQUEST:
      // Log all headers for request if from Google
      // has a referer
      if (isLogable(conn))
        logGoogle(conn);

      // Get validIP entry.  Add new entry if necessary
      ip = findIP(conn->remote_ip);

      // validate and process
      if (isValidReq(conn)) {
        if (strcmp(conn->uri, "/") == 0) {
          checkip_req(conn);
          result = 200;
        }
//      if (strncmp(conn->uri, "/ping") == 0) {
//        ping_req(conn);
//        result = 200;
//      }
      } else {
        reject_req(conn);
        result = 404;
      }

      // update the ban count and possibly ban the ip addr
      ip->count = updateCnt(conn->uri, ip, result);

      // log the request to syslog
      log_msg(daemon_mode, "[%d] %s: %s '%s%s%s' %d count=%d",
						   conn->local_port,
						   conn->remote_ip,
						   conn->request_method,
						   conn->uri,
						   ((conn->query_string == NULL) ? "" : "?"),
						   ((conn->query_string == NULL) ? "" : conn->query_string),
						   result,
						   ip->count
      );

      // if necessary, ban the IP address
      if (ip->count >= LIMIT) {
        banIP(ip, conn->remote_ip);
      }
      return (result == 200) ? MG_TRUE : MG_FALSE;

    default:
      return MG_FALSE;
  }
}

static void initValidIP() {
    int i;
    for(i = 0; i < SIZE; i++) {
      struct ValidIP* curr = &knownIP[i];
      curr->ipAddr = 0xffffffff;
      curr->count = -1;
    }
    knownCnt = 0;
}

static struct ValidIP* findIP(const char* remote_ip) {
    int i;
    uint32_t ipaddr = parseIPV4string(remote_ip);

    // Search for an existing entry
    for(i = 0; i < SIZE; i++) {
      struct ValidIP* curr = &knownIP[i];
      if (curr->ipAddr == ipaddr && curr->count != -1)
         return curr;
    }

    // Add a new entry (first unused)
    for(i = 0; i < SIZE; i++) {
      struct ValidIP* curr = &knownIP[i];
      if (curr->ipAddr == 0xffffffff) {
         curr->ipAddr = ipaddr;
         curr->count = 0;
         knownCnt++;
         log_msg(daemon_mode, "IP addr %s added to validIP table (count = %d)", remote_ip, knownCnt);
         return curr;
      }
    }

    return (struct ValidIP*)NULL;
}

static uint32_t parseIPV4string(const char* ipAddress) {
    const char* regexStr = "(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)";
    const char* error;
    int   errOffset;
    int   match[30];

    int buf[4];
    const char* matchStr;

    pcre* regex = pcre_compile(regexStr, 0, &error, &errOffset, NULL);
    if (regex == NULL) {
      log_msg(daemon_mode, "regex compile failed (%s) - exiting", error);
      exit(-1);
    }

    pcre_extra* regexOpt = pcre_study(regex, 0, &error);
    if (regexOpt == NULL) {
      log_msg(daemon_mode, "regex optimise failed (%s) - exiting", error);
      exit(-1);
    }

    int ret = pcre_exec(regex, regexOpt, ipAddress, strlen(ipAddress), 0, 0, match, sizeof(match)/sizeof(match[0]));
    if(ret < 0) { 	// Something bad happened..
      switch(ret) {
        case PCRE_ERROR_NOMATCH      : error = "String did not match the pattern";        break;
        case PCRE_ERROR_NULL         : error = "Something was null";                      break;
        case PCRE_ERROR_BADOPTION    : error = "A bad option was passed";                 break;
        case PCRE_ERROR_BADMAGIC     : error = "Magic number bad (compiled re corrupt?)"; break;
        case PCRE_ERROR_UNKNOWN_NODE : error = "Something kooky in the compiled RE";      break;
        case PCRE_ERROR_NOMEMORY     : error = "Ran out of memory";                       break;
        default                      : error = "Unknown error";                           break;
      }
      log_msg(daemon_mode, "regex exec error %d (%s) - exiting", ret, error);
      exit(-1);
    }

    if (ret != 5) {	// Wrong num of matches
      if (ret == 0) ret = sizeof(match)/sizeof(match[0]);
      log_msg(daemon_mode, "regex matched %d instead of 4 strings - exiting", ret);
      exit(-1);
    }

    int i;
    for (i = 0; i < 4; i++) {
      pcre_get_substring(ipAddress, match, ret, i+1, &(matchStr));
      buf[i] = atoi(matchStr);
    }

    return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

static void banIP(struct ValidIP* ip, const char* ipaddr) {
    char buf[100];

    ip->count = -1;
    ip->ipAddr = 0xffffffff;
    knownCnt--;

    sprintf(buf, "/sbin/iptables -I INPUT -s %s -j DROP", ipaddr);
    int rc = system(buf);
    log_msg(daemon_mode, "IP address %s banned - '%s' (rc = %d, errno = %d)", ipaddr, buf, rc, errno);
}

static void redir2null(FILE* oldfile, int oflags) {
    int newfd;
    int oldfd = fileno(oldfile);

    // first flush any pending output
    fflush(oldfile);

    // open /dev/null
    newfd = open("/dev/null", oflags);

    // redirect fd to the new file (/dev/null)
    dup2(newfd, oldfd);

    // close the now redundent new file
    close(newfd);
}

static bool dir_exists(const char* dir) {
   struct stat s;
   if (dir == NULL)
     return FALSE;
   int err = stat(dir, &s);
   if (err == -1 && errno == ENOENT)
     return FALSE;
   return(S_ISDIR(s.st_mode));
}

static bool user_exists(const char* userid) {
    return (getpwnam(userid) != NULL);
}

static bool isChrooted(void) {
   struct stat s;
   stat("/", &s);
   return(s.st_ino != 2);
}

static void usage(void) {
    printf("Usage: checkip -d -j -p nnn -u <userid>\nwhere\t-d\trun in daemon mode, logging to syslog\n"
           "\t-j <dir> run the server in a chroot jail - requires -d\n"
           "\t-p nnn is the port to listen to\n\t-u <userid> is the userid the server will execute under\n");
}

#pragma GCC diagnostic ignored "-Wunused-parameter"
static void intHandler(int dummy) {
    running = 0;
}

int main(int argc, char** argv) {
    struct mg_server *server;
    char  buf[100];
    const char* pidFile = "/var/run/checkip.pid";
    char* port = "80,ssl://443:server-cert.pem";
    char* user = "nobody";
    int jail_mode = FALSE;
    char* jail_root = NULL;
    int c;
    time_t start, finish;

    // init variables
    pid_t process_id = 0;
    pid_t sid = 0;
    daemon_mode = FALSE;
    initValidIP();

    // Get the start time
    time(&start);

    // Parse command line for "-h -p nnn -c /path/to/file"
    while((c = getopt(argc, argv, "dhj:p:u:")) != -1)
    {
      switch(c)
      {
      case 'd': daemon_mode = TRUE;
                break;
      case 'j': jail_mode = TRUE;
                char* temp_dir = optarg;
                if (!dir_exists(temp_dir)) {
                  printf("Jail root dir '%s' does not exist, or is not a directory\n", jail_root);
                  return -1;
                }
                jail_root = realpath(temp_dir, NULL);
                break;
      case 'p': port = optarg;
                break;
      case 'u': user = optarg;
                if (!user_exists(user)) {
                  printf("User '%s' does not exist\n", user);
                  return -1;
                }
                break;
      case 'h': usage();
		return -1;
		break;
      case '?': printf("Invalid option '%c'\n", optopt);
		usage();
		return -1;
		break;
      default:	printf("Getopt error\n");
		return -100;
      }

    }
    if (jail_mode && !daemon_mode) {
      printf("-j (chroot jail) requires -d (daemon) by specified\n");
      return -1;
    }

    // lock the pid file
    createPidFile(argv[0], pidFile, 0);

    // chroot jail the process
    if (jail_mode && !isChrooted()) {
       // adjust the path
       putenv("PATH=/bin:/sbin");

       // set the new root dir
       int err = chroot(jail_root);
       if (err != 0) {
          log_msg(daemon_mode, "chroot() failed! (err %d) - exiting", err);
          exit(-1);
       }
    }

    // If a daemon, fork a child process and exit the parent
    if (daemon_mode) {
      // 1. create a child process
      process_id = fork();
      if (process_id < 0) {
        log_msg(daemon_mode, "fork() failed! - exiting");
        exit(-1);
      }

      // 2. kill the parent process
      if (process_id > 0)
        exit(0);

      // 3. unmask the file mode
      umask(0);

      // 4. start a new session
      sid = setsid();
      if (sid < 0) {
        log_msg(daemon_mode, "setsid() failed! - exiting");
        exit(-1);
      }

      // 5. redirect stdin, stdout and stderr to null
      redir2null(stdin, O_RDONLY);
      redir2null(stdout, O_WRONLY);
      redir2null(stderr, O_RDWR);	// Note stderr must be r/w
    }

    // Create and configure the server
    server = mg_create_server(NULL, ev_handler);
    mg_set_option(server, "listening_port", port);
    mg_set_option(server, "run_as_user", user);
    strcpy(buf, mg_get_option(server, "listening_port"));
    if (buf[0] == '\0') {
       log_msg(daemon_mode, "open listening ports failed - exiting");
       goto exit;
    }

    // Trap KILL's - cause 'running' flag to be set false
    signal(SIGINT, intHandler);
    signal(SIGTERM, intHandler);

    // Serve request. Hit Ctrl-C or SIGTERM to terminate the program
    log_msg(daemon_mode, "[%d] CheckIP version %s starting on port %s", getpid(), VERSION, buf);
    if (jail_mode)
      log_msg(daemon_mode, "Established chroot() jail under '%s'", jail_root);
    if (user != NULL)
      log_msg(daemon_mode, "Server executing as user '%s'", user);
    running = -1;

    while (running) {
      mg_poll_server(server, 100);
    }

    // Get the finish time and compute the duration
exit:
    time(&finish);
    double dur = difftime(finish, start);
    long hours, mins, secs, t;
    hours = dur/3600.00;
    t  = fmod(dur,3600.00);
    mins = t / 60;
    secs = t % 60;

    // Cleanup, and free server instance
    if (jail_root != NULL) free(jail_root);
    mg_destroy_server(&server);
    log_msg(daemon_mode, "Checkip stopping after %lu:%02lu:%02lu", hours, mins, secs);
    if (!daemon_mode) printf("\nClean shutdown\n");

    return 0;
}
