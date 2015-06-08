#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
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

#include "mongoose.h"
#include "pidfile.h"
#include "checkip.h"
#include "netif_addr.h"
#include "validip.h"
#include "log_msg.h"

static char ipAddr[16];


static bool isLogable(struct mg_connection *conn) {
    uint32_t first_addr = 0x42f94001;		// 66.249.64.1
    uint32_t last_addr = 0x42f95ffe;		// 66.249.95.254

    const char* remote_ip = conn->remote_ip;
    const char* referer = getHeader(conn, "Referer");
    const char* host = getHeader(conn, "Host");
    uint32_t ip = parseIPV4string(remote_ip);

    bool result = (host == NULL || referer != NULL) && strcmp(conn->uri,"/favicon.ico") != 0;
    result |= ip >= first_addr && ip <= last_addr;
    return result;
}

static void logGoogle(struct mg_connection *conn) {
    int i;
    for (i = 0; i < 30; i++) {
      if (conn->http_headers[i].name == NULL || conn->http_headers[i].value == NULL || strlen(conn->http_headers[i].name) == 0) break;
      log_msg(daemon_mode, "%s: header %s = '%s'", conn->remote_ip, conn->http_headers[i].name, conn->http_headers[i].value);
    }
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

static bool isValidReq(struct mg_connection *conn) {
    // Allow references to /robot.txt
    if (strcmp(conn->uri, "/robots.txt")) return TRUE;

    // Check that method is GET
    if (!strcmp(conn->request_method, "GET") == 0) return FALSE;

    // Check that it's directed to this host
    const char* host = getHeader(conn, "Host");
    if (host != NULL && !(strcasecmp(host, HOSTNAME) == 0 || strcmp(host, ipAddr) == 0)) return FALSE;

    // Check that there is NO referer
    const char* referer = getHeader(conn, "Referer");
    if (referer != NULL) return FALSE;

    // Check that the URI is a URI, not a URL
    if (strstr(conn->uri, "://") != NULL) return FALSE;

    return TRUE;
}

static void send_headers(struct mg_connection *conn) {
    // Prevent proxies and browsers from caching response, also include some security headers
    mg_send_header(conn, "Cache-Control", "max-age=0, post-check=0, pre-check=0, no-store, no-cache, must-revalidate");
    mg_send_header(conn, "Pragma", "no-cache");
    mg_send_header(conn, "Content-Type", "text/html; charset=utf8");
    mg_send_header(conn, "X-Frame-Options", "DENY");
    mg_send_header(conn, "Server", "wsadmin-CheckIP/" VERSION);
}

static void checkip_req(struct mg_connection *conn) {
    send_headers(conn);

    // Return the remote ipaddr
    char resp[500];
    char* location = "unknown";
    snprintf(resp, sizeof(resp), "<html><head><meta name=\"robots\" content=\"noindex\"/><title>Current IP Check</title></head><body>Current IP Address: %s<br/>Geography: %s<br/><br/>This product includes GeoLite2 data created by MaxMind, available from <a href=\"http://www.maxmind.com\">http://www.maxmind.com</a></body></html>", conn->remote_ip, location);
    int len = strlen(resp);
    char lenStr[10];
    snprintf(lenStr, 10, "%d", len);
    mg_send_header(conn, "Content-Length", lenStr);

    mg_printf_data(conn, resp);
}

static void reject_req(struct mg_connection *conn) {
    send_headers(conn);

    // Return a please go away message
    char* resp = (strstr(conn->uri, "://") == NULL)?
                    "<html><head><title>Page not found</title></head><body><p>This page you requested '%s' does not exist</p></body></html>"
               :    "<html><head><title>This is not a proxy</title></head><body><p>This is not an open proxy. Your IP address %s has been banned</p></body></html>";

    // Compute a message len and return a Content-Length header
    char lenStr[10];
    mg_send_header(conn, "Content-Language", "en");
    int len = strlen(resp);
    snprintf(lenStr, 10, "%d", len);
    mg_send_header(conn, "Content-Length", lenStr);

    // Return the rejection message
    mg_printf_data(conn, resp, conn->uri);
}
static void banIP(struct ValidIP* ip, const char* ipaddr) {
    // Update the statistics
    markBanned(ip);

    // Fork child process to run iptables
    log_msg(daemon_mode, "IP address %s banned", ipaddr);
    int process_id = fork();
    if (process_id < 0) {
        log_msg(daemon_mode, "iptables fork() failed! - exiting");
        exit(-1);
    }

    // (parent) Make sure WAIT for child, otherwise zombie process
    if (process_id != 0) {
        int status;
        int wait = waitpid(process_id, &status, WUNTRACED | WCONTINUED);
        if (wait < 0) {
            log_msg(daemon_mode, "iptables waitpid() failed! - exiting");
            exit(-1);
        }
        return;
    }

    // (child) Run iptables
    int rc = execl("/sbin/iptables", "iptables", "-I", "INPUT", "-s", ipaddr, "-j", "DROP", (char *)0);
    if (rc != 0)
       log_msg(daemon_mode, "iptables exec() failed (ip = %s rc = %d, errno = %d err = '%s')", ipaddr, rc, errno, strerror(rc));
    exit(0);
}

static int ev_handler(struct mg_connection *conn, enum mg_event ev) {
  int result = 404;
  struct ValidIP* ip;
  bool valid = FALSE;

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
      valid = isValidReq(conn);
      if (valid && strcmp(conn->uri, "/") == 0) {
          checkip_req(conn);
          result = 200;
      }

      if (!valid) {
         result = 404;
         if (strcmp(conn->uri, "/robots.txt") == 0)
	    result = 200;
         reject_req(conn);
      }

      // update the ban count and possibly ban the ip addr
      updateCnt(conn->uri, ip, result);

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
      if (ip->count >= LIMIT || strcmp(conn->request_method, "GET") != 0) {
        banIP(ip, conn->remote_ip);
      }
      return (result == 200) ? MG_TRUE : MG_FALSE;

    default:
      return MG_FALSE;
  }
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

static const char* getIPaddr(void) {
    return netif_addr("eth0");
}

#pragma GCC diagnostic ignored "-Wunused-parameter"
static void intHandler(int dummy) {
    running = 0;
}

int main(int argc, char** argv) {
    struct mg_server *server;
    char  buf[100];
    const char* pidFile = "/var/run/checkip.pid";
    char port[80];
    char* user = "nobody";
    int jail_mode = FALSE;
    char* jail_root = NULL;
    int c;
    time_t start, finish;

    // init variables
    pid_t process_id = 0;
    pid_t sid = 0;
    daemon_mode = FALSE;

    strcpy(ipAddr, getIPaddr());
//  strcpy(port, "80,ssl://");
//  strcat(port, ipAddr);
//  strcat(port, ":443:checkip-cert.pem");
    strcpy(port, "80,ssl://0.0.0.0:443:checkip-cert.pem");

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
      case 'p': strcpy(port, optarg);
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

    // Open the log
    if (daemon_mode)
      openlog(NULL, LOG_CONS | LOG_PID, LOG_DAEMON);

    // lock the pid file
    createPidFile(argv[0], pidFile, 0);

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
    log_msg(daemon_mode, "CheckIP version %s starting", VERSION);
    server = mg_create_server(NULL, ev_handler);
    mg_set_option(server, "listening_port", port);
    strcpy(buf, mg_get_option(server, "listening_port"));
    if (buf[0] == '\0') {
       log_msg(daemon_mode, "open listening ports failed - exiting");
       goto exit;
    }

    // chroot jail the process
    if (jail_mode && !isChrooted()) {
       // adjust the path
       putenv("PATH=/bin:/sbin");

       // set the new root dir
       int err = chroot(jail_root);
       if (err != 0) {
          log_msg(daemon_mode, "chroot() failed! (err %d) - exiting", errno);
          exit(-1);
       }
       log_msg(daemon_mode, "Established chroot() jail under '%s'", jail_root);
    }

    // Trap KILL's - cause 'running' flag to be set false
    running = -1;
    signal(SIGINT, intHandler);
    signal(SIGTERM, intHandler);

    // Serve request. Hit Ctrl-C or SIGTERM to terminate the program
    mg_set_option(server, "run_as_user", user);
    if (user != NULL)
      log_msg(daemon_mode, "Server executing as user '%s'", user);
    log_msg(daemon_mode, "Listening on port %s", buf);

    while (running) {
      mg_poll_server(server, 250);
    }
    if(!daemon_mode) printf("\n");

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

    // Print stats
    print_stats(daemon_mode);

    if (!daemon_mode) printf("\nClean shutdown\n");

    return 0;
}
