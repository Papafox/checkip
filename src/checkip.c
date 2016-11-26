#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "mongoose.h"
#include "pidfile.h"
#include "checkip.h"
#include "netif_addr.h"
#include "validip.h"
#include "log_msg.h"
#include "geoip.h"

static char ipAddr[16];
static char robots[500];
static char sitemap[500];
static char jailDir[500];
static time_t start, finish;		// daemon start and end timestamps
static int running;			// Boolean set false on shutdown
static const char* acme_header = "/.well-known/acme-challenge";
static char letsencrypt_req[500];
static char letsencrypt_resp[500];

static bool isLogable(struct mg_connection *conn) {
    const char* referer = getHeader(conn, "Referer");
    const char* host = getHeader(conn, "Host");
    //const char* remote_ip = conn->remote_ip;
    //uint32_t ip = parseIPV4string(remote_ip);

    bool result = (host == NULL || referer != NULL);
    if (strcmp(conn->uri,"/favicon.ico") == 0) result = FALSE;
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

static bool isValidMethod(struct mg_connection *conn) {
    return (strcmp(conn->request_method, "GET") == 0);
}

static bool isValidReq(struct mg_connection *conn) {
    // Allow references to /robot.txt and /sitemap.xml
    if (strcmp(conn->uri, "/robots.txt") == 0) return TRUE;
    if (strcmp(conn->uri, "/sitemap.xml") == 0) return TRUE;
    if (strncmp(conn->uri, acme_header, strlen(acme_header)) == 0) return TRUE;

    // Check that it's directed to this host
//  const char* host = getHeader(conn, "Host");
//  if (host != NULL && !(strcasecmp(host, HOSTNAME) == 0 || strcmp(host, ipAddr) == 0)) return FALSE;

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
    mg_send_header(conn, "Host", HOSTNAME);
    mg_send_header(conn, "Content-Type", "text/html; charset=utf8");
    mg_send_header(conn, "X-Frame-Options", "DENY");
    mg_send_header(conn, "Server", "wsadmin-CheckIP/" VERSION);
}

static void checkip_letsencrypt(struct mg_connection *conn) {
    const char* remote_ip = conn->remote_ip;

    mg_send_header(conn, "Host", HOSTNAME);
    mg_send_header(conn, "Server", "wsadmin-CheckIP/" VERSION);
    mg_send_header(conn, "Content-Type", "text/plain; charset=ascii");
    if (strcmp(conn->uri, letsencrypt_req) == 0) {
        char lenStr[10];

        snprintf(lenStr, 10, "%d", strlen(letsencrypt_resp));
        mg_send_header(conn, "Content-Length", lenStr);
        mg_printf_data(conn, letsencrypt_resp);
        log_msg(daemon_mode, "letsencrypt challenge received from %s response '%s'", remote_ip, letsencrypt_resp);
    } else {
        char *resp = "** Invalid LetsEncrypt Challenge **\r\nExpected: '%s'\r\nReceived: '%s'\r\n";
        char buff[500];
        char lenStr[10];

        snprintf(buff, 500, resp, letsencrypt_req, conn->uri);
        mg_send_status(conn, 404);
        snprintf(lenStr, 10, "%d", strlen(buff));
        mg_send_header(conn, "Content-Length", lenStr);
        mg_printf_data(conn, buff);
        log_msg(daemon_mode, "incorrect letsencrypt challenge received from %s", remote_ip);
        log_msg(daemon_mode, "received '%s', expected '%s'", conn->uri, letsencrypt_req);
    }
}

static void checkip_robots(struct mg_connection *conn) {
    const char* remote_ip = conn->remote_ip;
    send_headers(conn);
    mg_printf_data(conn, robots);
    updateRobot();
    log_msg(daemon_mode, "robots.txt sent to %s", remote_ip);
}

static void checkip_sitemap(struct mg_connection *conn) {
    const char* remote_ip = conn->remote_ip;
    send_headers(conn);
    mg_printf_data(conn, sitemap);
    log_msg(daemon_mode, "sitemap.xml sent to %s", remote_ip);
}

static void checkip_req(struct mg_connection *conn) {
    send_headers(conn);

    // Return the remote ipaddr
    char resp[500];
    char* location;

    location = (char*)malloc(500);
    lookupCountry(conn->remote_ip, &location, sizeof(location));
    //log_msg(daemon_mode, "IP addr = %s Location = %s", conn->remote_ip, location);
    //strcpy(location, "unknown");
    snprintf(resp, sizeof(resp), "<html><head><meta name=\"google-site-verification\" content=\"sdVLgoSVNvwkjzJEwKUVFlbBuQY-n2HBoUzlHPBWGN8\" /><title>Current IP Check</title></head><body>Current IP Address: %s<br/>Geography: %s<br/><br/>This product includes GeoLite2 data created by MaxMind, available from <a href=\"http://www.maxmind.com\">http://www.maxmind.com</a></body></html>", conn->remote_ip, location);
    int len = strlen(resp);
    char lenStr[10];
    snprintf(lenStr, 10, "%d", len);
    mg_send_header(conn, "Content-Length", lenStr);

    mg_printf_data(conn, resp);
}

static void reject_req(struct mg_connection *conn, int result) {
    char resp[500];
    send_headers(conn);

    // Return a please go away message
    snprintf(resp, sizeof(resp), ((strstr(conn->uri, "://") == NULL)?
                    "<html><head><meta name='google-site-verification' content='sdVLgoSVNvwkjzJEwKUVFlbBuQY-n2HBoUzlHPBWGN8' /><title>Page not found</title></head><body><p>This page you requested '%s' does not exist</p></body></html>"
               :    "<html><head><meta name='google-site-verification' content='sdVLgoSVNvwkjzJEwKUVFlbBuQY-n2HBoUzlHPBWGN8' /><title>This is not a proxy</title></head><body><p>This is not an open proxy. Your IP address %s has been banned</p></body></html>"), conn->remote_ip);

    // Handle invalid method
    if (result == 501)
       snprintf(resp, sizeof(resp), "<html><head><title>No Supported</title></head><body><h1>501 Not Supported</h1><p>Method '%s' is not supported by this server</p></body></html>", conn->request_method);

    // Send result
    mg_send_status(conn, result);

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

    // Has this IP been banned in the past?
    char *msg = "IP address %s banned";
    if (ip->banned > 1)
       msg = "IP Address %s banned %d times";
    log_msg(daemon_mode, msg, ipaddr, ip->banned);

    // Fork child process to run iptables
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

    // (child) Add IP address to iptables "checkip" set
    int rc = (ip->banned <= 1) ? execl("/sbin/ipset", "ipset", "add", "checkip", ipaddr, (char *)0)
			       : execl("/sbin/ipset", "ipset", "add", "checkip", ipaddr, "timeout", "0", (char *)0);
    if (rc != 0)
       log_msg(daemon_mode, "ipset exec() failed (ip = %s rc = %d, errno = %d err = '%s')", ipaddr, rc, errno, strerror(errno));
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
      if (ip != NULL)
         updateCnt(ip);

      // validate and process
      valid = FALSE;
      result = 501;
      if (ip != NULL && (ip->banned == 0) && isValidMethod(conn)) {
         result = 404;
         valid = isValidReq(conn);

         // Handle Letsencrypt challenge
         if ((letsencrypt_req[0] != '\0') && strncmp(conn->uri, acme_header, strlen(acme_header)) == 0) {
             valid = TRUE;
             checkip_letsencrypt(conn);
             result = 200;
         }

         // Handle general cases
         if (valid && strcmp(conn->uri, "/") == 0) {
             checkip_req(conn);
             result = 200;
         }
         if (valid && strcmp(conn->uri, "/robots.txt") == 0) {
             checkip_robots(conn);
             result = 200;
         }
         if (valid && strcmp(conn->uri, "/sitemap.xml") == 0) {
             checkip_sitemap(conn);
             result = 200;
         }
         if (valid && strcmp(conn->uri, "/googled01a3874d935c921.html") == 0) {
             valid = FALSE;
             result = 200;
         }
      }

      if (!valid) {
         reject_req(conn, result);
      }

      // update the ban count and possibly ban the ip addr
      updateScore(conn->uri, ip, result);

      // log the request to syslog
      if (ip->score > 0 || strcmp(conn->uri, "/") != 0) {
		  log_msg(daemon_mode, "[%d] %s: %s '%s%s%s' %d score=%d",
							   conn->local_port,
							   conn->remote_ip,
							   conn->request_method,
							   conn->uri,
							   ((conn->query_string == NULL) ? "" : "?"),
							   ((conn->query_string == NULL) ? "" : conn->query_string),
							   result,
							   ip->score
		  );
      }

      // if necessary, ban the IP address
      if (ip->score >= LIMIT || strcmp(conn->request_method, "GET") != 0) {
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
    printf("Usage: checkip -d -j -p nnn -u <userid> -c <file>\nwhere"
           "\t-d\t\trun in daemon mode, logging to syslog\n"
           "\t-j <dir>\trun the server in a chroot jail - requires -d\n"
           "\t-p nnn\t\tis the port to listen to\n"
           "\t-u <userid>\tis the userid the server will execute under\n"
           "\t-c <file>\tis the SSL server certificate to use - must include both the cert and the private key\n"
           "\t-r <uri>\tis the LetEncrypt challenge URI\n"
           "\t-R \"xxx\"\tis the LetsEncrypt response string when the LetEncrypt challend URI is received\n");
}

static const char* getIPaddr(void) {
    return netif_addr("eth0");
}

// Load the robots.txt file into a static variable 'robots'
static void loadRobots(const char* rootDir) {
	const char* fname = realpath("./robots.txt", NULL);
	struct stat st;

	if (fname == NULL) {
		char pwd[500];
		getcwd(pwd, sizeof(pwd));
		log_msg(daemon_mode, "Robots file '%s' does not exist (curr dir = %s)\n", fname, pwd);
		exit(-1);
	}
	int fd = open(fname, O_RDONLY);
	if (fd == -1) {
		log_msg(daemon_mode, "Robots file '%s' open failed: error %d\n", fname, errno);
		exit(-1);
	}
	fstat(fd, &st);
	if (st.st_size >= (long)sizeof(robots)) {
		log_msg(daemon_mode, "Robots file '%s' has a size of %ld and is too long\n", fname, st.st_size);
		exit(-1);
	}

	read(fd, robots, sizeof(robots));
	close(fd);
	log_msg(daemon_mode, "Robots file '%s%s' loaded", rootDir, fname);
}

static void loadSitemap(const char* rootDir) {
	const char* fname = realpath("./sitemap.xml", NULL);
	struct stat st;

	if (fname == NULL) {
		char pwd[500];
		getcwd(pwd, sizeof(pwd));
		log_msg(daemon_mode, "Sitemap file '%s' does not exist (curr dir = %s)\n", fname, pwd);
		exit(-1);
	}
	int fd = open(fname, O_RDONLY);
	if (fd == -1) {
		log_msg(daemon_mode, "Sitemap file '%s' open failed: error %d\n", fname, errno);
		exit(-1);
	}
	fstat(fd, &st);
	if (st.st_size >= (long)sizeof(sitemap)) {
		log_msg(daemon_mode, "Sitemap file '%s' has a size of %ld and is too long\n", fname, st.st_size);
		exit(-1);
	}

	read(fd, sitemap, sizeof(sitemap));
	close(fd);
	log_msg(daemon_mode, "Sitemap file '%s%s' loaded", rootDir, fname);
}

#pragma GCC diagnostic ignored "-Wunused-function"
static void printTZ(void) {
	time_t t = time(NULL);
	struct tm lt = {0};
	char time[30];
	const char* TZ = getenv("TZ");

	localtime_r(&t, &lt);
	strftime(time, sizeof time, "%Z", &lt);
  	log_msg(daemon_mode, "TZ = '%s' while the timezone is '%s'", ((TZ == NULL) ? "*unset*":TZ), time);
	return;
}

// Signal handler
//    HUP	print the stats
//    INT	end server
//    TERM	end server
void intHandler(int signum) {
    log_msg(daemon_mode, "Signal %s (%d) receieved", strsignal(signum), signum);
    switch(signum) {
    case SIGINT:
         running = 0;
         break;
    case SIGTERM:
         running = 0;
         break;
    case SIGHUP:
    	 loadRobots(jailDir);
    	 loadSitemap(jailDir);
    	 time(&finish);
	 printTZ();
         print_stats(daemon_mode, start, finish, "running for");
         break;
    default:
         break;
    }
}

int main(int argc, char** argv) {
    struct mg_server *server;
    char  buf[100];
    char  cert[100];
    const char* pidFile = "/var/run/checkip.pid";
    char  port[140];
    char* user = "nobody";
    int jail_mode = FALSE;
    int c;
    int fd = -1;

    // init variables
    pid_t process_id = 0;
    pid_t sid = 0;
    daemon_mode = FALSE;
    letsencrypt_req[0] = '\0';
    letsencrypt_resp[0] = '\0';
    strncpy(cert, "checkip-cert.pem", sizeof cert);

    initValidIP();
    jailDir[0] = '\0';

    // Get the start time
    time(&start);

    // Parse command line for "-h -p nnn -c /path/to/file"
    while((c = getopt(argc, argv, "dhj:p:u:r:R:c:")) != -1)
    {
      switch(c)
      {
      case 'c': strncpy(cert, optarg, sizeof cert);
                break;
      case 'd': daemon_mode = TRUE;
                break;
      case 'j': jail_mode = TRUE;
                char* temp_dir = optarg;
                if (!dir_exists(temp_dir)) {
                  printf("Jail root dir '%s' does not exist, or is not a directory\n", jailDir);
                  return -1;
                }
                strncpy(jailDir, realpath(temp_dir, NULL), sizeof jailDir);
                break;
      case 'r': strcpy(letsencrypt_req, optarg);
                break;
      case 'R': strcpy(letsencrypt_resp, optarg);
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
    strcpy(ipAddr, getIPaddr());
    strcpy(port, "80,ssl://0.0.0.0:443:");
    strncat(port, cert, (sizeof port)-strlen(port)-1);

    // Open the log
    if (daemon_mode)
      openlog(NULL, LOG_CONS | LOG_PID, LOG_DAEMON);

    // lock the pid file
    fd = createPidFile(argv[0], pidFile, 0);

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

      // 6. Update the PID file with the child PID
      updateChildPid(fd, (long) getpid());
    }

    // Create and configure the server
    log_msg(daemon_mode, "CheckIP version %s starting", VERSION);
    printTZ();
    log_msg(daemon_mode, "Using SSL certificate '%s'", cert);
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
       int err = chroot(jailDir);
       if (err != 0) {
          log_msg(daemon_mode, "chroot() failed! (err %d) - exiting", errno);
          exit(-1);
       }
       log_msg(daemon_mode, "Established chroot() jail under '%s'", jailDir);

       // Set the curr dir to be within the chroot
       chdir("/");
    }

    // Trap KILL's - cause 'running' flag to be set false, HUP dumps the stats
    running = -1;
    signal(SIGINT, intHandler);
    signal(SIGTERM, intHandler);
    signal(SIGHUP, intHandler);

    // load robots.txt to robots variable
    loadRobots(jailDir);

    // load sitemap.xml to robots variable
    loadSitemap(jailDir);

    // load the GeoIP database
    initGeoIP();

    // Log LetsEncrypt settings
    if (letsencrypt_req[0] != '\0')
        log_msg(daemon_mode, "LE req = '%s'\n", letsencrypt_req);
    if (letsencrypt_resp[0] != '\0')
        log_msg(daemon_mode, "LE resp = '%s'\n", letsencrypt_resp);


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

    // Cleanup, and free server instance
    mg_destroy_server(&server);

    // Close and delete the pid file;
    if (fd != -1) {
    	close(fd);
    	unlink(pidFile);
    }

    // Print stats
    print_stats(daemon_mode, start, finish, "stopping after");

    // Clean up GeoIP2
    closeGeoIP();

    if (!daemon_mode) printf("\nClean shutdown\n");

    return 0;
}
