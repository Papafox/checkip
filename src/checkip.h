/*************************************************************************\
*                  Copyright (C) Matthew Donald, 2015.                    *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU Lesser General Public License as published   *
* by the Free Software Foundation, either version 3 or (at your option)   *
* any later version. This program is distributed without any warranty.    *
* See the files COPYING.lgpl-v3 and COPYING.gpl-v3 for details.           *
**************************************************************************/

#ifndef CHECKIP
#define CHECKIP

#define TRUE	1
#define FALSE	0
#define VERSION "1.10"
#define HOSTNAME "example.org"

struct ValidIP {
  uint32_t	ipAddr;
  int		count;
};

typedef int bool;

static bool isLogable(struct mg_connection *conn);
static void logGoogle(struct mg_connection *conn);
static void log_msg(int daemon_mode, const char *format, ...);
static int updateCnt(const char* uri, struct ValidIP* ip, int rc);
static const char* getHeader(struct mg_connection *conn, const char* name);
static bool isValidReq(struct mg_connection *conn);
static void checkip_req(struct mg_connection *conn);
static void reject_req(struct mg_connection *conn);
static int ev_handler(struct mg_connection *conn, enum mg_event ev);
static void usage();
static void intHandler(int dummy);
static void initValidIP();
static struct ValidIP* findIP(const char* remote_ip);
static uint32_t parseIPV4string(const char* ipAddress);
static void banIP(struct ValidIP* ip, const char* ipaddr);
static void redir2null(FILE* oldfile, int oflags);
static bool dir_exists(const char* dir);
static bool user_exists(const char* userid);

static int running;			// Boolean set false on shutdown
static int daemon_mode;			// Boolean when no terminal available


/*	Automatically ban IPs (via iptables) which issue more than	*/
/*	LIMIT number of bad requests.  Each entry in validIP contains 	*/
/*	an ip addr and a bad request count.  This count is incremented	*/
/*	on a bad request but decremented on a good request.  Thus an	*/
/*	ip addr needs to make LIMIT+1 bad requests in a row to be 	*/
/*	banned.  Once the addr is banned, the count is set to -1 and 	*/
/*	entry can be re-used.						*/
#define LIMIT 3
#define SIZE 100

static struct ValidIP knownIP[SIZE];	// List of IP which have made valid requests
static int knownCnt;

#endif
