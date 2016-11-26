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
#define VERSION "2.30"
#define HOSTNAME "checkip.wsadmin.org"

typedef int bool;

static bool isLogable(struct mg_connection *conn);
static void logGoogle(struct mg_connection *conn);
static const char* getHeader(struct mg_connection *conn, const char* name);
static bool isValidReq(struct mg_connection *conn);
static void checkip_req(struct mg_connection *conn);
static void checkip_robots(struct mg_connection *conn);
static void reject_req(struct mg_connection *conn, int result);
static int ev_handler(struct mg_connection *conn, enum mg_event ev);
static void usage();
static void intHandler(int dummy);
static void redir2null(FILE* oldfile, int oflags);
static bool dir_exists(const char* dir);
static bool user_exists(const char* userid);

#endif
