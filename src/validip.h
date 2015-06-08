#ifndef VALIDIP_H
#define VALIDIP_H

#include <stdint.h>

/*      Automatically ban IPs (via iptables) which issue more than      */
/*      LIMIT number of bad requests.  Each entry in validIP contains   */
/*      an ip addr and a bad request count.  This count is incremented  */
/*      on a bad request but decremented on a good request.  Thus an    */
/*      ip addr needs to make LIMIT+1 bad requests in a row to be       */
/*      banned.  Once the addr is banned, the count is set to -1 and    */
/*      entry can be re-used.                                           */
#define LIMIT 3
#define SIZE 100

struct ValidIP {
  uint32_t      ipAddr;
  int           count;
  int		banned;
};

void initValidIP(void);
uint32_t parseIPV4string(const char* ipAddress);
struct ValidIP* findIP(const char* remote_ip);
int updateCnt(const char* uri, struct ValidIP* ip, int rc);
void markBanned(struct ValidIP* ip);
int getKnown(void);
void print_stats(int daemon_mode);

#endif

