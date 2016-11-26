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
#define LIMIT 2
#define SIZE 500

struct ValidIP {
  uint32_t	ipAddr;
  int		count;
  int           score;
  int		banned;
  time_t	createTS;
  time_t	lastrefTS;
  char		country[3];
};

void initValidIP(void);
uint32_t parseIPV4string(const char* ipAddress);
struct ValidIP* findIP(const char* remote_ip);
int updateScore(const char* uri, struct ValidIP* ip, int rc);
void updateCnt(struct ValidIP* ip);
void markBanned(struct ValidIP* ip);
int getKnown(void);
void print_stats(int daemon_mode, time_t start, time_t finish, char* msg);
void updateRobot(void);

#endif

