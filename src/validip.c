#include <stdio.h>
#include <pcre.h>
#include <string.h>
#include <arpa/inet.h>
#include "validip.h"
#include "log_msg.h"

static int knownCnt;
static struct ValidIP knownIP[SIZE];    // List of IP which have made valid requests

void initValidIP(void) {
    int i;
    for(i = 0; i < SIZE; i++) {
      struct ValidIP* curr = &knownIP[i];
      curr->ipAddr = 0xffffffff;
      curr->count = -1;
      curr->banned = 0;
    }
    knownCnt = 0;
}

uint32_t parseIPV4string(const char* ipAddress) {
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
    if(ret < 0) {       // Something bad happened..
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

    if (ret != 5) {     // Wrong num of matches
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

char* stringIPV4(int ipAddr) {
    static char ip[17];

    int b1 =  ipAddr               >> 24;
    int b2 = (ipAddr & 0x00ffffff) >> 16;
    int b3 = (ipAddr & 0x0000ffff) >> 8;
    int b4 = (ipAddr & 0x000000ff);
    sprintf(ip, "%d.%d.%d.%d", b1, b2, b3, b4);

    return ip;
}

struct ValidIP* findIP(const char* remote_ip) {
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

int updateCnt(const char* uri, struct ValidIP* ip, int rc) {
    int count = ip->count;

    if (rc == 200) {
      if (count > 0) count--;
    } else {
      if (count > -1) {
        count += (strstr(uri, "://") == NULL) ? 2 : 10;
      }
      // don't increment count for favicon.ico
      count -= (strcmp(uri, "/favicon.ico") == 0) ? 2 : 0;
    }

    return ip->count = count;
}

int getKnown(void) {
    return knownCnt;
}

void markBanned(struct ValidIP* ip) {
    ip->banned = -1;
}

void print_stats(int daemon_mode) {
    int i;
    char  ip[17];

    log_msg(daemon_mode, "IP                Banned? Count");
    for(i = 0; i < SIZE; i++) {
        struct ValidIP* curr = &knownIP[i];
        if (curr->ipAddr != 0xffffffff) {
	   strcpy(ip, stringIPV4(curr->ipAddr));
           char* banned = (curr->banned) ? "   Y   " : "";
           log_msg(daemon_mode, "%15s %7s  %6d", ip, banned, curr->count);
        }
     }

}
