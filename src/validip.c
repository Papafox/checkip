#include <stdio.h>
#include <pcre.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>

#include "validip.h"
#include "log_msg.h"
#include "geoip.h"

int cmpValidTime(const void* left, const void* right);
int cmpValidIP(const void* left, const void* right);

static int knownCnt;
static int robotCnt;
static struct ValidIP knownIP[SIZE];    // List of IP which have made valid requests

void initValidIP(void) {
    int i;
    for(i = 0; i < SIZE; i++) {
      struct ValidIP* curr = &knownIP[i];
      curr->ipAddr = 0xffffffff;
      curr->score = -1;
      curr->banned = 0;
      curr->createTS = (time_t)0;
      curr->lastrefTS = (time_t)0;
      curr->country[0] = '\0';
    }
    knownCnt = 0;
    robotCnt = 0;
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

    unsigned int b1 = ((unsigned)(ipAddr & 0xff000000) >> 24) & 0x000000ff;
    unsigned int b2 = ((unsigned)(ipAddr & 0x00ff0000) >> 16) & 0x000000ff;
    unsigned int b3 = ((unsigned)(ipAddr & 0x0000ff00) >>  8) & 0x000000ff;
    unsigned int b4 = ((unsigned)ipAddr & 0x000000ff);
    sprintf(ip, "%u.%u.%u.%u", b1, b2, b3, b4);

    return ip;
}

struct ValidIP* findIP(const char* remote_ip) {
    int i;
    uint32_t ipaddr = parseIPV4string(remote_ip);

    // Search for an existing entry
    for(i = 0; i < SIZE; i++) {
      struct ValidIP* curr = &knownIP[i];
      if (curr->ipAddr == ipaddr ) {
         if (curr->score < 0)
             return NULL;
         else
             return curr;
      }
    }

    // Add a new entry (first unused)
    for(i = 0; i < SIZE; i++) {
      struct ValidIP* curr = &knownIP[i];
      if (curr->ipAddr == 0xffffffff) {
	 char* countryPtr = curr->country;
         curr->ipAddr = ipaddr;
         curr->score = 0;
         curr->createTS = time(NULL);
	 curr->lastrefTS = time(NULL);
         lookupCountry(remote_ip, &countryPtr, sizeof(curr->country));
         knownCnt++;
         log_msg(daemon_mode, "IP addr %s %s added to validIP table (count = %d)", remote_ip, curr->country, knownCnt);
         return curr;
      }
    }

    return (struct ValidIP*)NULL;
}

int updateScore(const char* uri, struct ValidIP* ip, int rc) {
    int score = ip->score;

    if (rc == 200) {
      if (score > 0) score--;
    } else {
      if (score > -1) {
        score += (strstr(uri, "://") == NULL) ? 2 : 10;
      }
    }
    // don't increment count for favicon.ico
    if (strcmp(uri, "/favicon.ico") == 0)
    	score = 0;
    // don't increment count for robots.txt
    if (strcmp(uri, "/robots.txt") == 0)
    	  score = 0;

    ip->lastrefTS = time(NULL);
    return ip->score = score;
}

void updateCnt(struct ValidIP* ip) {
    ip->count++;
}

void updateRobot(void) {
	robotCnt++;
}

int getKnown(void) {
    return knownCnt;
}

void markBanned(struct ValidIP* ip) {
    ip->banned++;
}

// Sort comparator - DESCENDING
int cmpValidIP(const void* left, const void* right) {
    const int dir = -1;		// 1 = asc -1 = desc
    unsigned int leftIP  = ((struct ValidIP*)left)->ipAddr;
    unsigned int rightIP = ((struct ValidIP*)right)->ipAddr;

    if (leftIP < rightIP)
       return -1 * dir;
    if (leftIP > rightIP)
       return 1 * dir;
    return 0;
}

int cmpValidTime(const void* left, const void* right) {
    const int dir = -1;		// 1 = asc -1 = desc
    time_t leftTime  = ((struct ValidIP*)left)->lastrefTS;
    time_t rightTime = ((struct ValidIP*)right)->lastrefTS;

    if (leftTime < rightTime)
       return -1 * dir;
    if (leftTime > rightTime)
       return 1 * dir;
    return 0;
}

void print_stats(int daemon_mode, time_t start, time_t finish, char* msg) {
    int i;
    char  ip[17];
    char  time[20];
    struct ValidIP tempIP[SIZE];

    // Copy the knownIP table so we can sort it
    memcpy(tempIP, knownIP, knownCnt * sizeof(struct ValidIP));

    // Sort the copied table
    qsort(tempIP, knownCnt, sizeof(struct ValidIP), cmpValidTime);

    //  Compute duration Checkip has been running
    double dur = difftime(finish, start);		// total duration as secs
    long days, hours, dhours, mins, secs, t;
    days = dur/86400.00;						// #days
    dhours = dur / 3600;						// #hours (total for duration)
    t  = fmod(dur, 86400.00);
    hours = t / 3600;							// #hours (remainder from days)
    t  = fmod(dur,3600.00);
    mins = t / 60;								// #mins (remainder from hours)
    secs = t % 60;								// #secs (remainder from mins)

    // Compute statistics
    int bannedCnt = 0;
    int totalCnt = 0;
    if (knownCnt > 0) {
	for(i = 0; i < knownCnt; i++) {
		struct ValidIP* curr = &tempIP[i];
		if (curr->ipAddr != 0xffffffff) {
			totalCnt += curr->count;
			if (curr->banned) bannedCnt++;
		}
	}
    }

    // Write summary
    log_msg(daemon_mode, "Checkip %s %lu days %lu hours %lu mins (%lu:%02lu:%02lu)",
			  msg, days, hours, mins, dhours, mins, secs);
    log_msg(daemon_mode, "Summary: total calls %d, total IP's %d, banned IP's %d", totalCnt, knownCnt, bannedCnt);
    log_msg(daemon_mode, "'robots.txt' served %d times", robotCnt);

    //  Dump the ValidIP table
    if (knownCnt > 0) {
    	log_msg(daemon_mode, "   IP                Banned? Count Last Seen");
	for(i = 0; i < knownCnt; i++) {
		struct ValidIP* curr = &tempIP[i];
		if (curr->ipAddr != 0xffffffff) {
			strcpy(ip, stringIPV4(curr->ipAddr));
			char* banned = (curr->banned) ? "     Y " : "";
			strftime(time, sizeof time, "%d/%b %H:%M:%S", localtime(&(curr->lastrefTS)));
			log_msg(daemon_mode, "%2s %15s %7s  %6d %s", curr->country, ip, banned, curr->count, time);
		}
	}
    }

}
