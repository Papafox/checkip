/*
 * geoip.h
 *
 *  Created on: 24 Aug 2015
 *      Author: matthew
 */

#ifndef GEOIP_H
#define GEOIP_H

void initGeoIP();
void closeGeoIP();
char* lookupCountry(const char* ipstr, char** result, int len);

#endif /* GEOIP_H */
