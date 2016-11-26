#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "maxminddb.h"

#define DB "/usr/share/GeoIP/GeoLite2-City.mmdb"

static MMDB_s *mmdb = NULL;

MMDB_s* openDB(const char* fname);
MMDB_lookup_result_s lookupIP(MMDB_s *mmdb, const char *ipstr);
char* getValue(MMDB_lookup_result_s result, char** buffer, int len, ...);


void initGeoIP() {

	mmdb = openDB(DB);

}

void closeGeoIP() {

	if (mmdb != NULL) {
		MMDB_close(mmdb);
		free(mmdb);
		mmdb = NULL;
	}
}

char* lookupCountry(const char* ipstr, char** result, int len) {

	MMDB_lookup_result_s res = lookupIP(mmdb, ipstr);
	if (!res.found_entry) {
	   *result[0] = '\0';
	   return NULL;
	}

	return getValue(res, result, len, "country", "iso_code", NULL);
}

MMDB_s* openDB(const char* fname) {
    MMDB_s* mmdb;
    mmdb = (MMDB_s*)malloc(sizeof(MMDB_s));
    int status = MMDB_open(fname, MMDB_MODE_MMAP, mmdb);

    if (MMDB_SUCCESS != status) {
        fprintf(stderr, "\n  Can't open %s - %s\n", fname,
                MMDB_strerror(status));

        if (MMDB_IO_ERROR == status) {
            fprintf(stderr, "    IO error: %s\n", strerror(errno));
        }

        fprintf(stderr, "\n");

        exit(2);
    }

    return mmdb;
}

MMDB_lookup_result_s lookupIP(MMDB_s *mmdb, const char *ipstr) {
	int gai_error, mmdb_error;
	MMDB_lookup_result_s result = MMDB_lookup_string(mmdb, ipstr, &gai_error, &mmdb_error);

	if (0 != gai_error) {
		fprintf(stderr, "\n  Error from getaddrinfo for %s - %s\n\n", ipstr, gai_strerror(gai_error));
		exit(2);
	}

	if (MMDB_SUCCESS != mmdb_error) {
		fprintf(stderr, "\n  Got an error from libmaxminddb: %s\n\n", MMDB_strerror(mmdb_error));
		exit(3);
	}

	return result;
}

char* getValue(MMDB_lookup_result_s result, char** buffer, int len, ...) {
	int xlen;
	va_list vl;

	va_start(vl, len);
	MMDB_entry_data_s entry_data;
	int status = MMDB_vget_value(&result.entry, &entry_data, vl);
	if (MMDB_SUCCESS != status) {
		fprintf(stderr, "\n  Got an error from libmaxminddb: %s\n\n",
				MMDB_strerror(status));
		exit(3);
	}
	if (!entry_data.has_data)
		return NULL;
	if (MMDB_DATA_TYPE_UTF8_STRING != entry_data.type) {
		fprintf(stderr,
				"\n  Got invalid data from libmaxminddb: %d\nExpected UTF8 String\n\n",
				entry_data.type);
		exit(3);
	}

	//xlen = (((int)entry_data.data_size) > (len - 1)) ? len : (int)entry_data.data_size;
	xlen = 2;
	strncpy(*buffer, entry_data.utf8_string, xlen);
	(*buffer)[xlen] = '\0';
	return *buffer;
}
