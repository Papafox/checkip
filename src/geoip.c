#include "maxminddb.h"

MMDB_s openDB(const char* fname);

void geoip_init() {



}

char* lookup(const char* ipstr, char** result, int len) {


}

MMDB_s openDB(const char* fname) {
    MMDB_s mmdb;
    int status = MMDB_open(fname, MMDB_MODE_MMAP, &mmdb);

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


}
