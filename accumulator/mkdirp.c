#include "mkdirp.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int mkdirp(char const* dir, mode_t mode) {
    char* dir_copy = strdup(dir);
    char* p = dir_copy;
    int rc = 0;

    // optimization for paths starting at the root. No need to make
    // a mkdir syscall to create the root directory, it has to exist.
    if (*p == '/') ++p;

    while(1) {
        char* slash = strchr(p, '/');
        if (slash) {
            *slash = 0;
        }
        rc = mkdir(dir_copy, mode);
        if (rc == -1 && errno != EEXIST) {
            int errno_save = errno;
            free(dir_copy);
            errno = errno_save;
            return rc;
        }
        if (slash) {
            *slash = '/';
        } else {
            // no more
            break;
        }
        p = slash + 1;
    }

    free(dir_copy);
    return 0;
}

