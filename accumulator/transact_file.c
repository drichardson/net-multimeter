#include "transact_file.h"
#include <fcntl.h>
#include <stdio.h>

bool transact_file_open(transact_file* tf, char const* path) {
    int path_len = strlen(path);
    char* tmp = malloc(path_len + 3);
    strcpy(tmp, path);
    strcpy(tmp+path_len, ".TX");

    int fd = open(tmp, O_CREAT | O_EXCL | O_WRONLY);
    if (fd == -1) {
        free(tmp);
        return false;
    }

    tf->fd = fd;
    tf->tmp = tmp;
    tf->dest = strdup(path);
    return true;
}

bool transact_file_close(transact_file* tf, bool commit) {
    bool result = false;
    int rc = close(tf->fd);
    if (rc == 0) {
        if (commit) {
            int rc = rename(tf->tmp, tf->dest);
            if (rc == 0) result = true;
        }
    }
    free(tf->tmp);
    free(tf->dest);
    return result;
}

