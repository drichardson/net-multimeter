#include "transact_file.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

bool transact_file_open(transact_file* tf, char const* path) {
    int path_len = strlen(path);
    char* tmp = malloc(path_len + 4);
    strcpy(tmp, path);
    strcpy(tmp+path_len, ".TX");

    int fd = open(tmp, O_CREAT | O_EXCL | O_WRONLY, 0666);
    if (fd == -1) {
        free(tmp);
        return false;
    }

    FILE* fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        free(tmp);
        return false;
    }

    tf->fp = fp;
    tf->tmp = tmp;
    tf->dest = strdup(path);

    return true;
}

bool transact_file_close(transact_file* tf, bool commit) {
    bool result = false;
    int rc = fclose(tf->fp);
    if (rc == 0) {
        if (commit) {
            rc = rename(tf->tmp, tf->dest);
            if (rc == 0) result = true;
        }
    }
    free(tf->tmp);
    free(tf->dest);
    return result;
}

