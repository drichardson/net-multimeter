#pragma once

#include <stdbool.h>
#include <stdio.h>

// Handles writing to a temporary location (in the same folder as the intended
// destination) and then atomically moving the file into the intended
// destination on close.

typedef struct transact_file {
    FILE* fp;
    char* dest;
    char* tmp;
} transact_file;

// Open a file for writing whose intended destination is path. The
// fd member of transact_file will point to a temporary file in
// the same directory as path.
// Returns true on success; false on failure.
// On success, transact_file_close must be called to free associated
// resources.
// On false, errno will be set.
bool transact_file_open(transact_file* tf, char const* path);

// Close a file for writing. If commit is true, tf->tmp is renamed
// to tf->dest. The previous file at tf->dest will be lost.
// If commit is false, the file is closed and unlinked.
// Returns true on success; false otherwise. If false, errno will be set.
bool transact_file_close(transact_file* tf, bool commit);

