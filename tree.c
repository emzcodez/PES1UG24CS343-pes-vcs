// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>


int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

#define MAX_FLAT_ENTRIES 4096

typedef struct {
    uint32_t mode;
    ObjectID hash;
    char path[256];
} FlatEntry;

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

//TODO COMPLETED

static int write_tree_recursive(FlatEntry *entries, int count, int depth, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        // Get the path relative to current depth
        const char *rel = entries[i].path;
        for (int d = 0; d < depth; d++) {
            const char *slash = strchr(rel, '/');
            if (!slash) { rel = NULL; break; }
            rel = slash + 1;
        }
        if (!rel) { i++; continue; }

        const char *slash = strchr(rel, '/');

        if (!slash) {
            // File at this level — add directly
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            te->hash = entries[i].hash;
            size_t nlen = strlen(rel);
            if (nlen >= sizeof(te->name)) nlen = sizeof(te->name) - 1;
            memcpy(te->name, rel, nlen);
            te->name[nlen] = '\0';
            i++;
        } else {
            // Extract subdirectory name (e.g. "src" from "src/main.c")
            size_t prefix_len = (size_t)(slash - rel);
            char subdir_name[256];
            if (prefix_len >= sizeof(subdir_name)) return -1;
            memcpy(subdir_name, rel, prefix_len);
            subdir_name[prefix_len] = '\0';

            // Find all entries sharing this prefix
            int j = i;
            while (j < count) {
                const char *r = entries[j].path;
                for (int d = 0; d < depth; d++) {
                    const char *s = strchr(r, '/');
                    if (!s) { r = NULL; break; }
                    r = s + 1;
                }
                if (!r) break;
                const char *s = strchr(r, '/');
                if (!s) break;
                size_t plen = (size_t)(s - r);
                if (plen != prefix_len || strncmp(r, subdir_name, prefix_len) != 0) break;
                j++;
            }

            // Recurse into this subdirectory group
            ObjectID subtree_id;
            if (write_tree_recursive(entries + i, j - i, depth + 1, &subtree_id) != 0)
                return -1;

            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = 0040000;
            te->hash = subtree_id;
            size_t nlen = strlen(subdir_name);
            if (nlen >= sizeof(te->name)) nlen = sizeof(te->name) - 1;
            memcpy(te->name, subdir_name, nlen);
            te->name[nlen] = '\0';

            i = j;
        }
    }

    void *tree_data; size_t tree_len;
    if (tree_serialize(&tree, &tree_data, &tree_len) != 0) return -1;
    int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
    free(tree_data);
    return rc;
}


int tree_from_index(ObjectID *id_out) {
    static FlatEntry entries[MAX_FLAT_ENTRIES];
    int count = 0;

    FILE *f = fopen(".pes/index", "r");
    if (f) {
        char hex[65];
        unsigned long long mtime, size_val;
        while (count < MAX_FLAT_ENTRIES) {
            FlatEntry *e = &entries[count];
            int ret = fscanf(f, "%o %64s %llu %llu %255s\n",
                             &e->mode, hex, &mtime, &size_val, e->path);
            if (ret < 5 || ret == EOF) break;
            // Convert hex string to binary hash
            for (int k = 0; k < HASH_SIZE; k++) {
                unsigned int byte;
                sscanf(hex + k * 2, "%2x", &byte);
                e->hash.hash[k] = (uint8_t)byte;
            }
            printf("DEBUG entry: %s\n", e->path);  // remove later
            count++;
        }
        fclose(f);
    }

    if (count == 0) {
        Tree empty = {0};
        void *tree_data; size_t tree_len;
        if (tree_serialize(&empty, &tree_data, &tree_len) != 0) return -1;
        int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
        free(tree_data);
        return rc;
    }

    return write_tree_recursive(entries, count, 0, id_out);
}
