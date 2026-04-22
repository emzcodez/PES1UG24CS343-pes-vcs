// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

//TODO COMPLETED AND TESTS WORKING
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = (type == OBJ_BLOB) ? "blob" :
                           (type == OBJ_TREE) ? "tree" : "commit";

    // Build full object: "type size\0data"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    size_t total_len = (size_t)header_len + 1 + len;

    uint8_t *full_object = malloc(total_len);
    if (!full_object) return -1;

    memcpy(full_object, header, (size_t)header_len);
    full_object[header_len] = '\0';
    memcpy(full_object + header_len + 1, data, len);

    // Compute SHA-256 of the full object
    ObjectID id;
    compute_hash(full_object, total_len, &id);

    // Deduplication check
    if (object_exists(&id)) {
        if (id_out) *id_out = id;
        free(full_object);
        return 0;
    }
    
    // Create shard directory .pes/objects/XX/
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);
    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);

    // Write to temp file
    char final_path[512];
    object_path(&id, final_path, sizeof(final_path));
    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { free(full_object); return -1; }

    ssize_t written = write(fd, full_object, total_len);
    free(full_object);
    if (written != (ssize_t)total_len) { close(fd); unlink(tmp_path); return -1; }
    
    // fsync, atomic rename, fsync directory
    fsync(fd);
    close(fd);

    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }

    if (id_out) *id_out = id;
    return 0;
}


int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size < 0) { fclose(f); return -1; }

    uint8_t *raw = malloc((size_t)file_size);
    if (!raw) { fclose(f); return -1; }

    if (fread(raw, 1, (size_t)file_size, f) != (size_t)file_size) {
        free(raw); fclose(f); return -1;
    }
    fclose(f);
    
    // Verify integrity: recompute hash and compare to expected
    ObjectID computed;
    compute_hash(raw, (size_t)file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(raw);
        return -1;
    }

    // Find null byte separating header from data
    uint8_t *null_pos = memchr(raw, '\0', (size_t)file_size);
    if (!null_pos) { free(raw); return -1; }

    // Parse type
    if      (strncmp((char *)raw, "blob ",   5) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char *)raw, "tree ",   5) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char *)raw, "commit ", 7) == 0) *type_out = OBJ_COMMIT;
    else { free(raw); return -1; }

    size_t data_offset = (size_t)(null_pos - raw) + 1;
    size_t data_len    = (size_t)file_size - data_offset;

    uint8_t *buf = malloc(data_len + 1);
    if (!buf) { free(raw); return -1; }
    memcpy(buf, raw + data_offset, data_len);
    buf[data_len] = '\0';

    free(raw);
    *data_out = buf;
    *len_out  = data_len;
    return 0;
}
