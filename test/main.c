#include "../src/ascon.h"
#include "greatest.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

void fill_random(uint8_t *output, int length) {
    int urandom = open("/dev/urandom", O_RDONLY);
    read(urandom, output, length);
    close(urandom);
}

unsigned char hex_to_byte(const char *hex) {
    unsigned char byte = 0;
    for (int i = 0; i < 2; i++) {
        byte <<= 4;
        if (hex[i] >= '0' && hex[i] <= '9')
            byte |= hex[i] - '0';
        else if (hex[i] >= 'A' && hex[i] <= 'F')
            byte |= hex[i] - 'A' + 10;
        else if (hex[i] >= 'a' && hex[i] <= 'f')
            byte |= hex[i] - 'a' + 10;
    }
    return byte;
}

// Returns pointer to memory and sets size. Caller must free the buffer.
char *read_file_into_memory(const char *filename, size_t *out_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen failed");
        return NULL;
    }

    // Go to end to get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file); // Go back to beginning

    if (size < 0) {
        perror("ftell failed");
        fclose(file);
        return NULL;
    }

    // Allocate memory
    char *buffer = malloc(size + 1); // +1 for null terminator (optional)
    if (!buffer) {
        perror("malloc failed");
        fclose(file);
        return NULL;
    }

    // Read file into buffer
    size_t read = fread(buffer, 1, size, file);
    fclose(file);

    if ((long)read != size) {
        fprintf(stderr, "fread failed or incomplete\n");
        free(buffer);
        return NULL;
    }

    buffer[size] = '\0'; // Null-terminate (safe even if it's binary)
    if (out_size) *out_size = size;

    return buffer;
}

unsigned next_newline(char *buffer) {
    unsigned i;
    for (i = 0; buffer[i]; i++) {
        if (buffer[i] == '\n') {
            buffer[i] = '\0';
            return i;
        }
    }
    return i;
}

typedef struct {
    uint8_t count[7];
    uint8_t *key;
    uint8_t *nonce;
    uint8_t *ad;
    size_t ad_len;
    uint8_t *pt;
    size_t pt_len;
    uint8_t *ct;
    size_t ct_len;
    uint8_t *msg;
    size_t msg_len;
    uint8_t *z;
    size_t z_len;
    uint8_t *md;
} ascon_test_vector_t;

void free_test_vector(ascon_test_vector_t *tv) {
    if (tv->key) free(tv->key);
    if (tv->nonce) free(tv->nonce);
    if (tv->ad) free(tv->ad);
    if (tv->pt) free(tv->pt);
    if (tv->ct) free(tv->ct);
    if (tv->msg) free(tv->msg);
    if (tv->z) free(tv->z);
    if (tv->md) free(tv->md);
}

void line_hex_2_bytes(char *line, uint8_t **bytes) {
    if (*line == 0) {
        return;
    }

    size_t len = strlen(line);
    *bytes = malloc(len / 2);

    unsigned i = 0;
    unsigned j = 0;

    while (i < len) {
        (*bytes)[j++] = hex_to_byte(line + i);
        i += 2;
    }
}

int startsWith(const char *str, const char *prefix) {
    size_t lenPrefix = strlen(prefix);
    size_t lenStr = strlen(str);
    if (lenStr < lenPrefix) return 0;
    return strncmp(str, prefix, lenPrefix) == 0;
}

int ascon_next_test_vector(ascon_test_vector_t *tv, char *buffer, size_t size) {
    size_t processed = 0;
    while (size > 10) {
        unsigned offset = next_newline(buffer);

        if (offset == 0) {
            buffer += offset + 1;
            processed += offset + 1;
            break;
        }

        if (startsWith(buffer, "Count = ")) {
            strcpy((char *)tv->count, buffer + 8);
        } else if (startsWith(buffer, "Key = ")) {
            line_hex_2_bytes(buffer + 6, &tv->key);
        } else if (startsWith(buffer, "Nonce = ")) {
            line_hex_2_bytes(buffer + 8, &tv->nonce);
        } else if (startsWith(buffer, "AD = ")) {
            line_hex_2_bytes(buffer + 5, &tv->ad);
            tv->ad_len = (offset - 5) / 2;
        } else if (startsWith(buffer, "PT = ")) {
            line_hex_2_bytes(buffer + 5, &tv->pt);
            tv->pt_len = (offset - 5) / 2;
        } else if (startsWith(buffer, "CT = ")) {
            line_hex_2_bytes(buffer + 5, &tv->ct);
            tv->ct_len = (offset - 5) / 2;
        } else if (startsWith(buffer, "Msg = "))  {
            line_hex_2_bytes(buffer + 6, &tv->msg);
            tv->msg_len = (offset - 6) / 2;
        } else if (startsWith(buffer, "MD = ")) {
            line_hex_2_bytes(buffer + 5, &tv->md);
        } else if (startsWith(buffer, "Z = ")) {
            line_hex_2_bytes(buffer + 4, &tv->z);
            tv->z_len = (offset - 4) / 2;
        }

        buffer += offset + 1;
        processed += offset + 1;
    }

    return processed;
}


#include "hash.c"
#include "aead.c"
#include "xof.c"
#include "cxof.c"

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();

    RUN_SUITE(aead);
    RUN_SUITE(hash);
    RUN_SUITE(xof);
    RUN_SUITE(cxof);

    GREATEST_MAIN_END();
}
