#include "greatest.h"

uint8_t *HASH_DATA;

size_t HASH_DATA_SIZE = 1000;

static void hash_setup(void *arg) {
    HASH_DATA = malloc(HASH_DATA_SIZE);
    fill_random(HASH_DATA, HASH_DATA_SIZE);
    (void)arg; }

static void hash_teardown(void *arg) {
    free(HASH_DATA);
    (void)arg;
}

TEST hash_official_test_vectors() {
    size_t size;
    char *buffer = read_file_into_memory("test/LWC_HASH_KAT_128_256.txt", &size);
    char *base_buffer = buffer;

    if (!buffer) {
        fprintf(stderr, "Failed to read test vectors\n");
        return 1;
    }

    while (size > 10) {
        ascon_test_vector_t tv = {0};
        size_t processed = ascon_next_test_vector(&tv, buffer, size);
        size -= processed;
        buffer += processed;

        uint8_t output[ASCON_HASH_SIZE];
        ascon_hash256(tv.msg, tv.msg_len, output);

        ASSERT_MEM_EQ(tv.md, output, ASCON_HASH_SIZE);
        

        // Low-level API

        AsconState state;
        ascon_hash256_init(&state);
        for (size_t i = 0; i < tv.msg_len; i += 3) {
            size_t len = (i + 2 < tv.msg_len) ? 3 : tv.msg_len - i;
            ascon_hash256_update(&state, tv.msg + i, len);
        }
        ascon_hash256_finalize(&state, output);

        ASSERT_MEM_EQ(tv.md, output, ASCON_HASH_SIZE);

        free(tv.key);
    }

    free(base_buffer);

    PASS();
}

TEST hash_correctness() {
    uint8_t output1[ASCON_HASH_SIZE];
    uint8_t output2[ASCON_HASH_SIZE];
    
    ascon_hash256(HASH_DATA, HASH_DATA_SIZE, output1);

    AsconState state;
    ascon_hash256_init(&state);

    for (size_t i = 0; i < HASH_DATA_SIZE; i++) {
        ascon_hash256_update(&state, HASH_DATA + i, 1);
    }

    ascon_hash256_finalize(&state, output2);

    ASSERT_MEM_EQ(output1, output2, ASCON_HASH_SIZE);

    PASS();
}

GREATEST_SUITE(hash) {
    GREATEST_SET_SETUP_CB(hash_setup, NULL);
    GREATEST_SET_TEARDOWN_CB(hash_teardown, NULL);

    RUN_TEST(hash_official_test_vectors);
    RUN_TEST(hash_correctness);
}
