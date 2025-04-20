#include "greatest.h"

TEST cxof_official_test_vectors() {
    size_t size;
    char *buffer = read_file_into_memory("test/LWC_CXOF_KAT_128_512.txt", &size);
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

        #define TEST_CXOF_SIZE (512 / 8)

        uint8_t output[TEST_CXOF_SIZE];
        ascon_cxof128(tv.msg, tv.msg_len, tv.z, tv.z_len, output, TEST_CXOF_SIZE);

        ASSERT_MEM_EQ(tv.md, output, TEST_CXOF_SIZE);

        // Low-level API

        AsconState state;
        ascon_cxof128_init(&state, tv.z, tv.z_len);
        for (size_t i = 0; i < tv.msg_len; i += 3) {
            size_t len = (i + 2 < tv.msg_len) ? 3 : tv.msg_len - i;
            ascon_cxof128_update(&state, tv.msg + i, len);
        }
        ascon_cxof128_finalize(&state, output, TEST_CXOF_SIZE);

        ASSERT_MEM_EQ(tv.md, output, TEST_CXOF_SIZE);

        free(tv.key);
    }

    free(base_buffer);

    PASS();
}

GREATEST_SUITE(cxof) {
    RUN_TEST(cxof_official_test_vectors);
}


