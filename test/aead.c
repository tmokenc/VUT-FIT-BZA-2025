#include "greatest.h"

TEST aead_official_test_vectors() {
    size_t size;
    char *buffer = read_file_into_memory("test/LWC_AEAD_KAT_128_128.txt", &size);
    char *base_buffer = buffer;

    if (!buffer) {
        fprintf(stderr, "Failed to read test vectors\n");
        return 1;
    }

    while (size > 10) {
        ascon_test_vector_t tv = {0};

        // High-level API

        size_t processed = ascon_next_test_vector(&tv, buffer, size);
        size -= processed;
        buffer += processed;

        uint8_t *output = malloc(tv.pt_len);
        uint8_t tag[ASCON_TAG_SIZE];

        ascon_encrypt(tv.pt, tv.pt_len, tv.ad, tv.ad_len, tv.key, tv.nonce, output, tag);

        ASSERT_MEM_EQ(tv.ct, output, tv.pt_len);
        ASSERT_MEM_EQ(tv.ct + tv.pt_len, tag, ASCON_TAG_SIZE);

        // Decrypt using high-level API

        int verified = ascon_decrypt(tv.ct, tv.pt_len, tv.ad, tv.ad_len, tv.key, tv.nonce, tv.ct + tv.pt_len, output);

        ASSERT_EQ(verified, 1);
        ASSERT_MEM_EQ(tv.pt, output, tv.pt_len);


        // Low-level API
        
        AsconAeadState state;
        ascon_aead_init(&state, tv.key, tv.nonce, tv.ad, tv.ad_len);

        for (size_t i = 0; i < tv.pt_len; i += 3) {
            size_t len = (i + 2 < tv.pt_len) ? 3 : tv.pt_len - i;
            ascon_aead_update(&state, tv.pt + i, len, output + i);
        }

        ascon_aead_finalize(&state, tag);
        ASSERT_MEM_EQ(tv.ct, output, tv.pt_len);
        ASSERT_MEM_EQ(tv.ct + tv.pt_len, tag, ASCON_TAG_SIZE);

        // Decrypt using low-level API
        
        ascon_aead_init(&state, tv.key, tv.nonce, tv.ad, tv.ad_len);

        for (size_t i = 0; i < tv.pt_len; i += 3) {
            size_t len = (i + 2 < tv.pt_len) ? 3 : tv.pt_len - i;
            ascon_aead_decrypt_update(&state, tv.ct + i, len, output + i);
        }

        verified = ascon_aead_decrypt_finalize(&state, tag);
        ASSERT_EQ(verified, 1);
        ASSERT_MEM_EQ(tv.pt, output, tv.pt_len);

        free(output);
        free_test_vector(&tv);
    }

    free(base_buffer);

    PASS();
}

GREATEST_SUITE(aead) {
    RUN_TEST(aead_official_test_vectors);
}
