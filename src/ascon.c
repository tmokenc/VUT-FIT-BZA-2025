/// @file ascon.h
/// @author Nguyen Le Duy
/// @date 13/04/2025
/// @brief Implementation of the ASCON cipher.

#include "ascon.h"
#include <string.h>
#include <stdio.h>

/// Inline function definition
#define INLINE static inline __attribute__((always_inline))

/// Rotate the bits of x to the right by n bits
#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// #define PADDING_MASK(x) (0x80 << (56 - (x) * 8))
#define PADDING_MASK(x) (1llu << (8 * (x)))

#define ASCON_HASH_BLOCK_SIZE 8
#define ASCON_AEAD_BLOCK_SIZE 16

// ASCON round constants
#define ROUND0  0x3c
#define ROUND1  0x2d
#define ROUND2  0x1e
#define ROUND3  0x0f
#define ROUND4  0xf0
#define ROUND5  0xe1
#define ROUND6  0xd2
#define ROUND7  0xc3
#define ROUND8  0xb4
#define ROUND9  0xa5
#define ROUND10 0x96
#define ROUND11 0x87
#define ROUND12 0x78
#define ROUND13 0x69
#define ROUND14 0x5a
#define ROUND15 0x4b

#define ASCON_AEAD_IV 0x00001000808c0001

INLINE void ascon_round(AsconState *state, uint64_t constant);

// For hashing functions
INLINE void ascon_absorb(AsconState *state, const uint8_t *input, size_t input_len);
INLINE void ascon_squeeze(AsconState *state, uint8_t *output, size_t output_len);
void zeroize(void *ptr, size_t len);

INLINE uint64_t read_u64(const uint8_t *ptr, size_t len) {
    uint64_t result = 0;
    memcpy(&result, ptr, len);
    return result;
}

#define PERMUTATION_ROUNDS_12(state) \
    ascon_round(state, ROUND4); \
    ascon_round(state, ROUND5); \
    ascon_round(state, ROUND6); \
    ascon_round(state, ROUND7); \
    ascon_round(state, ROUND8); \
    ascon_round(state, ROUND9); \
    ascon_round(state, ROUND10); \
    ascon_round(state, ROUND11); \
    ascon_round(state, ROUND12); \
    ascon_round(state, ROUND13); \
    ascon_round(state, ROUND14); \
    ascon_round(state, ROUND15)

#define PERMUTATION_ROUNDS_8(state) \
    ascon_round(state, ROUND8); \
    ascon_round(state, ROUND9); \
    ascon_round(state, ROUND10); \
    ascon_round(state, ROUND11); \
    ascon_round(state, ROUND12); \
    ascon_round(state, ROUND13); \
    ascon_round(state, ROUND14); \
    ascon_round(state, ROUND15)

void ascon_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *key, const uint8_t *nonce,
                   uint8_t *ciphertext, uint8_t *tag) {

    AsconAeadState state;

    ascon_aead_init(&state, key, nonce, aad, aad_len);
    ascon_aead_update(&state, plaintext, plaintext_len, ciphertext);
    ascon_aead_finalize(&state, tag);

    zeroize(&state, sizeof(AsconAeadState));
}

int ascon_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *tag, uint8_t *plaintext) {
    AsconAeadState state;

    ascon_aead_init(&state, key, nonce, aad, aad_len);
    ascon_aead_decrypt_update(&state, ciphertext, ciphertext_len, plaintext);
    int result = ascon_aead_decrypt_finalize(&state, tag);
    zeroize(&state, sizeof(AsconAeadState));

    return result;
}

void ascon_hash256(const uint8_t *input, size_t input_len, uint8_t *output) {
    AsconState state;
    ascon_hash256_init(&state);
    ascon_hash256_update(&state, input, input_len);
    ascon_hash256_finalize(&state, output);
    zeroize(&state, sizeof(AsconState));
}

void ascon_xof128(const uint8_t *input, size_t input_len,
                   uint8_t *output, size_t output_len) {
    AsconState state;
    ascon_xof128_init(&state);
    ascon_xof128_update(&state, input, input_len);
    ascon_xof128_finalize(&state, output, output_len);
    zeroize(&state, sizeof(AsconState));
}

void ascon_cxof128(const uint8_t *input, size_t input_len,
                   const uint8_t *custom_data, size_t custom_data_len,
                   uint8_t *output, size_t output_len) {
    AsconState state;
    ascon_cxof128_init(&state, custom_data, custom_data_len);
    ascon_cxof128_update(&state, input, input_len);
    ascon_cxof128_finalize(&state, output, output_len);
    zeroize(&state, sizeof(AsconState));
}



// =========== Low-level API functions ===========

void ascon_aead_init(
    AsconAeadState *aead_state,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len
) {
    aead_state->key[0].q = read_u64(key, 8);
    aead_state->key[1].q = read_u64(key + 8, 8);

    // load key
    aead_state->state.inner[0].q = ASCON_AEAD_IV;
    aead_state->state.inner[1].q = aead_state->key[0].q;
    aead_state->state.inner[2].q = aead_state->key[1].q;
    aead_state->state.inner[3].q = read_u64(nonce, 8);
    aead_state->state.inner[4].q = read_u64(nonce + 8, 8);
    PERMUTATION_ROUNDS_12(&aead_state->state);
    aead_state->state.inner[3].q ^= aead_state->key[0].q;
    aead_state->state.inner[4].q ^= aead_state->key[1].q;
    aead_state->state.unprocessed_len = 0;

    // associated data
    if (aad_len > 0) {
        while (aad_len >= ASCON_AEAD_BLOCK_SIZE) {
            aead_state->state.inner[0].q ^= read_u64(aad, 8);
            aead_state->state.inner[1].q ^= read_u64(aad + 8, 8);
            PERMUTATION_ROUNDS_8(&aead_state->state);
            aad += ASCON_AEAD_BLOCK_SIZE;
            aad_len -= ASCON_AEAD_BLOCK_SIZE;
        }

        if (aad_len >= 8) {
            aead_state->state.inner[0].q ^= read_u64(aad, 8);
            aead_state->state.inner[1].q ^= read_u64(aad + 8, aad_len - 8);
            aead_state->state.inner[1].q ^= PADDING_MASK(aad_len - 8);
        } else {
            aead_state->state.inner[0].q ^= read_u64(aad, aad_len);
            aead_state->state.inner[0].q ^= PADDING_MASK(aad_len);
        }

        PERMUTATION_ROUNDS_8(&aead_state->state);
    }

    // domain separation
    aead_state->state.inner[4].q ^= 0x8000000000000000;
}

void ascon_aead_update(AsconAeadState *aead_state, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext) {
    // Mostly the same as ascon_absorb, but use 8 rounds instead of 12 rounds

    if (aead_state->state.unprocessed_len > 0) {
        while (plaintext_len > 0 && aead_state->state.unprocessed_len < ASCON_AEAD_BLOCK_SIZE) {
            if (aead_state->state.unprocessed_len < 8) {
                aead_state->state.inner[0].b[aead_state->state.unprocessed_len] ^= *plaintext;
                ciphertext[0] = aead_state->state.inner[0].b[aead_state->state.unprocessed_len];
            } else {
                aead_state->state.inner[1].b[aead_state->state.unprocessed_len - 8] ^= *plaintext;
                ciphertext[0] = aead_state->state.inner[1].b[aead_state->state.unprocessed_len - 8];
            }

            plaintext += 1;
            plaintext_len -= 1;
            ciphertext += 1;
            aead_state->state.unprocessed_len += 1;
        }

        if (aead_state->state.unprocessed_len == ASCON_AEAD_BLOCK_SIZE) {
            PERMUTATION_ROUNDS_8(&aead_state->state); // unprocessed_len will be reset later
        } else {
            return; // Nothing left in the plaintext
        }
    }

    while (plaintext_len >= ASCON_AEAD_BLOCK_SIZE) {
        aead_state->state.inner[0].q ^= read_u64(plaintext, 8);
        memcpy(ciphertext, aead_state->state.inner[0].b, 8);
        aead_state->state.inner[1].q ^= read_u64(plaintext + 8, 8);
        memcpy(ciphertext + 8, aead_state->state.inner[1].b, 8);
        PERMUTATION_ROUNDS_8(&aead_state->state);
        plaintext += ASCON_AEAD_BLOCK_SIZE;
        plaintext_len -= ASCON_AEAD_BLOCK_SIZE;
        ciphertext += ASCON_AEAD_BLOCK_SIZE;
    }

    // Absorb the remaining bytes
    aead_state->state.unprocessed_len = plaintext_len;

    if (plaintext_len >= 8) {
        aead_state->state.inner[0].q ^= read_u64(plaintext, 8);
        memcpy(ciphertext, aead_state->state.inner[0].b, 8);
        aead_state->state.inner[1].q ^= read_u64(plaintext + 8, plaintext_len - 8);
        memcpy(ciphertext + 8, aead_state->state.inner[1].b, plaintext_len - 8);
    } else {
        aead_state->state.inner[0].q ^= read_u64(plaintext, plaintext_len);
        memcpy(ciphertext, aead_state->state.inner[0].b, plaintext_len);
    }
}

void ascon_aead_finalize(AsconAeadState *aead_state, uint8_t *tag) {
    if (aead_state->state.unprocessed_len >= 8) {
        aead_state->state.inner[1].q ^= PADDING_MASK(aead_state->state.unprocessed_len - 8);
    } else {
        aead_state->state.inner[0].q ^= PADDING_MASK(aead_state->state.unprocessed_len);
    }


    aead_state->state.inner[2].q ^= aead_state->key[0].q;
    aead_state->state.inner[3].q ^= aead_state->key[1].q;
    PERMUTATION_ROUNDS_12(&aead_state->state);
    aead_state->state.inner[3].q ^= aead_state->key[0].q;
    aead_state->state.inner[4].q ^= aead_state->key[1].q;

    memcpy(tag, aead_state->state.inner[3].b, 8);
    memcpy(tag + 8, aead_state->state.inner[4].b, 8);

    zeroize(aead_state->state.inner, sizeof(AsconState));
    zeroize(aead_state->key, ASCON_KEY_SIZE);
}

void ascon_aead_decrypt_update(
    AsconAeadState *aead_state,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *plaintext
) { 
    if (aead_state->state.unprocessed_len > 0) {
        while (ciphertext_len > 0 && aead_state->state.unprocessed_len < ASCON_AEAD_BLOCK_SIZE) {
            if (aead_state->state.unprocessed_len < 8) {
                plaintext[0] = aead_state->state.inner[0].b[aead_state->state.unprocessed_len] ^ *ciphertext;
                aead_state->state.inner[0].b[aead_state->state.unprocessed_len] = *ciphertext;
            } else {
                plaintext[0] = aead_state->state.inner[1].b[aead_state->state.unprocessed_len - 8] ^ *ciphertext;
                aead_state->state.inner[1].b[aead_state->state.unprocessed_len - 8] = *ciphertext;
            }
            ciphertext += 1;
            ciphertext_len -= 1;
            plaintext += 1;
            aead_state->state.unprocessed_len += 1;
        }

        if (aead_state->state.unprocessed_len == ASCON_AEAD_BLOCK_SIZE) {
            PERMUTATION_ROUNDS_8(&aead_state->state); // unprocessed_len will be reset later
        } else {
            return; // Nothing left in the input
        }
    }

    while (ciphertext_len >= ASCON_AEAD_BLOCK_SIZE) {
        uint64_t ciphertext_u64 = read_u64(ciphertext, 8);
        uint64_t plaintext_u64 = aead_state->state.inner[0].q ^ ciphertext_u64;
        memcpy(plaintext, &plaintext_u64, 8);
        aead_state->state.inner[0].q = ciphertext_u64;

        ciphertext_u64 = read_u64(ciphertext + 8, 8);
        plaintext_u64 = aead_state->state.inner[1].q ^ ciphertext_u64;
        memcpy(plaintext + 8, &plaintext_u64, 8);
        aead_state->state.inner[1].q = ciphertext_u64;

        PERMUTATION_ROUNDS_8(&aead_state->state);
        ciphertext += ASCON_AEAD_BLOCK_SIZE;
        ciphertext_len -= ASCON_AEAD_BLOCK_SIZE;
        plaintext += ASCON_AEAD_BLOCK_SIZE;
    }

    // Absorb the remaining bytes
    aead_state->state.unprocessed_len = ciphertext_len;
    size_t index = 0;

    if (ciphertext_len >= 8) {
        uint64_t ciphertext_u64 = read_u64(ciphertext, 8);
        uint64_t plaintext_u64 = aead_state->state.inner[0].q ^ ciphertext_u64;
        memcpy(plaintext, &plaintext_u64, 8);
        aead_state->state.inner[0].q = ciphertext_u64;

        index = 1;
        ciphertext += 8;
        ciphertext_len -= 8;
        plaintext += 8;
    }

    // Must do it byte by byte, since it is assigned to a byte array, not XOR
    for (size_t i = 0; i < ciphertext_len; i++) {
         plaintext[i] = aead_state->state.inner[index].b[i] ^ ciphertext[i];
         aead_state->state.inner[index].b[i] = ciphertext[i];
    }
}

int ascon_aead_decrypt_finalize(AsconAeadState *aead_state, const uint8_t *tag) {
    if (aead_state->state.unprocessed_len >= 8) {
        aead_state->state.inner[1].q ^= PADDING_MASK(aead_state->state.unprocessed_len - 8);
    } else {
        aead_state->state.inner[0].q ^= PADDING_MASK(aead_state->state.unprocessed_len);
    }

    aead_state->state.inner[2].q ^= aead_state->key[0].q;
    aead_state->state.inner[3].q ^= aead_state->key[1].q;
    PERMUTATION_ROUNDS_12(&aead_state->state);
    aead_state->state.inner[3].q ^= aead_state->key[0].q;
    aead_state->state.inner[4].q ^= aead_state->key[1].q;

    uint32_t *tag_ptr = (uint32_t *)tag;
    uint32_t fold = 
        (aead_state->state.inner[3].d[0] ^ tag_ptr[0])
      | (aead_state->state.inner[3].d[1] ^ tag_ptr[1])
      | (aead_state->state.inner[4].d[0] ^ tag_ptr[2])
      | (aead_state->state.inner[4].d[1] ^ tag_ptr[3]);

    fold |= -fold;

    zeroize(aead_state->state.inner, sizeof(AsconState));
    zeroize(aead_state->key, ASCON_KEY_SIZE);

    return (fold >> 31) ^ 1;
}


void ascon_hash256_init(AsconState *state) {
    // Precomputed IVs for ASCON-256
    state->inner[0].q = 0x9b1e5494e934d681;
    state->inner[1].q = 0x4bc3a01e333751d2;
    state->inner[2].q = 0xae65396c6b34b81a;
    state->inner[3].q = 0x3c7fd4a4d56a4db3;
    state->inner[4].q = 0x1a5c464906c5976d;
    state->unprocessed_len = 0;
}

void ascon_hash256_update(AsconState *state, const uint8_t *input, size_t input_len) {
    ascon_absorb(state, input, input_len);
}

void ascon_hash256_finalize(AsconState *state, uint8_t *output) {
    ascon_squeeze(state, output, ASCON_HASH_SIZE);
    zeroize(state, sizeof(AsconState));
}

void ascon_xof128_init(AsconState *state) {
    // Precomputed IVs for ASCON-XOF
    state->inner[0].q = 0xda82ce768d9447eb;
    state->inner[1].q = 0xcc7ce6c75f1ef969;
    state->inner[2].q = 0xe7508fd780085631;
    state->inner[3].q = 0x0ee0ea53416b58cc;
    state->inner[4].q = 0xe0547524db6f0bde;
    state->unprocessed_len = 0;
}

void ascon_xof128_update(AsconState *state, const uint8_t *input, size_t input_len) {
    ascon_absorb(state, input, input_len);
}

void ascon_xof128_finalize(AsconState *state, uint8_t *output, size_t output_len) {
    ascon_squeeze(state, output, output_len);
    zeroize(state, sizeof(AsconState));
}

void ascon_cxof128_init(AsconState *state, const uint8_t *custom_data, size_t custom_data_len) {
    state->inner[0].q = 0x675527c2a0e8de03;
    state->inner[1].q = 0x43d12d7dc0377bbc;
    state->inner[2].q = 0xe9901dec426e81b5;
    state->inner[3].q = 0x2ab14907720780b6;
    state->inner[4].q = 0x8f3f1d02d432bc46;
    state->unprocessed_len = 0;

    // Z0 is the length of the custom data in bits
    state->inner[0].q ^= custom_data_len * 8;
    PERMUTATION_ROUNDS_12(state);

    // absorb the custom data
    ascon_absorb(state, custom_data, custom_data_len);
    state->inner[0].q ^= PADDING_MASK(state->unprocessed_len);
    PERMUTATION_ROUNDS_12(state);
    state->unprocessed_len = 0;
}

void ascon_cxof128_update(AsconState *state, const uint8_t *input, size_t input_len) {
    ascon_absorb(state, input, input_len);
}

void ascon_cxof128_finalize(AsconState *state, uint8_t *output, size_t output_len) {
    ascon_squeeze(state, output, output_len);
    zeroize(state, sizeof(AsconState));
}

INLINE void ascon_absorb(AsconState *state, const uint8_t *input, size_t input_len) {
    if (state->unprocessed_len > 0) {
        while (input_len > 0 && state->unprocessed_len < ASCON_HASH_BLOCK_SIZE) {
            state->inner[0].b[state->unprocessed_len] ^= *input;
            input += 1;
            input_len -= 1;
            state->unprocessed_len += 1;
        }

        if (state->unprocessed_len == ASCON_HASH_BLOCK_SIZE) {
            PERMUTATION_ROUNDS_12(state); // unprocessed_len will be reset later
        } else {
            return; // Nothing left in the input
        }
    }


    while (input_len >= ASCON_HASH_BLOCK_SIZE) {
        state->inner[0].q ^= read_u64(input, ASCON_HASH_BLOCK_SIZE);
        PERMUTATION_ROUNDS_12(state);
        input += ASCON_HASH_BLOCK_SIZE;
        input_len -= ASCON_HASH_BLOCK_SIZE;
    }

    // Absorb the remaining bytes
    state->unprocessed_len = input_len;
    state->inner[0].q ^= read_u64(input, input_len);
}

INLINE void ascon_squeeze(AsconState *state, uint8_t *output, size_t output_len) {
    // Absorb the last block before squeezing
    state->inner[0].q ^= PADDING_MASK(state->unprocessed_len);
    PERMUTATION_ROUNDS_12(state);

    while (output_len >= ASCON_HASH_BLOCK_SIZE) {
        memcpy(output, state->inner[0].b, ASCON_HASH_BLOCK_SIZE);
        PERMUTATION_ROUNDS_12(state);
        output += ASCON_HASH_BLOCK_SIZE;
        output_len -= ASCON_HASH_BLOCK_SIZE;
    }

    // Squeeze the final output block
    memcpy(output, state->inner[0].b, output_len);
}

/*

// Reference S-box function from specification:
// state words x0..x4 (uint64), temporary variables t0..t4 (uint64)

x0 ^= x4;    x4 ^= x3;    x2 ^= x1;
t0  = x0;    t1  = x1;    t2  = x2;    t3  = x3;    t4  = x4;
t0 =~ t0;    t1 =~ t1;    t2 =~ t2;    t3 =~ t3;    t4 =~ t4;
t0 &= x1;    t1 &= x2;    t2 &= x3;    t3 &= x4;    t4 &= x0;
x0 ^= t1;    x1 ^= t2;    x2 ^= t3;    x3 ^= t4;    x4 ^= t0;
x1 ^= x0;    x0 ^= x4;    x3 ^= x2;    x2 =~ x2;

*/

INLINE void ascon_round(AsconState *state, uint64_t constant) {
    #define x(i) state->inner[i].q
    uint64_t x0, x1, x2, x3, x4;

    // S-box
    x0 = x(0) ^ x(4);
    x2 = x(2) ^ x(1) ^ constant; // constant layer is added here, since XOR is commutative
    x4 = x(4) ^ x(3);

    uint64_t tx0 = x0   ^ (~x(1) & x2);
    uint64_t tx1 = x(1) ^ (~x2   & x(3));
    uint64_t tx2 = x2   ^ (~x(3) & x4);
    uint64_t tx3 = x(3) ^ (~x4   & x0);
    uint64_t tx4 = x4   ^ (~x0   & x(1));

    tx1 = tx1 ^ tx0;
    tx3 = tx3 ^ tx2;
    tx0 = tx0 ^ tx4;

    // linear
    x0 = tx0 ^ ROR(tx0, 9);
    x1 = tx1 ^ ROR(tx1, 22);
    x2 = tx2 ^ ROR(tx2, 5);
    x3 = tx3 ^ ROR(tx3, 7);
    x4 = tx4 ^ ROR(tx4, 34);

    x(0) = tx0   ^ ROR(x0, 19);
    x(1) = tx1   ^ ROR(x1, 39);
    x(2) = ~(tx2 ^ ROR(x2, 1));
    x(3) = tx3   ^ ROR(x3, 10);
    x(4) = tx4   ^ ROR(x4, 7);
}

/// https://www.cryptologie.net/article/419/zeroing-memory-compiler-optimizations-and-memset_s/
/// Securely zeroizes a buffer to prevent sensitive data leakage
/// Ensuring that the process is not optimized away by the compiler
/// @param ptr Pointer to the buffer to be zeroized
/// @param len Length of the buffer
void zeroize(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}
