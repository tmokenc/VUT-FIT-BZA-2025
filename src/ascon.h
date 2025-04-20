/// @file ascon.h
/// @author Nguyen Le Duy
/// @date 13/04/2025
/// @brief Header file for the ASCON cipher.

#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>
#include <stdlib.h>

#define ASCON_BLOCK_SIZE 16
#define ASCON_STATE_SIZE 5
#define ASCON_KEY_SIZE 16 
#define ASCON_NONCE_SIZE 16
#define ASCON_TAG_SIZE 16
#define ASCON_HASH_SIZE 32

typedef union {
    uint8_t b[8];
    uint32_t d[2];
    uint64_t q;
} u64;

typedef struct {
    u64 inner[ASCON_STATE_SIZE];
    uint8_t unprocessed_len;
} AsconState;

typedef struct {
    AsconState state;
    u64 key[2];
} AsconAeadState;

// =========== High-level API functions ===========

/// @brief Encrypts data using ASCON
/// @param plaintext Pointer to the plaintext data
/// @param plaintext_len Length of the plaintext data
/// @param aad Pointer to the associated data
/// @param aad_len Length of the associated data
/// @param key Pointer to the encryption key
/// @param nonce Pointer to the nonce
/// @param ciphertext Pointer to the output buffer for the ciphertext
/// @param tag Pointer to the output buffer for the tag
/// @note The ciphertext buffer must be at least `plaintext_len` bytes long
void ascon_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *key, const uint8_t *nonce,
                   uint8_t *ciphertext, uint8_t *tag);

/// @brief Decrypts data using ASCON
/// @param ciphertext Pointer to the ciphertext data
/// @param ciphertext_len Length of the ciphertext data
/// @param aad Pointer to the associated data
/// @param aad_len Length of the associated data
/// @param key Pointer to the decryption key
/// @param nonce Pointer to the nonce
/// @param tag Pointer to the tag to verify
/// @param plaintext Pointer to the output buffer for the plaintext
/// @return 1 if decryption is successful and the tag is valid, 0 otherwise
/// @note The plaintext buffer must be at least `ciphertext_len` bytes long
int ascon_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *key, const uint8_t *nonce,
                  const uint8_t *tag, uint8_t *plaintext);

/// @brief Hash function for ASCON, producing a 256-bit digest (32 bytes)
/// @param input Pointer to the input data
/// @param input_len Length of the input data
/// @param output Pointer to the output buffer
/// @note The output buffer must be at least 32 bytes long
void ascon_hash256(const uint8_t *input, size_t input_len, uint8_t *output);

void ascon_xof128(const uint8_t *input, size_t input_len,
                   uint8_t *output, size_t output_len);

void ascon_cxof128(const uint8_t *input, size_t input_len,
                   const uint8_t *custom_data, size_t custom_data_len,
                   uint8_t *output, size_t output_len);


// =========== Low-level API functions ===========

/*
For the low-level API, the user is responsible for managing the state and
the input/output buffers. The user must call the appropriate functions in the
correct order to perform encryption, decryption, hashing, or XOF operations.

The low-level API provides more flexibility and control over the ASCON
operations, by using Initialize - Update - Finalize sequence. This allows the user 
to process data in chunks. This is practically useful for applications that require 
streaming encryption or hashing, where data may not be available in a single block. 
Also useful for embedded applications, where the user may want to process data 
in smaller chunks to save precious memory resources.

The correct sequence of function calls is as follows:
1. Initialize the state with the key, nonce, and any associated data (if applicable).
2. Update the state with the input data (plaintext, ciphertext, or hash input).
    (This can be done in multiple calls, allowing for streaming data processing.)
3. Finalize the operation to produce the output (ciphertext, plaintext, or hash digest).
   
For best practice, the user should zero out the state and any sensitive data
(like keys) after use to prevent accidental leakage, there is a utility function
`zeroize` provided for this purpose.
*/

/// Initialize - Update - Finalize sequence for ASCON AEAD
/// The initialization function must be called first and it is the same for both
/// encryption and decryption
void ascon_aead_init(AsconAeadState *state, const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_len);

/// The ciphertext buffer must be at least `plaintext_len` bytes long
void ascon_aead_update(AsconAeadState *state, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext);
/// Finalize the encryption process by generating the tag
void ascon_aead_finalize(AsconAeadState *state, uint8_t *tag);

/// The plaintext buffer must be at least `ciphertext_len` bytes long
void ascon_aead_decrypt_update(AsconAeadState *state, const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *plaintext);
/// Finalize the decryption process by verify the tag
int ascon_aead_decrypt_finalize(AsconAeadState *state, const uint8_t *tag);

// Initialize - Update - Finalize sequence for ASCON hash256
void ascon_hash256_init(AsconState *state);
void ascon_hash256_update(AsconState *state, const uint8_t *input, size_t input_len);
void ascon_hash256_finalize(AsconState *state, uint8_t *output);

// Initialize - Update - Finalize sequence for ASCON XOF128
void ascon_xof128_init(AsconState *state);
void ascon_xof128_update(AsconState *state, const uint8_t *input, size_t input_len);
void ascon_xof128_finalize(AsconState *state, uint8_t *output, size_t output_len);

// Initialize - Update - Finalize sequence for ASCON CXOF128
// The custom data is used to initialize the state
// It can be any length up to 2048 bits (256 bytes)
void ascon_cxof128_init(AsconState *state, const uint8_t *custom_data, size_t custom_data_len);
void ascon_cxof128_update(AsconState *state, const uint8_t *input, size_t input_len);
void ascon_cxof128_finalize(AsconState *state, uint8_t *output, size_t output_len);

// =========== Utility functions ===========

/// Securely zeroizes a buffer to prevent sensitive data leakage
/// Ensuring that the process is not optimized away by the compiler
/// @param ptr Pointer to the buffer to be zeroized
/// @param len Length of the buffer
void zeroize(void *ptr, size_t len);

#endif
