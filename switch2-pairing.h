/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef SWITCH2_PAIRING_H
#define SWITCH2_PAIRING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static inline bool switch2_pair_random(uint8_t out[16])
{
	return RAND_bytes(out, 16) == 1;
}

/* Use userspace AES so enrollment does not depend on AF_ALG modules in either
 * the builder or guest. Inputs are Nintendo's little-endian wire components. */
static inline bool switch2_pair_encrypt_le(const uint8_t key[16],
		const uint8_t challenge[16], uint8_t encrypted_le[16])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	uint8_t k[16], input[16], output[32];
	int length = 0, final_length = 0;
	unsigned int i;
	bool ok = false;
	if (!ctx)
		return false;
	for (i = 0; i < 16; i++) {
		k[i] = key[15 - i];
		input[i] = challenge[15 - i];
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, k, NULL) != 1 ||
	    EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
	    EVP_EncryptUpdate(ctx, output, &length, input, 16) != 1 ||
	    EVP_EncryptFinal_ex(ctx, output + length, &final_length) != 1 ||
	    length + final_length != 16)
		goto done;
	for (i = 0; i < 16; i++)
		encrypted_le[i] = output[15 - i];
	ok = true;
done:
	OPENSSL_cleanse(k, sizeof(k));
	OPENSSL_cleanse(input, sizeof(input));
	OPENSSL_cleanse(output, sizeof(output));
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

/* These helpers have no BlueZ dependencies and are exercised by unit tests. */
static inline size_t switch2_pair_packet(uint8_t *out, size_t capacity,
		uint8_t subcommand, const uint8_t *data, size_t length)
{
	/* The side command characteristic combines 17 vibration bytes and CMD. */
	if (length > 255 || capacity < 25 + length || (!data && length))
		return 0;
	memset(out, 0, 25 + length);
	out[17] = 0x15;
	out[18] = 0x91;
	out[19] = 0x01;
	out[20] = subcommand;
	out[22] = length;
	if (length)
		memcpy(out + 25, data, length);
	return 25 + length;
}

static inline bool switch2_pair_reply(const uint8_t *data, size_t length,
		uint8_t subcommand, size_t payload_length)
{
	return data && length >= 8 + payload_length && data[0] == 0x15 &&
		data[1] == 0x01 && data[2] == 0x01 && data[3] == subcommand &&
		data[5] == 0x78 && payload_length && data[8] == 0x01;
}

static inline void switch2_pair_key(const uint8_t a[16], const uint8_t b[16],
		uint8_t key[16])
{
	unsigned int i;
	for (i = 0; i < 16; i++)
		key[i] = a[i] ^ b[i];
}

/* switch2_pair_encrypt_le returns little-endian AES output. Nintendo's captured
 * challenge response uses the unreversed AES block. Compare without logging. */
static inline bool switch2_pair_challenge(const uint8_t encrypted_le[16],
		const uint8_t reply[16])
{
	uint8_t different = 0;
	unsigned int i;
	for (i = 0; i < 16; i++)
		different |= encrypted_le[15 - i] ^ reply[i];
	return different == 0;
}

#endif
