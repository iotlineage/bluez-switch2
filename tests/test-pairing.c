/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include "switch2-pairing.h"

int main(void)
{
	uint8_t packet[64], payload[17] = {0}, reply[25] = {0x15, 1, 1, 4, 0x10, 0x78, 0, 0, 1};
	const uint8_t a[] = {0x35,3,0xe9,0x29,0x82,0x87,0x71,0x24,0xbe,0xa8,0x0c,0x66,0x46,0x15,0x83,0x4b};
	const uint8_t b[] = {0x5c,0xf6,0xee,0x79,0x2c,0xdf,5,0xe1,0xba,0x2b,0x63,0x25,0xc4,0x1a,0x5f,0x10};
	const uint8_t challenge[] = {0x6f,0xc6,0xdf,0x8a,0xd8,0xfe,0xdf,0x15,0xbb,0x8c,0x15,0xe9,0x1f,0x32,5,0x44};
	uint8_t expected[] = {0x13,0x4c,0x97,0xf5,0x11,0xb9,0xb6,0xdd,0x4d,0x86,0xfd,0x40,0xf5,0x36,0xe9,0xed};
	uint8_t key[16], encrypted[16];
	assert(switch2_pair_random(key));
	assert(switch2_pair_packet(packet, sizeof(packet), 4, payload, 17) == 42);
	assert(packet[17] == 0x15 && packet[18] == 0x91 && packet[20] == 4 && packet[22] == 17);
	assert(!switch2_pair_packet(packet, 41, 4, payload, 17));
	assert(!switch2_pair_packet(packet, sizeof(packet), 4, NULL, 17));
	for (size_t n = 0; n < 25; n++)
		assert(!switch2_pair_reply(reply, n, 4, 17));
	assert(switch2_pair_reply(reply, sizeof(reply), 4, 17));
	assert(!switch2_pair_reply(reply, sizeof(reply), 2, 17));
	reply[5] = 0;
	assert(!switch2_pair_reply(reply, sizeof(reply), 4, 17));
	reply[5] = 0x78;
	reply[8] = 0;
	assert(!switch2_pair_reply(reply, sizeof(reply), 4, 17));
	switch2_pair_key(a, b, key);
	assert(switch2_pair_encrypt_le(key, challenge, encrypted));
	assert(switch2_pair_challenge(encrypted, expected));
	for (unsigned int i = 0; i < 16; i++) {
		expected[i] ^= 1;
		assert(!switch2_pair_challenge(encrypted, expected));
		expected[i] ^= 1;
	}
	puts("PASS: captured Nintendo crypto vector, framing, truncated/stale/negative replies, corrupt challenges");
	return 0;
}
