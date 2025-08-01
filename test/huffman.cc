#include <gtest/gtest.h>

#include <ddnet_protocol/common.h>
#include <ddnet_protocol/errors.h>
#include <ddnet_protocol/huffman.h>

TEST(Huffman, Decompress) {
	uint8_t decompressed[512];
	uint8_t compressed[] = {0x74, 0xde, 0x16, 0xd9, 0xa2, 0x8a, 0x1b};
	DDNetError err = DDNET_ERR_NONE;
	size_t len = ddnet_huffman_decompress(compressed, sizeof(compressed), decompressed, sizeof(decompressed), &err);
	EXPECT_EQ(err, DDNET_ERR_NONE);
	EXPECT_EQ(len, 4);
	EXPECT_STREQ((const char *)decompressed, "foo");
}
