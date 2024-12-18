#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// generic error enum
// holds all kind of errors returned
// by different functions
typedef enum {
	ERR_NONE,
	ERR_INVALID_PACKET,
	ERR_UNKNOWN_MESSAGE,
	ERR_INVALID_CONTROL_MESSAGE,
	ERR_INVALID_TOKEN_MAGIC,
	ERR_INVALID_BOOL,
	ERR_STR_UNEXPECTED_EOF,
	ERR_EMPTY_BUFFER,
	ERR_END_OF_BUFFER,
	ERR_BUFFER_FULL,
	ERR_REMAINING_BYTES_IN_BUFFER,
	ERR_MISSING_DDNET_SECURITY_TOKEN,
	ERR_HUFFMAN_NODE_NULL,
	ERR_MESSAGE_ID_OUT_OF_BOUNDS,
} Error;

#ifdef __cplusplus
}
#endif
