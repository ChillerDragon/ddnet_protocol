#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"
#include "errors.h"
#include "msg_game.h"
#include "msg_system.h"

// The sequence and acknowledge number can never
// be higher than 1024
#define MAX_SEQUENCE (1 << 10)

// These flags are used by the chunk header.
// Vital chunks contain a sequence number
// and are reliable.
// If the peer does not acknowledge the sequence number
// the chunk is resend with the resend flag set.
typedef enum {
	// Vital chunks are reliable.
	// They contain a sequence number and will be resend
	// if the peer did not acknowledge that sequence number.
	CHUNK_FLAG_VITAL = 0b01000000,

	// If this exact message was already sent the resend flag is set.
	// This can happen if there is lag or packet loss.
	CHUNK_FLAG_RESEND = 0b10000000,
} ChunkFlag;

// Every game or system message is packed in a chunk.
// Every chunk has a 2 or 3 byte header.
// This struct is the parsed representation of this header.
//
// Be careful! The `sequence` field is only used by vital chunks!
typedef struct {
	// Bit flags that can be any combination of the `ChunkFlag` enum.
	uint8_t flags;

	// Size in bytes of the chunk payload.
	// Excluding the chunk headers size.
	uint16_t size;

	// Set only if flags & CHUNK_FLAG_VITAL
	// Is the amount of vital chunks that were already sent.
	// But the number flips back to 0 when `MAX_SEQUENCE` is reached.
	uint16_t sequence;
} ChunkHeader;

// Parses a byte buffer as a chunk header.
// Consumes 2 or 3 bytes and stores the result in `header`. Returns the number
// of bytes consumed.
size_t decode_chunk_header(const uint8_t *buf, ChunkHeader *header);

// Given a filled header struct it it will pack it into `buf`
// writing either 2 or 3 bytes depending on the header type.
// Returns a number of bytes written
//
// Example usage:
// ```C
// ChunkHeader header = {
// 	.flags = CHUNK_FLAG_VITAL,
// 	.size = 2,
// 	.sequence = 4};
// uint8_t buf[8];
// size_t bytes_written = encode_chunk_header(&header, buf);
// ```
size_t encode_chunk_header(const ChunkHeader *header, uint8_t *buf);

// Be careful this is not the message id
// that is sent over the network!
typedef enum {
	DDNET_MSG_KIND_UNKNOWN,
	DDNET_MSG_KIND_INFO,
	DDNET_MSG_KIND_MAP_CHANGE,
	DDNET_MSG_KIND_MAP_DATA,
	DDNET_MSG_KIND_CON_READY,
	DDNET_MSG_KIND_CL_STARTINFO,
	DDNET_MSG_KIND_SNAP,
	DDNET_MSG_KIND_SNAPEMPTY,
	DDNET_MSG_KIND_SNAPSINGLE,
	DDNET_MSG_KIND_SNAPSMALL,
	DDNET_MSG_KIND_INPUTTIMING,
	DDNET_MSG_KIND_RCON_AUTH_STATUS,
	DDNET_MSG_KIND_RCON_LINE,
	DDNET_MSG_KIND_READY,
	DDNET_MSG_KIND_ENTERGAME,
	DDNET_MSG_KIND_INPUT,
	DDNET_MSG_KIND_RCON_CMD,
} DDNetMessageKind;

// Union abstracting away any kind of game or system message
// Check the DDNetMessageKind to know which one to use
typedef union {
	MsgUnknown unknown;
	MsgInfo info;
	MsgMapChange map_change;
	MsgMapData map_data;
	MsgInputTiming input_timing;
	MsgRconAuthStatus rcon_auth_status;
	MsgRconLine rcon_line;
	MsgInput input;
	MsgRconCmd rcon_cmd;
	MsgClStartInfo start_info;
} DDNetGenericMessage;

// To access the net message struct check the `kind`
// and access the `msg` union accordingly.
typedef struct {
	DDNetMessageKind kind;
	DDNetGenericMessage msg;
} DDNetMessage;

// A chunk is the container of a net message.
// One chunk contains of a chunk header.
// And a chunk payload. The payload contains
// exactly one net message of either type game or system.
typedef struct {
	ChunkHeader header;
	DDNetMessage payload;
} Chunk;

// Returns true if the passed in message kind is a vital message
// vital messages are reliable and should be resend if they
// are not acknowledged by the peer.
// Not all messages are vital to improve performance
// and not resend outdated data such as game state and inputs.
bool ddnet_is_vital_msg(DDNetMessageKind kind);

// Given an entire chunk that has all values
// for message in the payload already set
// This function will fill the chunks header accordingly
// For now this only means setting the correct size based on the payload
Error fill_chunk_header(Chunk *chunk);

#ifdef __cplusplus
}
#endif
