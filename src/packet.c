#include "packet.h"
#include "common.h"
#include "errors.h"
#include "fetch_chunks.h"
#include "huffman.h"
#include "packet_control.h"

PacketHeader decode_packet_header(uint8_t *buf) {
	return (PacketHeader){
		.flags = buf[0] >> 2,
		.ack = ((buf[0] & 0x3) << 8) | buf[1],
		.num_chunks = buf[2],
	};
}

size_t get_packet_payload(PacketHeader *header, uint8_t *full_data, size_t full_len, uint8_t *payload, size_t payload_len, Error *err) {
	full_data += PACKET_HEADER_SIZE;
	full_len -= PACKET_HEADER_SIZE;
	if(header->flags & PACKET_FLAG_COMPRESSION) {
		// TODO: check lengths and decompression errors
		*err = ERR_NONE;
		return huffman_decompress(full_data, full_len, payload, payload_len);
	}
	memcpy(payload, full_data, payload_len);
	return full_len;
}

Packet *decode(uint8_t *buf, size_t len, Error *err) {
	if(len < PACKET_HEADER_SIZE || len > MAX_PACKET_SIZE) {
		if(err) {
			*err = ERR_INVALID_PACKET;
		}

		return NULL;
	}

	Packet *packet = malloc(sizeof(Packet));
	memset(packet, 0, sizeof(*packet));
	packet->header = decode_packet_header(buf);
	memcpy(packet->data, buf + PACKET_HEADER_SIZE, sizeof(packet->data));
	packet->data_len = len;
	packet->data_decompressed_len = get_packet_payload(&packet->header, buf, len, packet->data_decompressed, sizeof(packet->data_decompressed), err);
	if(*err != ERR_NONE) {
		free_packet(packet);
		return NULL;
	}

	if(packet->header.flags & PACKET_FLAG_CONTROL) {
		packet->kind = PACKET_CONTROL;
		packet->control = decode_control(packet->data_decompressed, packet->data_decompressed_len, &packet->header, err);
	} else {
		packet->kind = PACKET_NORMAL;
		Error chunk_error = fetch_chunks(packet->data_decompressed, packet->data_decompressed_len, packet);
		if(chunk_error != ERR_NONE) {
			if(err) {
				*err = chunk_error;
			}
			free_packet(packet);
			return NULL;
		}
	}

	return packet;
}

Error free_packet(Packet *packet) {
	if(packet->kind == PACKET_NORMAL) {
		for(size_t i = 0; i < MAX_CHUNKS; i++) {
			free(packet->chunks[i].msg.unused);
		}
	}
	free(packet);
	return ERR_NONE;
}
