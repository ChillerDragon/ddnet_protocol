# ddnet_huffman_compress

## Syntax

```C
size_t ddnet_huffman_compress(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len, DDNetError *err);
```

applies huffman compression to the given `input`
and stores the compressed result in `output`
this should be applied to the teeworlds packet payload if the `PACKET_FLAG_COMPRESSION` is set
returns the size of the compressed `output`

See also https://chillerdragon.github.io/teeworlds-protocol/06/fundamentals.html#huffman

# ddnet_huffman_decompress

## Syntax

```C
size_t ddnet_huffman_decompress(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len, DDNetError *err);
```

applies huffman decompression to the given `input`
and stores the result in `output`
this should be applied to the teeworlds packet payload if the `PACKET_FLAG_COMPRESSION` is set
returns the size of the decompressed `output`

See also https://chillerdragon.github.io/teeworlds-protocol/06/fundamentals.html#huffman

