/*
 * Basic functions for packing and unpacking data.
 */
#ifndef __BASIC_PACKING_H__
#define __BASIC_PACKING_H__

static inline void pack_uint16_little (uint8_t dst[static 2], uint16_t src)
{
	dst[0] = (uint8_t)(src >>  0);
	dst[1] = (uint8_t)(src >>  8);
}


static inline void pack_uint32_little (uint8_t dst[static 4], uint32_t src)
{
	dst[0] = (uint8_t)(src >>  0);
	dst[1] = (uint8_t)(src >>  8);
	dst[2] = (uint8_t)(src >> 16);
	dst[3] = (uint8_t)(src >> 24);
}


static inline void pack_uint64_little (uint8_t dst[static 8], uint64_t src)
{
	dst[0] = (uint8_t)(src >>  0);
	dst[1] = (uint8_t)(src >>  8);
	dst[2] = (uint8_t)(src >> 16);
	dst[3] = (uint8_t)(src >> 24);
	dst[4] = (uint8_t)(src >> 32);
	dst[5] = (uint8_t)(src >> 40);
	dst[6] = (uint8_t)(src >> 48);
	dst[7] = (uint8_t)(src >> 56);
}


static inline void pack_uint32_big (uint8_t dst[static 4], uint32_t src)
{
	dst[0] = (uint8_t)(src >> 24);
	dst[1] = (uint8_t)(src >> 16);
	dst[2] = (uint8_t)(src >>  8);
	dst[3] = (uint8_t)(src >>  0);
}


static inline uint16_t unpack_uint16_little (uint8_t const src[static 2])
{
	return (uint16_t)(
	         ((uint16_t)(src[0]) <<  0)
	       | ((uint16_t)(src[1]) <<  8)
	       );
}


static inline uint32_t unpack_uint32_little (uint8_t const src[static 4])
{
	return   ((uint32_t)(src[0]) <<  0)
	       | ((uint32_t)(src[1]) <<  8)
	       | ((uint32_t)(src[2]) << 16)
	       | ((uint32_t)(src[3]) << 24);
}


static inline uint64_t unpack_uint64_little (uint8_t const src[static 8])
{
	return   ((uint64_t)(src[0]) <<  0)
	       | ((uint64_t)(src[1]) <<  8)
	       | ((uint64_t)(src[2]) << 16)
	       | ((uint64_t)(src[3]) << 24)
	       | ((uint64_t)(src[4]) << 32)
	       | ((uint64_t)(src[5]) << 40)
	       | ((uint64_t)(src[6]) << 48)
	       | ((uint64_t)(src[7]) << 56);
}

#endif
