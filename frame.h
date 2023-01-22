#ifndef H__FRAME
#define H__FRAME

#ifdef __cplusplus
extern "C" {
#else
#    if defined(__STDC__) && ( __STDC_VERSION__ < 199901L )
#        define inline  /* nothing */
#    endif
#endif

#define IP(a,b,c,d)                  \
        (                            \
           (uint_fast32_t)(a) << 24  \
         | (uint_fast32_t)(b) << 16  \
         | (uint_fast32_t)(c) << 8   \
         | (uint_fast32_t)(d)        \
        )

#define MIN_LEN_HEADER_IP4 20u
#define MIN_LEN_HEADER_UDP 8u
#define MIN_LEN_HEADER_TCP 20u

#define OFFSET_ETHER_DST       0u
#define OFFSET_ETHER_SRC       6u
#define OFFSET_ETHER_PROTO     12u
#define OFFSET_ETHER_over      14u

#define OFFSET_IP_TOTAL_LEN    2u
#define OFFSET_IP_TTL          8u
#define OFFSET_IP_PROTO        9u
#define OFFSET_IP_CHECKSUM    10u
#define OFFSET_IP_SRC         12u
#define OFFSET_IP_DST         16u
#define OFFSET_IP_over        20u

#define OFFSET_ARP_OPCODE      6u
#define OFFSET_ARP_SRC_MAC     8u
#define OFFSET_ARP_SRC_IP     14u
#define OFFSET_ARP_DST_MAC    18u
#define OFFSET_ARP_DST_IP     24u

#define LEN_TRP_PSUEDO_HED     12u

#define OFFSET_UDP_SRC          0u
#define OFFSET_UDP_DST          2u
#define OFFSET_UDP_LEN          4u
#define OFFSET_UDP_CHECKSUM     6u

#define OFFSET_TCP_SRC          0u
#define OFFSET_TCP_DST          2u
#define OFFSET_TCP_CHECKSUM    16u

#define GetIP4HeaderLen(p_ip) (4*(p_ip[0] & 0xFu))

#include <stdint.h>
#include <assert.h>

static inline uint_fast16_t Get16(uint8_t const *const p)
{
    return ((uint_fast16_t)(p[0]) << 8) | p[1];
}

static inline void Set16(uint8_t *const p,uint_fast16_t const val)
{
    assert(val <= 0xFFFFu);

    p[0] = val >> 8;
    p[1] = val & 0xFF;
}

static inline uint_fast32_t Get32(uint8_t const *const p)
{
    return ((uint_fast32_t)(p[0]) << 24)
         | ((uint_fast32_t)(p[1]) << 16)
         | ((uint_fast32_t)(p[2]) << 8)
         | p[3];
}

static inline void Set32(uint8_t *const p,uint_fast32_t const val)
{
    assert(val <= 0xFFFFFFFFu);

    p[0] = val >> 24;
    p[1] = (val >> 16) & 0xFF;
    p[2] = (val >> 8) & 0xFF;
    p[3] = val & 0xFF;
}

static inline uint_fast64_t Get48(uint8_t const *const p)
{
    return
           ((uint_fast64_t)(p[0]) << 40)
         | ((uint_fast64_t)(p[1]) << 32)
         | ((uint_fast64_t)(p[2]) << 24)
         | ((uint_fast64_t)(p[3]) << 16)
         | ((uint_fast64_t)(p[4]) << 8)
         | p[5];
}

static inline void Set48(uint8_t *const p,uint_fast64_t const val)
{
    assert(val <= 0xFFFFFFFFFFFFllu);

    p[0] = (val >> 40) & 0xFF;  /* Bitwise AND'ing just to suppress compiler warning */
    p[1] = (val >> 32) & 0xFF;
    p[2] = (val >> 24) & 0xFF;
    p[3] = (val >> 16) & 0xFF;
    p[4] = (val >> 8) & 0xFF;
    p[5] = val & 0xFF;
}


#ifdef __cplusplus
	} /* To close the extern "C" */
#endif


#endif
