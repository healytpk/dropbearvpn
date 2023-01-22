#ifdef __cplusplus
#error You must use a C compiler to compile this file (not a C++ compiler)
#endif

#include "checksum.h"

#include <assert.h>
#include <stdint.h>

#include "frame.h"     /* Frame Offsets, e.g. OFFSET_UDP_LEN */
#include "abbrev.h"    /* PEND */

static uint_fast32_t SumUp(uint8_t const *p,uint_fast16_t amount_octets)
{
    /* p must be a valid pointer
       amount_octets must be >= 1 */

    assert(p != 0);
    assert(amount_octets != 0);

    uint_fast32_t sum = 0;

    /* First check if there's an odd number of octets */
    if (amount_octets & 1u)
    {
        --amount_octets;
        sum = (uint_fast32_t)(p[amount_octets]) << 8;
    }

    amount_octets /= 2;  /* 16-Bit chunks instead of 8-Bit chunks */

    for ( ; amount_octets--; p += 2)
        sum += Get16(p);

    return sum;
}

uint_fast16_t FinalSum(uint_fast32_t sum)
{
    while (sum & 0xFFFF0000u)
        sum = ((sum & 0xFFFF0000u)>> 16) + (sum & 0xFFFFu);

    sum = ~(unsigned)sum;  /* Use "unsigned" for at least 16-Bit unsigned
                              Don't use "short unsigned" because it might
                              promote to signed int. */

    sum &= 0xFFFFu;

    /* Don't return 0xFFFF if checksum is zero, Wireshark says it's wrong */

    return sum;
}

static void MakeValid_IP4(uint8_t *const p_ip,uint8_t const *const pend)
{
    assert(p_ip != 0);
    assert(pend != 0);
    assert(pend > p_ip);

    assert(pend-p_ip >= MIN_LEN_HEADER_IP4);
    assert(pend-p_ip >= GetIP4HeaderLen(p_ip));

    /* Set the total length field correctly */
    Set16(p_ip + OFFSET_IP_TOTAL_LEN, pend-p_ip);

    /* Now set the checksum field to zero */
    Set16(p_ip + OFFSET_IP_CHECKSUM,0);

    /* Calculate and set the checksum */
    Set16(p_ip + OFFSET_IP_CHECKSUM, FinalSum(SumUp(p_ip, GetIP4HeaderLen(p_ip)))  );
}

uint_fast8_t IsValidIP4(uint8_t *const p_ip, uint8_t const *const pend)
{
    uint_fast32_t const actual_packet_length = pend-p_ip;

    if (actual_packet_length < MIN_LEN_HEADER_IP4)
    {
        ErrPrint("actual_packet_length < MIN_LEN_HEADER_IP4\n");
        return 0;
    }

    if (GetIP4HeaderLen(p_ip) < MIN_LEN_HEADER_IP4)
    {
        ErrPrint("GetIP4HeaderLen(p_ip) < MIN_LEN_HEADER_IP4\n");
        return 0;
    }

    if (actual_packet_length < GetIP4HeaderLen(p_ip))
    {
        ErrPrint("actual_packet_length < GetIP4HeaderLen(p_ip)\n");
        return 0;
    }

    uint_fast16_t const sum = Get16(p_ip + OFFSET_IP_CHECKSUM),
                        len = Get16(p_ip + OFFSET_IP_TOTAL_LEN);

    MakeValid_IP4(p_ip,pend);

    if (sum != Get16(p_ip + OFFSET_IP_CHECKSUM))
    {
        ErrPrint("sum != Get16(p_ip + OFFSET_IP_CHECKSUM)\n");
        return 0;
    }

    if (len != Get16(p_ip + OFFSET_IP_TOTAL_LEN))
    {
        ErrPrint("len != Get16(p_ip + OFFSET_IP_TOTAL_LEN\n");
        return 0;
    }

    return 1;
}

typedef struct TrpPsuedoHeader {
    uint_fast32_t src_ip, dst_ip;
    uint_fast16_t proto;
    uint_fast16_t seg_len;
} TrpPsuedoHeader;

static uint_fast32_t SumUp_PsuedoHeader(TrpPsuedoHeader const *const p)
{
    /* In order to calculate checksum, a psuedo-header consisting
       of 12 bytes must be added:
        1: Source IP address (4 bytes)
           Destination IP address (4 bytes)
        2: Protocol (e.g. 0x0011 for UDP) (2 bytes)
        3: Segment length (2 bytes)                    */

    uint8_t data[12];

    Set32(data + 0, p->src_ip);
    Set32(data + 4, p->dst_ip);
    Set16(data + 8, p->proto);
    Set16(data + 10, p->seg_len);

    return SumUp(data,12);
}

static void MakeValid_IP4_UDP(uint8_t *const p_ip,uint8_t const *const pend)
{
    assert(p_ip != 0);
    assert(pend != 0);
    assert(pend > p_ip);

    assert(pend-p_ip >= MIN_LEN_HEADER_IP4 + MIN_LEN_HEADER_UDP);
    assert(GetIP4HeaderLen(p_ip) >= MIN_LEN_HEADER_IP4);
    assert(pend-p_ip >= GetIP4HeaderLen(p_ip) + MIN_LEN_HEADER_UDP);
    assert(p_ip[OFFSET_IP_PROTO] == 0x11u);

    uint8_t *const p_trp = p_ip + GetIP4HeaderLen(p_ip);

    uint_fast16_t const octets_in_segment = pend-p_trp;

    assert(octets_in_segment >= MIN_LEN_HEADER_UDP);

    Set16(p_trp + OFFSET_UDP_LEN, octets_in_segment); /* Set the segment length */

    TrpPsuedoHeader hdr;
    hdr.src_ip = Get32(p_ip+OFFSET_IP_SRC);
    hdr.dst_ip = Get32(p_ip+OFFSET_IP_DST);
    hdr.proto = 0x11;  /* For UDP */
    hdr.seg_len = octets_in_segment;

    /* First zero out the checksum bits! */
    Set16(p_trp+OFFSET_UDP_CHECKSUM,0);

    Set16(p_trp + OFFSET_UDP_CHECKSUM,
         FinalSum(
                       SumUp(p_trp,octets_in_segment) + SumUp_PsuedoHeader(&hdr)
                 )
         );
}

uint_fast8_t IsValidIP4_UDP(uint8_t *const p_ip, uint8_t const *const pend)
{
    /* A validity check has already been performed on the IPv4 portion */

    assert(p_ip[OFFSET_IP_PROTO] == 0x11u);

    uint_fast32_t const actual_packet_length = pend-p_ip;

    if (actual_packet_length < (MIN_LEN_HEADER_IP4 + MIN_LEN_HEADER_UDP))
    {
        ErrPrint("actual_packet_length < (MIN_LEN_HEADER_IP4 + MIN_LEN_HEADER_UDP)\n");
        return 0;
    }

    uint_fast16_t const actual_segment_length = actual_packet_length - GetIP4HeaderLen(p_ip);

    if (actual_segment_length < MIN_LEN_HEADER_UDP)
    {
        ErrPrint("actual_segment_length < MIN_LEN_HEADER_UDP\n");
        return 0;
    }

    uint8_t *const p_trp = p_ip + GetIP4HeaderLen(p_ip);

    uint_fast16_t const sum = Get16(p_trp + OFFSET_UDP_CHECKSUM),
                        len = Get16(p_trp + OFFSET_UDP_LEN);

    MakeValid_IP4_UDP(p_ip,pend);

    if (sum != Get16(p_trp + OFFSET_UDP_CHECKSUM))
    {
        ErrPrint("sum != Get16(p_trp + OFFSET_UDP_CHECKSUM)\n");
        return 0;
    }

    if (len != Get16(p_trp + OFFSET_UDP_LEN))
    {
        ErrPrint("len != Get16(p_trp + OFFSET_UDP_LEN)\n");
        return 0;
    }

    return 1;
}

static void MakeValid_IP4_TCP(uint8_t *const p_ip, uint8_t const *const pend)
{
    assert(p_ip != 0);
    assert(pend != 0);
    assert(pend > p_ip);

    assert(pend-p_ip >= MIN_LEN_HEADER_IP4 + MIN_LEN_HEADER_TCP);
    assert(GetIP4HeaderLen(p_ip) >= MIN_LEN_HEADER_IP4);
    assert(pend-p_ip >= GetIP4HeaderLen(p_ip) + MIN_LEN_HEADER_TCP);
    assert(p_ip[OFFSET_IP_PROTO] == 0x06u);

    uint8_t *const p_trp = p_ip + GetIP4HeaderLen(p_ip);

    uint_fast16_t const octets_in_segment = pend-p_trp;

    assert(octets_in_segment >= MIN_LEN_HEADER_TCP);

    TrpPsuedoHeader hdr;
    hdr.src_ip = Get32(p_ip+OFFSET_IP_SRC);
    hdr.dst_ip = Get32(p_ip+OFFSET_IP_DST);
    hdr.proto = 0x06;  /* For TCP */
    hdr.seg_len = octets_in_segment;

    /* First zero out the checksum bits! */
    Set16(p_trp+OFFSET_TCP_CHECKSUM,0);

    Set16(p_trp + OFFSET_TCP_CHECKSUM,
         FinalSum(
                       SumUp(p_trp,octets_in_segment) + SumUp_PsuedoHeader(&hdr)
                 )
         );
}

uint_fast8_t IsValidIP4_TCP(uint8_t *const p_ip, uint8_t const *const pend)
{
    /* A validity check has already been performed on the IPv4 portion */

    assert(p_ip[OFFSET_IP_PROTO] == 0x06u);

    uint_fast32_t const actual_packet_length = pend - p_ip;

    if (actual_packet_length < (MIN_LEN_HEADER_IP4 + MIN_LEN_HEADER_TCP))
    {
        ErrPrint("actual_packet_length < (MIN_LEN_HEADER_IP4 + MIN_LEN_HEADER_TCP)\n");
        return 0;
    }

    uint_fast16_t const actual_segment_length = actual_packet_length - GetIP4HeaderLen(p_ip);

    if (actual_segment_length < MIN_LEN_HEADER_TCP)
    {
        ErrPrint("actual_segment_length < MIN_LEN_HEADER_TCP\n");
        return 0;
    }

    uint8_t *const p_trp = p_ip + GetIP4HeaderLen(p_ip);

    uint_fast16_t const sum = Get16(p_trp + OFFSET_TCP_CHECKSUM);

    MakeValid_IP4_TCP(p_ip,pend);

    if (sum != Get16(p_trp + OFFSET_TCP_CHECKSUM))
    {
        ErrPrint("sum != Get16(p_trp + OFFSET_TCP_CHECKSUM)\n");
        return 0;
    }

    return 1;
}

void MakeValid_IP4_Transport(uint8_t *const p_ip, uint8_t const *const pend)
{
    assert(GetIP4HeaderLen(p_ip) >= MIN_LEN_HEADER_IP4);
    assert(pend-p_ip >= (GetIP4HeaderLen(p_ip) + MIN_LEN_HEADER_UDP));  /* UDP is the smaller one */

    /* Calculate Segment Checksum (and also set length for UDP) */

    switch (p_ip[OFFSET_IP_PROTO])
    {
    case 0x11:

        /* UDP */
        MakeValid_IP4_UDP(p_ip,pend);
        break;

    case 0x06:

        /* TCP */
        assert(pend-p_ip >= (GetIP4HeaderLen(p_ip) + MIN_LEN_HEADER_TCP));
        MakeValid_IP4_TCP(p_ip,pend);
        break;

    default:

        assert("Shouldn't be here!" == 0);
    }


    /* Calculate IP header checksum and length */
    MakeValid_IP4(p_ip,pend);  /* Must be done last */
}
