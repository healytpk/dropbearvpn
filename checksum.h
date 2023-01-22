#ifndef H__CHECKSUM
#define H__CHECKSUM

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void MakeValid_IP4_Transport(uint8_t *const p_ip, uint8_t const *const pend);

uint_fast8_t IsValidIP4(uint8_t *const p_ip, uint8_t const *const pend);
uint_fast8_t IsValidIP4_UDP(uint8_t *const p_ip, uint8_t const *const pend);
uint_fast8_t IsValidIP4_TCP(uint8_t *const p_ip, uint8_t const *const pend);


#ifdef __cplusplus
	} /* To close the extern "C" */
#endif

#endif
