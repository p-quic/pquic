/**
 * SWiF Codec: an open-source sliding window FEC codec in C
 * https://github.com/irtf-nwcrg/swif-codec
 */

#ifndef __SWIF_SYMBOL_H__
#define __SWIF_SYMBOL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
    
/*---------------------------------------------------------------------------*/

/**
 * @brief Take a symbol and add another symbol multiplied by a 
 *        coefficient, e.g. performs the equivalent of: p1 += coef * p2
 * @param[in,out] p1     First symbol (to which coef*p2 will be added)
 * @param[in]     coef2  Coefficient by which the second packet is multiplied
 * @param[in]     p2     Second symbol
 */
void symbol_add_scaled
(void *symbol1, uint8_t coef, void *symbol2, uint32_t symbol_size);

/*---------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __SWIF_SYMBOL_H__ */
