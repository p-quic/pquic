/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
#ifndef SWIF_SYMBOL_H
#define SWIF_SYMBOL_H
#define symbol_sub_scaled symbol_add_scaled
#define gf256_add(a, b) (a^b)
#define gf256_sub gf256_add
#include <stdbool.h>

static __attribute__((always_inline)) uint8_t gf256_mul(uint8_t a, uint8_t b, uint8_t **mul)
{ return mul[a][b]; }


static __attribute__((always_inline)) uint8_t gf256_mul_formula(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0 ; i < 8 ; i++) {
        if ((b % 2) == 1) p ^= a;
        b >>= 1;
        bool carry = (a & 0x80) != 0;
        a <<= 1;
        if (carry) {
            a ^= 0x1d;
        }
    }
    return p;
}


/**
 * @brief Take a symbol and add another symbol multiplied by a 
 *        coefficient, e.g. performs the equivalent of: p1 += coef * p2
 * @param[in,out] p1     First symbol (to which coef*p2 will be added)
 * @param[in]     coef  Coefficient by which the second packet is multiplied
 * @param[in]     p2     Second symbol
 */
static __attribute__((always_inline)) void symbol_add_scaled
(void *symbol1, uint8_t coef, void *symbol2, uint32_t symbol_size, uint8_t **mul)
{
    uint8_t *data1 = (uint8_t *) symbol1;
    uint8_t *data2 = (uint8_t *) symbol2; 
    for (uint32_t i=0; i<symbol_size; i++) {
        data1[i] ^= gf256_mul(coef, data2[i], mul);
    }
}

static __attribute__((always_inline)) bool symbol_is_zero(void *symbol, uint32_t symbol_size) {
    uint8_t *data8 = (uint8_t *) symbol;
    uint64_t *data64 = (uint64_t *) symbol;
    for (int i = 0 ; i < symbol_size/8 ; i++) {
        if (data64[i] != 0) return false;
    }
    for (int i = (symbol_size/8)*8 ; i < symbol_size ; i++) {
        if (data8[i] != 0) return false;
    }
    return true;
}



static __attribute__((always_inline)) void symbol_mul
(uint8_t *symbol1, uint8_t coef, uint32_t symbol_size, uint8_t **mul)
{
    for (uint32_t i=0; i<symbol_size; i++) {
        symbol1[i] = gf256_mul(coef, symbol1[i], mul);
    }
}

/*---------------------------------------------------------------------------*/
#endif