#include <stdint.h>

typedef struct {
    uint8_t **table_mul;
    uint8_t *table_inv;
} rlc_gf256_fec_scheme_t;
