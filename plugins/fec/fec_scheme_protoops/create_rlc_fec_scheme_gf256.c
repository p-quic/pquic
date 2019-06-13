#include <picoquic.h>
#include <memcpy.h>
#include <memory.h>
#include "../../helpers.h"
#include "rlc_fec_scheme_gf256.h"
#include "../gf256/generated_table_code.c"


static __attribute__((always_inline)) int create_fec_schemes(picoquic_cnx_t *cnx, rlc_gf256_fec_scheme_t *fec_schemes[2]) {
    // TODO: free when error
    PROTOOP_PRINTF(cnx, "CALLED CREATE\n");
    rlc_gf256_fec_scheme_t *fs = my_malloc(cnx, sizeof(rlc_gf256_fec_scheme_t));
    if (!fs)
        return PICOQUIC_ERROR_MEMORY;
    uint8_t **table_mul = my_malloc(cnx, 256*sizeof(uint8_t *));
    if (!table_mul)
        return PICOQUIC_ERROR_MEMORY;
    uint8_t *table_inv = my_malloc(cnx, 256*sizeof(uint8_t));
    if (!table_inv)
        return PICOQUIC_ERROR_MEMORY;
    my_memset(table_inv, 0, 256*sizeof(uint8_t));
    assign_inv(table_inv);
    for (int i = 0 ; i < 256 ; i++) {
        table_mul[i] = my_malloc(cnx, 256 * sizeof(uint8_t));
        if (!table_mul[i])
            return PICOQUIC_ERROR_MEMORY;
        my_memset(table_mul[i], 0, 256*sizeof(uint8_t));
    }
    PROTOOP_PRINTF(cnx, "BEFORE ASSIGN MUL\n");
    assign_mul(table_mul);
    PROTOOP_PRINTF(cnx, "AFTER ASSIGN MUL\n");
    fs->table_mul = table_mul;
    fs->table_inv = table_inv;
    uint8_t **mmul = table_mul;
    uint8_t *inv = table_inv;
    fec_schemes[0] = fs;
    fec_schemes[1] = fs;
    PROTOOP_PRINTF(cnx, "GENERATED TABLE MUL = %p\n", (protoop_arg_t) fs->table_mul);
    PROTOOP_PRINTF(cnx, "MUL[1] = 0x%x, 0x%x, 0x%x ...\n", mmul[1][0], mmul[1][1], mmul[1][2]);
    PROTOOP_PRINTF(cnx, "INV = 0x%x, 0x%x, 0x%x ...\n", (protoop_arg_t) inv[0], (protoop_arg_t)  inv[1], (protoop_arg_t)  inv[2]);
    return 0;
}



protoop_arg_t create_fec_scheme(picoquic_cnx_t *cnx)
{
    rlc_gf256_fec_scheme_t *fs[2];
    PROTOOP_PRINTF(cnx, "BEFORE CREATING\n");
    int ret = create_fec_schemes(cnx, fs);
    PROTOOP_PRINTF(cnx, "DONE CREATING\n");
    if (ret) {
        PROTOOP_PRINTF(cnx, "ERROR CREATING GF256\n");
        return ret;
    }
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) fs[0]);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) fs[1]);
    return 0;
}
