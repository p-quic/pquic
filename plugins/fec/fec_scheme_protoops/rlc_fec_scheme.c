#include <picoquic_internal.h>
#include "../gmp/mini-gmp.c"
#include "../fec.h"
#include "../../helpers.h"
#include "../prng/tinymt32.c"


static __attribute__((always_inline)) void print_bignum(picoquic_cnx_t *cnx, mpz_t bn) {
    uint8_t *array = my_malloc(cnx, 1500);
    uint64_t count;
    int i;
    mpz_export(array, &count, 1, 1, bn);
    PROTOOP_PRINTF(cnx, "COUNT = %u\n", (protoop_arg_t) count);
    for (i = 0 ; i < count ; i++){
        PROTOOP_PRINTF(cnx, "ARRAY[] = %u\n", array[i]);
    }
    my_free(cnx, array);
}


/*******
Function that performs Gauss-Elimination and returns the Upper triangular matrix:
There are two options to do this in C.
1. Pass a matrix (a) as the parameter, and calculate and store the upperTriangular(Gauss-Eliminated Matrix) in it.
2. Use malloc and make the function of pointer type and return the pointer.
This program uses the first option.
********/
static __attribute__((always_inline)) void gaussElimination(picoquic_cnx_t *cnx, int m, int n, mpz_t **a, mpz_t x[m]){
    mpz_t *tmps = my_malloc(cnx, 4*sizeof(mpz_t));
    if (!tmps) {
        PROTOOP_PRINTF(cnx, "NOT ENOUGH MEMORY\n");
    }
    #define mulnum (tmps)
    #define muldenom (&tmps[1])
    #define tmp (&tmps[2])
    #define tmp2 (&tmps[3])
    mpz_init(cnx, *mulnum);
    mpz_init(cnx, *muldenom);
    mpz_init(cnx, *tmp);
    mpz_init(cnx, *tmp2);
    int i,j,k;
    for(i=0;i<m-1;i++){
        for(k=i+1;k<m;k++){
            //If diagonal element(absolute value) is smaller than any of the terms below it
            if(mpz_cmpabs(a[i][i], a[k][i]) < 0){
                //Swap the rows
                for(j=0;j<n;j++){
                    mpz_swap(a[i][j], a[k][j]);
                }
            }
        }
        for(k=i+1;k<m;k++){
            uint8_t first = 1;
            if(k > i){
                for(j=0;j<n;j++){
                    // i < m-1 AND m <= n, -> i < n-1
                    // term=a[k][i]/a[i][i]
                    if (first) {
                        mpz_set(*mulnum, a[k][i]);
                        mpz_set(*muldenom, a[i][i]);
                        first = 0;
                    }
                    mpz_mul(*tmp, a[k][j], *muldenom);    // set a[k][j] at the common denominator
                    mpz_mul(*tmp2, a[i][j], *mulnum);              // tmp2 = a[k][j]->denom * mulnum, but a[k][j]->denom == 1
                    mpz_sub(a[k][j], *tmp, *tmp2);
                }
            }
        }
    }
    //Begin Back-substitution
    for(i=m-1;i>=0;i--){
        mpz_set(x[i], a[i][n-1]);
        for(j=i+1;j<n-1;j++){
//             x[i]=x[i]-a[i][j]*x[j];
            mpz_mul(*tmp, a[i][j], x[j]);
            mpz_sub(x[i], x[i], *tmp);
        }
        // a[i][i] = small
        if (mpz_cmp_ui(x[i], 0) == 0 || mpz_cmp_ui(a[i][i], 0) == 0) {
            // this solution is undetermined
            // TODO
            PROTOOP_PRINTF(cnx, "UNDETERMINED SOL\n");
        } else {
            if (mpz_sgn(x[i]) < 0 && mpz_sgn(a[i][i]) < 0) {
                mpz_abs(x[i], x[i]);
                mpz_abs(a[i][i], a[i][i]);
            }
            mpz_fdiv_q(x[i], x[i], a[i][i]);
        }
    }
    mpz_clear(*mulnum);
    mpz_clear(*muldenom);
    mpz_clear(*tmp);
    mpz_clear(*tmp2);
    my_free(cnx, tmps);
#undef mulnum
#undef muldenom
#undef tmp
#undef tmp2
}

static __attribute__((always_inline)) void get_coefs(picoquic_cnx_t *cnx, tinymt32_t *prng, uint32_t seed, int n, uint8_t *coefs) {
    tinymt32_init(prng, seed);
    int i;
    for (i = 0 ; i < n ; i++) {
        coefs[i] = (uint8_t) tinymt32_generate_uint32(prng);
        if (coefs[i] == 0)
            coefs[i] = 1;
    }
}

/**
 * fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
 *
 * Output: return code (int)
 */
protoop_arg_t fec_recover(picoquic_cnx_t *cnx)
{
    fec_block_t *fec_block = (fec_block_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    PROTOOP_PRINTF(cnx, "TRYING TO RECOVER SYMBOLS WITH RLC FOR BLOCK %u !\n", fec_block->fec_block_number);
    if (fec_block->total_repair_symbols == 0 || fec_block->current_source_symbols == fec_block->total_source_symbols ||
        fec_block->current_source_symbols + fec_block->current_repair_symbols < fec_block->total_source_symbols) {
        PROTOOP_PRINTF(cnx, "NO RECOVERY TO DO\n");
        return 0;
    }
    tinymt32_t *prng = my_malloc(cnx, sizeof(tinymt32_t));
    prng->mat1 = 0x8f7011ee;
    prng->mat2 = 0xfc78ff1f;
    prng->tmat = 0x3793fdff;

    PROTOOP_PRINTF(cnx, "RECOVERING\n");
    int n_unknowns = fec_block->total_source_symbols - fec_block->current_source_symbols;
    int n_eq = fec_block->current_repair_symbols;
    int i = 0;
    int j;
    uint8_t *coefs = my_malloc(cnx, fec_block->total_source_symbols*sizeof(uint8_t));//[fec_block->total_source_symbols];
    mpz_t *knowns = my_malloc(cnx, fec_block->current_source_symbols*sizeof(mpz_t));//[fec_block->current_source_symbols];
    mpz_t *unknowns = my_malloc(cnx, (n_unknowns)*sizeof(mpz_t));;//[n_unknowns];
    mpz_t **system = my_malloc(cnx, n_eq*sizeof(mpz_t *));;//[n_eq][n_unknowns + 1];
    mpz_t *tmp = my_malloc(cnx, sizeof(mpz_t));


    if (!coefs || !knowns || !unknowns || !system || !tmp) {
        PROTOOP_PRINTF(cnx, "NOT ENOUGH MEM\n");
    }
    mpz_init(cnx, *tmp);

    for (j = 0 ; j < n_eq ; j++) {
        system[j] = NULL;
        system[j] = my_malloc(cnx, (n_unknowns + 1) * sizeof(mpz_t));
        if (!system[j]) {
            PROTOOP_PRINTF(cnx, "NOT ENOUGH MEM\n");
        }
    }

    for (j = 0 ; j < n_unknowns ; j++) {
        mpz_init(cnx, unknowns[j]);
    }

    int current_known = 0;
    source_symbol_t *ss;
    for_each_source_symbol(fec_block, ss) {
        if (ss) {
            mpz_init(cnx, knowns[current_known]);
            mpz_import(knowns[current_known++], ss->data_length, 1, 1, ss->data);
        }
    }

    int idx = 0;
    int first_notnull_rs = -1;
    // building the system, equation by equation
    i = 0;
    repair_symbol_t *rs;
    for_each_repair_symbol(fec_block, rs) {
        if (rs) {
            if (first_notnull_rs == -1) first_notnull_rs = idx;
            mpz_init(cnx, system[i][n_unknowns]);
            mpz_import(system[i][n_unknowns], rs->data_length, 1, 1, rs->data);
            get_coefs(cnx, prng, (rs->repair_fec_payload_id.source_fpid.raw), fec_block->total_source_symbols, coefs);
            int current_unknown = 0;
            int current_known = 0;
            for (j = 0 ; j < fec_block->total_source_symbols ; j++) {
                if (fec_block->source_symbols[j]) {
                    mpz_mul_ui(*tmp, knowns[current_known++], coefs[j]);
                    mpz_sub(system[i][n_unknowns], system[i][n_unknowns], *tmp);
                } else if (current_unknown < n_unknowns) {
                    mpz_init_set_ui(cnx, system[i][current_unknown++], coefs[j]);
                }
            }
            i++;
        }
        idx++;
    }

    for (j = 0 ; j < fec_block->current_source_symbols ; j++) {
        mpz_clear(knowns[j]);
    }
    mpz_clear(*tmp);
    my_free(cnx, tmp);

    // the system is built: let's recover it
    gaussElimination(cnx, n_eq, n_unknowns+1, system, unknowns);
    int current_unknown = 0;
    for (j = 0 ; j < fec_block->total_source_symbols ; j++) {
        if (!fec_block->source_symbols[j] && mpz_cmp_ui(unknowns[current_unknown], 0) != 0) {
            // TODO: handle the case where source symbols could be 0
            ss = malloc_source_symbol(cnx, (source_fpid_t) ((fec_block->fec_block_number << 8) + ((uint8_t)j)), fec_block->repair_symbols[first_notnull_rs]->data_length);
            if (!ss) {
                mpz_clear(unknowns[current_unknown++]);
                continue;
            }
            uint64_t count;
            mpz_export(ss->data, &count, 1, 1, unknowns[current_unknown]);
            ss->data_length = (uint16_t) count;
            fec_block->source_symbols[j] = ss;
            fec_block->current_source_symbols++;
            mpz_clear(unknowns[current_unknown++]);
        }
    }

    // free the system
    for (i = 0 ; i < n_eq ; i++) {
        for (j = 0 ; j < n_unknowns + 1 ; j++) {
            mpz_clear(system[i][j]);
        }
        my_free(cnx, system[i]);
    }
    my_free(cnx, prng);
    my_free(cnx, system);
    my_free(cnx, unknowns);
    my_free(cnx, knowns);
    my_free(cnx, coefs);

    return 0;
}
