#include "../helpers.h"

uint64_t get_set_cnx_fields_loop(picoquic_cnx_t *cnx) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < 500000000; i++) {
        sum += get_cnx(cnx, CNX_AK_START_TIME, 0);
        sum += get_cnx(cnx, CNX_AK_LATEST_PROGRESS_TIME, 0);
        set_cnx(cnx, CNX_AK_START_TIME, 0, 2 * sum + 3 * i);
        set_cnx(cnx, CNX_AK_LATEST_PROGRESS_TIME, 0, 3 * sum / 4 + i);
    }
    return sum;
}