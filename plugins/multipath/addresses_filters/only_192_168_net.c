#include "../bpf.h"

protoop_arg_t protoop_accept_addr(picoquic_cnx_t *cnx) {
    struct sockaddr_storage *t = (struct sockaddr_storage *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint32_t if_index = get_cnx(cnx, AK_CNX_INPUT, 1);
    struct sockaddr_storage sa;
    my_memcpy(&sa, t, sizeof(struct sockaddr_storage));
    if (sa.ss_family == AF_INET) {
        struct sockaddr_in *sai4 = (struct sockaddr_in *) &sa;
        in_addr_t a = sai4->sin_addr.s_addr;
        return (a & 0x0000FFFF) == 0xA8C0;
    } else if (sa.ss_family == AF_INET6) {
        return false;
    }
    return false;
}