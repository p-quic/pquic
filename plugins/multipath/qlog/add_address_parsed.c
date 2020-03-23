#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, add_address_frame_t)
        char addr_str[80];
        inet_ntop(frame.ip_vers == 6 ? AF_INET6 : AF_INET, frame.ip_vers == 6 ? (void *) &frame.addr.sin6_addr : (void *) &((struct sockaddr_in*) (&frame.addr))->sin_addr, addr_str, sizeof(addr_str));
        addr_str[sizeof(addr_str) - 1] = 0;
        char *frame_str = my_malloc(cnx, sizeof(addr_str) + 100);
        if (!frame_str) return 0;
        PROTOOP_SNPRINTF(cnx, frame_str, sizeof(addr_str) + 100, "{\"frame_type\": \"add_address\", \"address_id\": %" PRIu64 ", \"ip_vers\": %d, \"address\": \"%s\"}", frame.address_id, frame.ip_vers, (protoop_arg_t) addr_str);
        helper_log_frame(cnx, frame_str);
        my_free(cnx, frame_str);
    TMP_FRAME_END
    return 0;
}