#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    TMP_FRAME_BEGIN(cnx, parsed_frame, frame, add_address_frame_t)
        char addr_str[80];
        inet_ntop(frame.ip_vers == 6 ? AF_INET6 : AF_INET, frame.ip_vers == 6 ? (void *) &frame.addr.sin6_addr : (void *) &((struct sockaddr_in*) (&frame.addr))->sin_addr, addr_str, sizeof(addr_str));
        addr_str[sizeof(addr_str) - 1] = 0;
        LOG_EVENT(cnx, "FRAMES", "ADD_ADDRESS_PARSED", "", "{\"ptr\": \"%p\", \"address_id\": %lu, \"ip_vers\": %d, \"address\": \"%s\"}", (protoop_arg_t) parsed_frame, frame.address_id, frame.ip_vers, (protoop_arg_t) addr_str);
    TMP_FRAME_END
    return 0;
}