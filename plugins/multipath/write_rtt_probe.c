#include "bpf.h"

/**
 * See PROTOOP_PARAM_WRITE_FRAME
 */
protoop_arg_t write_rtt_probe(picoquic_cnx_t *cnx)  // TODO: What happens if the path disappears ?
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    uint8_t selected_path = (uint8_t) get_cnx(cnx, AK_CNX_INPUT, 2);
    int ret = 0;
    size_t consumed = 0;

    bpf_data *bpfd = get_bpf_data(cnx);
    if (bpfd->last_uniflow_index_sent != selected_path) {
        uniflow_data_t *ud = bpfd->sending_uniflows[selected_path];
        if (ud->rtt_probe_ready) {
            ud->rtt_probe_tries++;
        } else {
            ud->rtt_probe_ready = true;
        }
        PROTOOP_PRINTF(cnx, "RTT probe ready to be sent for sending uniflow %d, try %d\n", selected_path, ud->rtt_probe_tries);
        if (ud->rtt_probe_tries >= 3) {
            PROTOOP_PRINTF(cnx, "Too many tries for the probe for sending uniflow %d, drop it\n", selected_path);
            ud->rtt_probe_ready = false;
            ret = 0;
            consumed = 0;
        } else {
            ret = PICOQUIC_MISCCODE_RETRY_NXT_PKT;
            helper_cnx_set_next_wake_time(cnx, picoquic_current_time());
        }
    } else {
        uniflow_data_t *ud = bpfd->sending_uniflows[selected_path];
        my_memset(bytes, picoquic_frame_type_ping, 1);
        my_memset(bytes + 1, picoquic_frame_type_padding, bytes_max - (bytes + 1));
        ud->rtt_probe_ready = false;

        /* PROTOOP_PRINTF(cnx, "Wrote a %" PRIu64 "-byte long RTT probe for path %d\n", bytes_max - bytes, selected_path); */
        consumed = bytes_max - bytes;
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
    return (protoop_arg_t) ret;
}