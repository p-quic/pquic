#include "picoquic.h"
#include "picoquic_internal.h"
#include "getset.h"

#include "../helpers.h"
#include "bpf.h"

/**
 * See PROTOOP_NOPARAM_SCHEDULE_NEXT_STREAM
 */
protoop_arg_t schedule_next_stream(picoquic_cnx_t *cnx) {
    picoquic_stream_head *stream = (picoquic_stream_head *) get_cnx(cnx, AK_CNX_FIRST_STREAM, 0);
    uint64_t cnx_maxdata_remote = get_cnx(cnx, AK_CNX_MAXDATA_REMOTE, 0);
    uint64_t cnx_data_sent = get_cnx(cnx, AK_CNX_DATA_SENT, 0);
    int client_mode = (int) get_cnx(cnx, AK_CNX_CLIENT_MODE, 0);
    uint64_t cnx_max_stream_id_bidir_remote = get_cnx(cnx, AK_CNX_MAX_STREAM_ID_BIDIR_REMOTE, 0);

    picoquic_stream_head *candidate_stream = NULL;
    uint64_t *last_stream_id = get_last_drr_stream_id(cnx);
    bool wrap_around = false;

    PROTOOP_PRINTF(cnx, "first_stream: %p, last_stream_id: %" PRIu64 "\n", (protoop_arg_t) stream, *last_stream_id);

    if (cnx_maxdata_remote > cnx_data_sent) {
        while (stream && (stream = (picoquic_stream_head *) get_stream_head(stream, AK_STREAMHEAD_NEXT_STREAM))) {
            if (get_stream_head(stream, AK_STREAMHEAD_STREAM_ID) >= *last_stream_id) {
                stream = (picoquic_stream_head *) get_stream_head(stream, AK_STREAMHEAD_NEXT_STREAM);
                break;
            }
        }

        if (!stream) {
            wrap_around = stream == NULL;
            stream = (picoquic_stream_head *) get_cnx(cnx, AK_CNX_FIRST_STREAM, 0);
        }
        while (stream) {
            uint64_t stream_maxdata_remote = get_stream_head(stream, AK_STREAMHEAD_MAX_DATA_REMOTE);
            uint64_t stream_sent_offset = get_stream_head(stream, AK_STREAMHEAD_SENT_OFFSET);
            uint64_t stream_id = get_stream_head(stream, AK_STREAMHEAD_STREAM_ID);
            picoquic_stream_data *stream_send_queue = (picoquic_stream_data *) get_stream_head(stream, AK_STREAMHEAD_SEND_QUEUE);
            if ((stream_send_queue != NULL && get_stream_data(stream_send_queue, AK_STREAMDATA_LENGTH) > get_stream_data(stream_send_queue, AK_STREAMDATA_OFFSET) &&
                 stream_sent_offset < stream_maxdata_remote) ||
                (PSTREAM_SEND_FIN(stream) && (stream_sent_offset < stream_maxdata_remote) && !PSTREAM_FIN_SENT(stream)) ||
                (PSTREAM_SEND_RESET(stream) && !PSTREAM_RESET_SENT(stream)) ||
                (PSTREAM_SEND_STOP_SENDING(stream) && !PSTREAM_STOP_SENDING_SENT(stream) && !PSTREAM_FIN_RCVD(stream) && !PSTREAM_RESET_RCVD(stream)))
            {
                /* if the stream is not active yet, verify that it fits under
                 * the max stream id limit */
                /* Check parity */
                if (IS_CLIENT_STREAM_ID(stream_id) == client_mode) {
                    if (stream_id <= cnx_max_stream_id_bidir_remote) {
                        candidate_stream = stream;
                    }
                } else {
                    candidate_stream = stream;
                }

                if (candidate_stream && (get_stream_head(candidate_stream, AK_STREAMHEAD_STREAM_ID) > *last_stream_id || wrap_around)) {
                    PROTOOP_PRINTF(cnx, "Chose stream %" PRIu64 " after %" PRIu64 "\n", get_stream_head(candidate_stream, AK_STREAMHEAD_STREAM_ID), *last_stream_id);
                    *last_stream_id = get_stream_head(candidate_stream, AK_STREAMHEAD_STREAM_ID);
                    break;
                }
            }

            stream = (picoquic_stream_head *) get_stream_head(stream, AK_STREAMHEAD_NEXT_STREAM);

            if (!stream && !wrap_around) {
                PROTOOP_PRINTF(cnx, "wrap_around\n");
                stream = (picoquic_stream_head *) get_cnx(cnx, AK_CNX_FIRST_STREAM, 0);
                wrap_around = true;
            }
        }
    } else if (stream) { // TODO: Motivate the need for this branch
        candidate_stream = stream;
        picoquic_stream_data *stream_send_queue = (picoquic_stream_data *) get_stream_head(stream, AK_STREAMHEAD_SEND_QUEUE);
        if ((stream_send_queue != NULL && get_stream_data(stream_send_queue, AK_STREAMDATA_LENGTH) > get_stream_data(stream_send_queue, AK_STREAMDATA_OFFSET)) &&
            (!PSTREAM_FIN_NOTIFIED(stream) || PSTREAM_FIN_SENT(stream)) &&
            (!PSTREAM_RESET_REQUESTED(stream) || PSTREAM_RESET_SENT(stream)) &&
            (!PSTREAM_STOP_SENDING_REQUESTED(stream) || PSTREAM_STOP_SENDING_SENT(stream))) {
            candidate_stream = NULL;
        }
    }

    PROTOOP_PRINTF(cnx, "final choice is %p (%" PRIu64 ")\n", (protoop_arg_t) candidate_stream, candidate_stream ? get_stream_head(candidate_stream, AK_STREAMHEAD_STREAM_ID) : 0);

    return (protoop_arg_t) candidate_stream;
}
