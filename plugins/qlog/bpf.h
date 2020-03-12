#include "memory.h"
#include "util.h"

#include "../helpers.h"
#include "picoquic_internal.h"

#define QLOG_OPAQUE_ID 0x00

#define QLOG_VANTAGE_POINT_CLIENT "client"
#define QLOG_VANTAGE_POINT_SERVER "server"
#define QLOG_VERSION "draft-01"
#define QLOG_N_EVENT_FIELDS 6
#define QLOG_EVENT_FIELDS {"relative_time", "category", "event_type", "trigger", "context", "data"}
#define QLOG_N_END_CHARS 4
#define QLOG_END_CHARS "]}]}"

typedef struct st_qlog_ctx_t {
    char *ctx;
    struct st_qlog_ctx_t *next;
} qlog_ctx_t;

typedef struct st_qlog_event_t {
    uint64_t reference_time;
    char *fields[QLOG_N_EVENT_FIELDS - 1];
    struct st_qlog_event_t *next;
} qlog_event_t;

typedef struct st_qlog_frames_t {
    char *frame;
    size_t frame_len;
    struct st_qlog_frames_t *next;
} qlog_frames_t;

typedef struct st_qlog_header_t {
    char *title;
    char *description;
    char *vantage_point;
    picoquic_connection_id_t odcid;
    uint64_t reference_time;
    char *event_fields[QLOG_N_EVENT_FIELDS];
} qlog_hdr_t;

typedef struct st_qlog_t {
    int fd;
    qlog_hdr_t hdr;
    qlog_event_t *head;
    qlog_event_t *tail;
    qlog_ctx_t *top;
    qlog_frames_t *frames_head;
    qlog_frames_t *frames_tail;
    bool wrote_hdr;
    bool wrote_event;
    picoquic_packet_header pkt_hdr;
} qlog_t;

static __attribute__((always_inline)) qlog_t* get_qlog_t(picoquic_cnx_t *cnx) {
    qlog_t *bpfd_ptr = (qlog_t *) get_cnx_metadata(cnx, QLOG_OPAQUE_ID);
    if (!bpfd_ptr) {
        bpfd_ptr = (qlog_t *) my_malloc_ex(cnx, sizeof(qlog_t));
        /* TODO Handle NULL */
        my_memset(bpfd_ptr, 0, sizeof(qlog_t));
        bpfd_ptr->fd = -1;
        char *events[QLOG_N_EVENT_FIELDS] = QLOG_EVENT_FIELDS;
        my_memcpy(bpfd_ptr->hdr.event_fields, events, sizeof(events));
        set_cnx_metadata(cnx, QLOG_OPAQUE_ID, (protoop_arg_t) bpfd_ptr);
    }
    return bpfd_ptr;
}

static __attribute__((always_inline)) void push_ctx(picoquic_cnx_t *cnx, qlog_t *q, char *ctx) {
    qlog_ctx_t *e = (qlog_ctx_t *) my_malloc(cnx, sizeof(qlog_ctx_t));
    if (e) {
        e->next = q->top;
        e->ctx = ctx;
        q->top = e;
    }
}

static __attribute__((always_inline)) char * pop_ctx(picoquic_cnx_t *cnx, qlog_t *q) {
    char *ctx = NULL;
    qlog_ctx_t *e = q->top;
    if (e) {
        q->top = e->next;
        ctx = e->ctx;
        my_free(cnx, e);
    }
    return ctx;
}

static __attribute__((always_inline)) char * format_ctx(picoquic_cnx_t *cnx, qlog_t *q) {
    size_t ctx_size = 256;
    char *ctx = (char *) my_malloc(cnx, ctx_size);
    if (!ctx) {
        return NULL;
    }
    size_t ofs = snprintf(ctx, ctx_size, "{");
    qlog_ctx_t *c = q->top;
    while (c && ofs < ctx_size) {
        ofs += snprintf(ctx + ofs, ctx_size - ofs, "%s", c->ctx);
        if ((c = c->next)) {
            ofs += snprintf(ctx + ofs, ctx_size - ofs, ", ");
        }
    }
    if (ofs < ctx_size) {
        ofs += snprintf(ctx + ofs, ctx_size - ofs, "}");
    }
    ctx[ofs] = 0;
    return ctx;
}

static __attribute__((always_inline)) void free_event(picoquic_cnx_t *cnx, qlog_event_t *e) {
    for (int i = 0; i < QLOG_N_EVENT_FIELDS - 1; i++) {
        if (e->fields[i]) {
            my_free(cnx, e->fields[i]);
        }
    }
    my_free(cnx, e);
}

static __attribute__((always_inline)) void append_event(qlog_t *q, uint64_t absolute_time, char **fields) {
    if (q->wrote_hdr || q->wrote_event) {
        lseek(q->fd, -QLOG_N_END_CHARS, SEEK_END);
    }
    uint64_t relative_time = absolute_time - q->hdr.reference_time;
    dprintf(q->fd, "[%" PRIu64 ", ", relative_time);
    for (int i = 0; i < QLOG_N_EVENT_FIELDS - 3; i++) {
        dprintf(q->fd, "\"%s\", ", fields[i]);
    }
    dprintf(q->fd, "%s, %s],", fields[QLOG_N_EVENT_FIELDS - 3], fields[QLOG_N_EVENT_FIELDS - 2]);
    dprintf(q->fd, QLOG_END_CHARS);
    q->wrote_event = true;
}

static void write_header(picoquic_cnx_t *cnx, qlog_t *q) {
    dprintf(q->fd, "{\"qlog_version\": \"%s\", \"title\": \"%s\", \"description\": \"%s\", \"summary\": {}, ", QLOG_VERSION, q->hdr.title, q->hdr.description);
    dprintf(q->fd, "\"traces\": [{\"vantage_point\": {\"type\": \"%s\", \"name\": \"\"}, \"title\": \"%s\", \"description\": \"%s\", ", q->hdr.vantage_point, q->hdr.title, q->hdr.description);
    dprintf(q->fd, "\"events\": []}]}");
    q->wrote_hdr = true;

    while (q->head) {
        qlog_event_t *e = q->head;
        append_event(q, e->reference_time, e->fields);
        q->head = e->next;
        free_event(cnx, e);
    }
}

static void write_trailer(picoquic_cnx_t *cnx, qlog_t *q) {
    lseek(q->fd, -(QLOG_N_END_CHARS + q->wrote_event), SEEK_END);
    char *id_str = my_malloc(cnx, (sizeof(char) * (q->hdr.odcid.id_len * 2)) + sizeof(char));
    if (!id_str) return;
    for (int i = 0; i < q->hdr.odcid.id_len; i ++) {
        snprintf(id_str + (i * 2), 2, "%02x", q->hdr.odcid.id[i]);
    }
    id_str[(q->hdr.odcid.id_len * 2)] = 0;
    dprintf(q->fd, "], \"configuration\": {\"time_offset\": 0, \"time_units\": \"us\"}, \"common_fields\": {\"group_id\": \"%s\", \"ODCID\": \"%s\", ", id_str, id_str);
    dprintf(q->fd, "\"reference_time\": %" PRIu64 "}, \"event_fields\": [", q->hdr.reference_time);
    for (int i = 0; i < QLOG_N_EVENT_FIELDS - 1; i++) {
        dprintf(q->fd, "\"%s\", ", q->hdr.event_fields[i]);
    }
    dprintf(q->fd, "\"%s\"]}]}", q->hdr.event_fields[QLOG_N_EVENT_FIELDS - 1]);

    off_t cur = lseek(q->fd, 0, SEEK_CUR);
    ftruncate(q->fd, cur);
}


static char *ptype(picoquic_packet_type_enum ptype) {
    if (ptype == picoquic_packet_initial)
        return "initial";
    else if (ptype == picoquic_packet_handshake)
        return "handshake";
    else if (ptype == picoquic_packet_0rtt_protected)
        return "zerortt";
    else if (ptype == picoquic_packet_1rtt_protected_phi0 || ptype == picoquic_packet_1rtt_protected_phi1)
        return "onertt";
    else
        return "unknown";
}

static __attribute__((always_inline)) char *sprint_header(picoquic_cnx_t *cnx, qlog_t *qlog) {
    char *hdr_str = (char *) my_malloc(cnx, 300);
    if (!hdr_str) {
        return 0;
    }

    size_t dcid_str_len = (2*qlog->pkt_hdr.dest_cnx_id.id_len) + 1;
    char *dcid_str = (char *) my_malloc(cnx, dcid_str_len);
    if (!dcid_str) {
        goto fail;
    }
    snprintf_bytes(dcid_str, dcid_str_len, (const uint8_t *) &qlog->pkt_hdr.dest_cnx_id.id, qlog->pkt_hdr.dest_cnx_id.id_len);

    if (qlog->pkt_hdr.ptype != picoquic_packet_1rtt_protected_phi0 && qlog->pkt_hdr.ptype != picoquic_packet_1rtt_protected_phi1) {
        char *hdr_format = "{\"packet_number\": \"%" PRIu64 "\", \"packet_size\": %d, \"payload_size\": %d, \"version\": \"%s\", \"dcid\": \"%s\", \"dcil\": \"%d\", \"scid\": \"%s\", \"scil\": \"%d\"}";
        char *version_str = (char *) my_malloc(cnx, 9);
        if (!version_str) {
            my_free(cnx, dcid_str);
            goto fail;
        }
        uint8_t *vn_ptr = (uint8_t *) &qlog->pkt_hdr.vn;
        uint8_t vn[4] = {vn_ptr[3], vn_ptr[2], vn_ptr[1], vn_ptr[0]};
        snprintf_bytes(version_str, 9, (const uint8_t *) vn, sizeof(vn));
        size_t scid_str_len = (2*qlog->pkt_hdr.srce_cnx_id.id_len) + 1;
        char *scid_str = (char *) my_malloc(cnx, scid_str_len);
        if (!scid_str) {
            my_free(cnx, dcid_str);
            my_free(cnx, version_str);
            goto fail;
        }
        snprintf_bytes(scid_str, scid_str_len, (const uint8_t *) &qlog->pkt_hdr.srce_cnx_id.id, qlog->pkt_hdr.srce_cnx_id.id_len);
        PROTOOP_SNPRINTF(cnx, hdr_str, 300, hdr_format, qlog->pkt_hdr.pn, qlog->pkt_hdr.offset + qlog->pkt_hdr.payload_length, qlog->pkt_hdr.payload_length, (protoop_arg_t) version_str, (protoop_arg_t) dcid_str, qlog->pkt_hdr.dest_cnx_id.id_len, (protoop_arg_t) scid_str, qlog->pkt_hdr.srce_cnx_id.id_len);
        my_free(cnx, scid_str);
        my_free(cnx, version_str);
    } else {
        char *hdr_format = "{\"packet_number\": \"%" PRIu64 "\", \"packet_size\": %d, \"payload_size\": %d, \"dcid\": \"%s\"}";
        PROTOOP_SNPRINTF(cnx, hdr_str, 300, hdr_format, qlog->pkt_hdr.pn, qlog->pkt_hdr.offset + qlog->pkt_hdr.payload_length, qlog->pkt_hdr.payload_length, (protoop_arg_t) dcid_str);
    }

    my_free(cnx, dcid_str);
    return hdr_str;
fail:
    my_free(cnx, hdr_str);
    return NULL;
}

static __attribute__((always_inline)) char* sprint_frames(picoquic_cnx_t *cnx, qlog_t *qlog) {
    size_t frame_str_len = 0;
    size_t frame_cnt = 0;
    qlog_frames_t *f = qlog->frames_head;
    while(f) {
        frame_cnt++;
        frame_str_len += f->frame_len;
        f = f->next;
    }
    char *frame_str = NULL;
    if (frame_str_len) {
        frame_str_len += 4 + (4 * frame_cnt);
        frame_str = (char *) my_malloc(cnx, frame_str_len);
        if (!frame_str)
            return NULL;

        strncpy(frame_str, "[", 2);
        size_t consumed = 1;

        f = qlog->frames_head;
        while(f) {
            strncpy(frame_str + consumed, f->frame, f->frame_len);
            consumed += f->frame_len - 1;  // Subtract NULL byte

            if (f->next) {
                strncpy(frame_str + consumed, ", ", 3);
                consumed += 2;
            }

            qlog_frames_t *t = f;
            f = f->next;
            my_free(cnx, t->frame);
            my_free(cnx, t);
        }

        strncpy(frame_str + consumed, "]", 2);
        consumed += 2;

        qlog->frames_head = NULL;
        qlog->frames_tail = NULL;
    }

    return frame_str;
}