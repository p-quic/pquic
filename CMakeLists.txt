CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(picoquic)
SET(CMAKE_C_STANDARD 11)

# FIND_PACKAGE(PkgConfig REQUIRED)

SET(CMAKE_C_FLAGS "-std=gnu99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

SET(GCC_COVERAGE_LINK_FLAGS    "-Wl,--no-as-needed,-lprofiler,--as-needed")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

if($ENV{DISABLE_DEBUG_PRINTF})
    SET(CMAKE_C_FLAGS "-DDISABLE_DEBUG_PRINTF ${CMAKE_C_FLAGS}")
endif()

if($ENV{DISABLE_QLOG})
    SET(CMAKE_C_FLAGS "-DDISABLE_QLOG ${CMAKE_C_FLAGS}")
endif()

INCLUDE_DIRECTORIES(picoquic picoquictest ../picotls/include
    ${PICOTLS_INCLUDE_DIR})

SET(PICOQUIC_LIBRARY_FILES
    picoquic/cubic.c
    picoquic/endianness.c
    picoquic/fnv1a.c
    picoquic/frames.c
    picoquic/getset.c
    picoquic/http0dot9.c
    picoquic/intformat.c
    picoquic/logger.c
    picoquic/memory.c
    picoquic/memcpy.c
    picoquic/newreno.c
    picoquic/packet.c
    picoquic/picohash.c
    picoquic/picosocks.c
    picoquic/picosplay.c
    picoquic/plugin.c
    picoquic/protoop.c
    picoquic/queue.c
    picoquic/quicctx.c
    picoquic/sacks.c
    picoquic/sender.c
    picoquic/ticket_store.c
    picoquic/tls_api.c
    picoquic/transport.c
    picoquic/ubpf.c
    picoquic/util.c
)

SET(PICOQUIC_TEST_LIBRARY_FILES
    picoquictest/ack_of_ack_test.c
    picoquictest/cleartext_aead_test.c
    picoquictest/cnx_creation_test.c
    picoquictest/float16test.c
    picoquictest/fnv1atest.c
    picoquictest/hashtest.c
    picoquictest/http0dot9test.c
    picoquictest/intformattest.c
    picoquictest/parseheadertest.c
    picoquictest/pn2pn64test.c
    picoquictest/sacktest.c
    picoquictest/skip_frame_test.c
    picoquictest/sim_link.c
    picoquictest/socket_test.c
    picoquictest/splay_test.c
    picoquictest/stream0_frame_test.c
    picoquictest/stresstest.c
    picoquictest/ticket_store_test.c
    picoquictest/tls_api_test.c
    picoquictest/transport_param_test.c
    picoquictest/datagram.c
    picoquictest/microbench.c
)

SET(PLUGINS_DATAGRAM
    plugins/datagram/parse_datagram_frame.c
    plugins/datagram/send_datagram.c
    plugins/datagram/process_datagram_frame.c
    plugins/datagram/is_datagram_frame_congestion_controlled.c
    plugins/datagram/write_datagram_frame.c
    plugins/datagram/get_datagram_socket.c
    plugins/datagram/cnx_state_changed.c
    plugins/datagram/process_datagram_buffer.c
)

SET(PLUGINS_COP2
    plugins/cop2/cnx_state_changed.c
    plugins/cop2/packet_received.c
    plugins/cop2/packet_sent.c
    plugins/cop2/rtt_updated.c
    plugins/cop2/check_ooo_stream_frame.c
    plugins/cop2/check_spurious_stream_frame.c
    plugins/cop2/packet_lost.c
    plugins/cop2/fast_retransmit.c
    plugins/cop2/retransmission_timeout.c
    plugins/cop2/tail_loss_probe.c
    plugins/cop2/stream_opened.c
    plugins/cop2/stream_closed.c
)

SET(PLUGINS_MULTIPATH
    plugins/multipath/connection_state_changed.c
    plugins/multipath/get_destination_connection_id.c
    plugins/multipath/get_incoming_path.c
    plugins/multipath/parse_add_address_frame.c
    plugins/multipath/parse_mp_ack_frame.c
    plugins/multipath/parse_mp_new_connection_id_frame.c
    plugins/multipath/predict_packet_header_length.c
    plugins/multipath/process_mp_ack_frame.c
    plugins/multipath/process_mp_new_connection_id_frame.c
    plugins/multipath/process_possible_ack_of_ack_frame.c
    plugins/multipath/set_next_wake_time.c
    plugins/multipath/write_add_address_frame.c
    plugins/multipath/write_mp_ack_frame.c
    plugins/multipath/write_mp_new_connection_id_frame.c
    plugins/multipath/write_rtt_probe.c
    plugins/multipath/path_schedulers/schedule_path_rr.c
    plugins/multipath/path_schedulers/schedule_path_rtt.c
    plugins/multipath/path_schedulers/schedule_frames.c
    plugins/multipath/qlog/mp_ack_frame_parsed.c
    plugins/multipath/qlog/mp_new_connection_id_frame_parsed.c
    plugins/multipath/qlog/add_address_parsed.c
    plugins/multipath/qlog/path_update_parsed.c
    plugins/multipath/path_manager.c
    plugins/multipath/notify_path_update.c
    plugins/multipath/parse_path_update.c
    plugins/multipath/process_path_update.c
    plugins/multipath/write_path_update.c
    plugins/multipath/addresses_filters/no_v6_no_10.c
)

SET(PLUGINS_STREAM_SCHEDULER
    plugins/stream_scheduling_rr/stream_scheduling_rr.c
)

SET(PLUGINS_QLOG
    plugins/qlog/cnx_state_changed.c
    plugins/qlog/set_output_file.c
    plugins/qlog/log_event.c
    plugins/qlog/frames/stream_opened.c
    plugins/qlog/frames/stream_flags_changed.c
    plugins/qlog/frames/reset_stream_frame_parsed.c
    plugins/qlog/frames/new_connection_id_parsed.c
    plugins/qlog/frames/new_token_frame_parsed.c
    plugins/qlog/frames/stop_sending_parsed.c
    plugins/qlog/frames/crypto_frame_parsed.c
    plugins/qlog/frames/ack_frame_parsed.c
    plugins/qlog/frames/is_ack_needed.c
    plugins/qlog/frames/connection_close_parsed.c
    plugins/qlog/frames/application_close_parsed.c
    plugins/qlog/frames/max_data_parsed.c
    plugins/qlog/frames/max_stream_data_parsed.c
    plugins/qlog/frames/path_challenge_created.c
    plugins/qlog/frames/path_response_parsed.c
    plugins/qlog/frames/blocked_frame_parsed.c
    plugins/qlog/frames/stream_blocked_frame_parsed.c
    plugins/qlog/frames/stream_id_blocked_frame_parsed.c
    plugins/qlog/frames/padding_or_ping_parsed.c
    plugins/qlog/sender/retransmit_needed_by_packet.c
    plugins/qlog/sender/retransmit_needed.c
    plugins/qlog/sender/congestion_algorithm_notified.c
    plugins/qlog/sender/ready_stream.c
    plugins/qlog/sender/next_stream_scheduled.c
    plugins/qlog/push_log_context.c
    plugins/qlog/pop_log_context.c
        plugins/qlog/sender/next_wake_time.c)

FIND_LIBRARY(PTLS_CORE picotls-core PATH ../picotls)
MESSAGE(STATUS "Found picotls-core at : ${PTLS_CORE} " )

FIND_LIBRARY(PTLS_MINICRYPTO picotls-minicrypto PATH ../picotls)
MESSAGE(STATUS "Found picotls-crypto at : ${PTLS_MINICRYPTO} " )

FIND_LIBRARY(PTLS_OPENSSL picotls-openssl PATH ../picotls)
MESSAGE(STATUS "Found picotls-openssl at : ${PTLS_OPENSSL} " )

FIND_LIBRARY(UBPF ubpf PATH ubpf/vm)
MESSAGE(STATUS "Found ubpf at : ${UBPF} " )

FIND_PACKAGE(OpenSSL )
MESSAGE("root: ${OPENSSL_ROOT_DIR}")
MESSAGE("OpenSSL_VERSION: ${OPENSSL_VERSION}")
MESSAGE("OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
MESSAGE("OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})

FIND_PACKAGE(LibArchive)
MESSAGE("root: ${LibArchive_FOUND}")
MESSAGE("libarchive_version: ${LibArchive_VERSION}")
MESSAGE("libarchive include dirs: ${LibArchive_INCLUDE_DIRS}")
MESSAGE("libarchive_LIBRARIES: ${LibArchive_LIBRARIES}")
INCLUDE_DIRECTORIES(${LibArchive_INCLUDE_DIRS})

ADD_LIBRARY(picoquic-core
    ${PICOQUIC_LIBRARY_FILES}
)

# They add lot of noise at compile time without actually compiling them...
if($ENV{COMPILE_CLION})
    ADD_LIBRARY(plugins-cop2
        ${PLUGINS_COP2}
    )

    ADD_LIBRARY(plugins-multipath
        ${PLUGINS_MULTIPATH}
    )
    ADD_LIBRARY(plugins-datagram
        ${PLUGINS_DATAGRAM}
    )
    ADD_LIBRARY(plugins-stream-scheduler
        ${PLUGINS_STREAM_SCHEDULER}
    )
    ADD_LIBRARY(plugins-qlog
        ${PLUGINS_QLOG}
    )
endif()

ADD_EXECUTABLE(picoquicdemo picoquicfirst/picoquicdemo.c
                            picoquicfirst/getopt.c )
TARGET_LINK_LIBRARIES(picoquicdemo picoquic-core
    ${PTLS_CORE}
    ${PTLS_OPENSSL}    
    ${PTLS_MINICRYPTO}
    ${OPENSSL_LIBRARIES}
    ${UBPF}
    ${CMAKE_DL_LIBS}
    ${LibArchive_LIBRARIES}
)

ADD_EXECUTABLE(picoquicvpn picoquicfirst/picoquicvpn.c
                            picoquicfirst/getopt.c )
TARGET_LINK_LIBRARIES(picoquicvpn picoquic-core
    ${PTLS_CORE}
    ${PTLS_OPENSSL}
    ${PTLS_MINICRYPTO}
    ${OPENSSL_LIBRARIES}
    ${UBPF}
    ${CMAKE_DL_LIBS}
    ${LibArchive_LIBRARIES}
)

ADD_EXECUTABLE(picoquicdemobench picoquicfirst/picoquicdemobench.c
                            picoquicfirst/getopt.c )
TARGET_LINK_LIBRARIES(picoquicdemobench picoquic-core
    ${PTLS_CORE}
    ${PTLS_OPENSSL}
    ${PTLS_MINICRYPTO}
    ${OPENSSL_LIBRARIES}
    ${UBPF}
    ${CMAKE_DL_LIBS}
    ${LibArchive_LIBRARIES}
)

ADD_EXECUTABLE(picoquic_ct picoquic_t/picoquic_t.c
 ${PICOQUIC_TEST_LIBRARY_FILES} )
TARGET_LINK_LIBRARIES(picoquic_ct picoquic-core
    ${PTLS_CORE}
    ${PTLS_OPENSSL}    
    ${PTLS_MINICRYPTO}
    ${PTLS_OPENSSL}
    ${PTLS_CORE}
    ${OPENSSL_LIBRARIES}
    ${UBPF}
    ${CMAKE_DL_LIBS}
    ${LibArchive_LIBRARIES}
)

SET(TEST_EXES picoquic_ct)

# get all project files for formatting
file(GLOB_RECURSE CLANG_FORMAT_SOURCE_FILES *.c *.h)

# Adds clangformat as target that formats all source files
add_custom_target(
    clangformat
    COMMAND clang-format
    -style=Webkit
    -i
    ${CLANG_FORMAT_SOURCE_FILES}
)
