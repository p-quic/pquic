from ED_benchmark import experimental_design, int, float, str


def symmetric_link_curl_dct():
    ranges = {
        "bw": {"range": [5, 15], "type": int, "count": 1},
        "delay_ms": {"range": [5, 25], "type": int, "count": 1}
    }

    file_sizes = (1500, 10000, 50000, 1000000, 10000000)
    nets_opts = [{'quic_tun': False, 'ip_tun': False}, {'quic_tun': True, 'ip_tun': True, 'multipath': False}, {'quic_tun': True, 'ip_tun': True, 'multipath': True}]
    tests = ('tcp_over_path_b', 'tcp_over_picoquicvpn', 'tcp_over_mpicoquic')

    experimental_design(ranges, file_sizes, nets_opts, tests, 'results_symmetric_link_curl_dct.sqlite')


if __name__ == "__main__":
    symmetric_link_curl_dct()
