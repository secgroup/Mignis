#!/usr/bin/env python3

import json
import sys


def read_mbit(filename):
    with open(filename) as result_file:
        result = json.load(result_file)
    if 'error' in result:
        raise AssertionError(f'{filename}: iperf3 failed: {result["error"]}')
    return result['end']['sum_sent']['bits_per_second'] / 1_000_000


def between(label, value, minimum, maximum):
    if not minimum <= value <= maximum:
        raise AssertionError(
            f'{label}: expected {minimum:.1f}-{maximum:.1f} Mbit/s, got {value:.2f} Mbit/s')


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            'usage: assert_rates.py CLIENT_B_ALONE CLIENT_A_ALONE '
            'CLIENT_A_CONCURRENT CLIENT_B_CONCURRENT')

    client_b_alone = read_mbit(sys.argv[1])
    client_a_alone = read_mbit(sys.argv[2])
    client_a_concurrent = read_mbit(sys.argv[3])
    client_b_concurrent = read_mbit(sys.argv[4])
    concurrent_total = client_a_concurrent + client_b_concurrent

    print(
        'Measured: '
        f'client-b={client_b_alone:.2f} Mbit/s, '
        f'client-a={client_a_alone:.2f} Mbit/s, '
        f'concurrent={client_a_concurrent:.2f}+{client_b_concurrent:.2f}'
        f'={concurrent_total:.2f} Mbit/s')

    between('unclassified client, interface ceiling', client_b_alone, 14.0, 22.5)
    between('limited client', client_a_alone, 3.5, 6.2)
    # A limit is a ceiling, not a reservation: under contention this client
    # may receive less than 5 Mbit/s.
    between('limited client under contention', client_a_concurrent, 1.0, 6.2)
    between('aggregate under contention', concurrent_total, 13.0, 22.5)
    if client_b_concurrent < 7.0:
        raise AssertionError(
            f'unclassified client under contention: expected at least 7.0 Mbit/s, '
            f'got {client_b_concurrent:.2f} Mbit/s')

    print('PASS: interface and per-IP ceilings are enforced')


if __name__ == '__main__':
    main()
