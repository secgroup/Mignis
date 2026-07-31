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
    if len(sys.argv) != 8:
        raise SystemExit(
            'usage: assert_rates.py LABEL AGGREGATE_MBIT SPECIFIC_MBIT '
            'CLIENT_B_ALONE CLIENT_A_ALONE '
            'CLIENT_A_CONCURRENT CLIENT_B_CONCURRENT')

    label = sys.argv[1]
    aggregate_limit = float(sys.argv[2])
    specific_limit = float(sys.argv[3])
    client_b_alone = read_mbit(sys.argv[4])
    client_a_alone = read_mbit(sys.argv[5])
    client_a_concurrent = read_mbit(sys.argv[6])
    client_b_concurrent = read_mbit(sys.argv[7])
    concurrent_total = client_a_concurrent + client_b_concurrent

    print(
        f'{label} measured: '
        f'client-b={client_b_alone:.2f} Mbit/s, '
        f'client-a={client_a_alone:.2f} Mbit/s, '
        f'concurrent={client_a_concurrent:.2f}+{client_b_concurrent:.2f}'
        f'={concurrent_total:.2f} Mbit/s')

    between(
        'unclassified client, interface ceiling',
        client_b_alone,
        aggregate_limit * 0.70,
        aggregate_limit * 1.125,
    )
    between(
        'limited client',
        client_a_alone,
        specific_limit * 0.70,
        specific_limit * 1.24,
    )
    # A limit is a ceiling, not a reservation: under contention this client
    # may receive less than its configured rate.
    between(
        'limited client under contention',
        client_a_concurrent,
        specific_limit * 0.20,
        specific_limit * 1.24,
    )
    between(
        'aggregate under contention',
        concurrent_total,
        aggregate_limit * 0.65,
        aggregate_limit * 1.125,
    )
    minimum_unclassified = aggregate_limit * 0.35
    if client_b_concurrent < minimum_unclassified:
        raise AssertionError(
            f'unclassified client under contention: expected at least '
            f'{minimum_unclassified:.1f} Mbit/s, '
            f'got {client_b_concurrent:.2f} Mbit/s')

    print(f'PASS: {label} interface and per-IP ceilings are enforced')


if __name__ == '__main__':
    main()
