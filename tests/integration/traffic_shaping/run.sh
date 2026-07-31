#!/bin/sh

set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
compose_file="$script_directory/compose.yaml"
result_directory=$(mktemp -d)

cleanup() {
    if [ "${MIGNIS_KEEP_TEST_LAB:-0}" = "1" ]; then
        echo "Keeping Docker lab and results in $result_directory"
        return
    fi
    docker compose -f "$compose_file" down --volumes
    rm -r "$result_directory"
}
trap cleanup EXIT INT TERM

docker compose -f "$compose_file" build router
docker compose -f "$compose_file" up --detach --no-build
docker compose -f "$compose_file" exec -T router \
    python3 /opt/mignis/mignis.py \
    -c /etc/mignis/router.config -e -f

# Applying the same configuration twice must be safe and idempotent.
docker compose -f "$compose_file" exec -T router \
    python3 /opt/mignis/mignis.py \
    -c /etc/mignis/router.config -e -f

# The unclassified client should see only the aggregate interface ceiling.
docker compose -f "$compose_file" exec -T client-b \
    iperf3 -c 10.77.20.10 -p 5202 -O 2 -t 8 -J \
    >"$result_directory/client-b-alone.json"

# The classified client should see its own lower ceiling.
docker compose -f "$compose_file" exec -T client-a \
    iperf3 -c 10.77.20.10 -p 5201 -O 2 -t 8 -J \
    >"$result_directory/client-a-alone.json"

# Run both clients together to verify the per-IP and aggregate ceilings.
docker compose -f "$compose_file" exec -T client-a \
    iperf3 -c 10.77.20.10 -p 5201 -O 2 -t 10 -J \
    >"$result_directory/client-a-concurrent.json" &
client_a_pid=$!
docker compose -f "$compose_file" exec -T client-b \
    iperf3 -c 10.77.20.10 -p 5202 -O 2 -t 10 -J \
    >"$result_directory/client-b-concurrent.json" &
client_b_pid=$!
wait "$client_a_pid"
wait "$client_b_pid"

python3 "$script_directory/assert_rates.py" \
    "$result_directory/client-b-alone.json" \
    "$result_directory/client-a-alone.json" \
    "$result_directory/client-a-concurrent.json" \
    "$result_directory/client-b-concurrent.json"

docker compose -f "$compose_file" exec -T router \
    tc -s class show dev wan0
docker compose -f "$compose_file" exec -T router \
    iptables -t mangle -L MIGNIS_TC -n -v

# Flush must remove the Mignis-owned qdisc and its runtime state.
docker compose -f "$compose_file" exec -T router \
    python3 /opt/mignis/mignis.py -F -f
docker compose -f "$compose_file" exec -T router /bin/sh -ec \
    '! tc qdisc show dev wan0 | grep -q "1d00:"; test ! -e /run/mignis/tc-state.json'
