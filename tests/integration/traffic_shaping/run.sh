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

# The unclassified client should see only the egress aggregate ceiling.
docker compose -f "$compose_file" exec -T client-b \
    iperf3 -c 10.77.20.10 -p 5202 -O 2 -t 8 -J \
    >"$result_directory/egress-client-b-alone.json"

# The classified client should see its own lower egress ceiling.
docker compose -f "$compose_file" exec -T client-a \
    iperf3 -c 10.77.20.10 -p 5201 -O 2 -t 8 -J \
    >"$result_directory/egress-client-a-alone.json"

# Run both clients together to verify the egress ceilings.
docker compose -f "$compose_file" exec -T client-a \
    iperf3 -c 10.77.20.10 -p 5201 -O 2 -t 10 -J \
    >"$result_directory/egress-client-a-concurrent.json" &
client_a_pid=$!
docker compose -f "$compose_file" exec -T client-b \
    iperf3 -c 10.77.20.10 -p 5202 -O 2 -t 10 -J \
    >"$result_directory/egress-client-b-concurrent.json" &
client_b_pid=$!
wait "$client_a_pid"
wait "$client_b_pid"

python3 "$script_directory/assert_rates.py" \
    egress 20 5 \
    "$result_directory/egress-client-b-alone.json" \
    "$result_directory/egress-client-a-alone.json" \
    "$result_directory/egress-client-a-concurrent.json" \
    "$result_directory/egress-client-b-concurrent.json"

docker compose -f "$compose_file" exec -T router \
    tc -s class show dev wan0
docker compose -f "$compose_file" exec -T router \
    iptables -t mangle -L MIGNIS_TC -n -v

# Switch directions. This also verifies that the stale egress qdisc is removed.
docker compose -f "$compose_file" exec -T router \
    python3 /opt/mignis/mignis.py \
    -c /etc/mignis/router-ingress.config -e -f
docker compose -f "$compose_file" exec -T router \
    python3 /opt/mignis/mignis.py \
    -c /etc/mignis/router-ingress.config -e -f
docker compose -f "$compose_file" exec -T router /bin/sh -ec \
    '! tc qdisc show dev wan0 | grep -q "1d00:"'

# Repeat the measurements with packets shaped as they enter lan0.
docker compose -f "$compose_file" exec -T client-b \
    iperf3 -c 10.77.20.10 -p 5202 -O 2 -t 8 -J \
    >"$result_directory/ingress-client-b-alone.json"
docker compose -f "$compose_file" exec -T client-a \
    iperf3 -c 10.77.20.10 -p 5201 -O 2 -t 8 -J \
    >"$result_directory/ingress-client-a-alone.json"
docker compose -f "$compose_file" exec -T client-a \
    iperf3 -c 10.77.20.10 -p 5201 -O 2 -t 10 -J \
    >"$result_directory/ingress-client-a-concurrent.json" &
client_a_pid=$!
docker compose -f "$compose_file" exec -T client-b \
    iperf3 -c 10.77.20.10 -p 5202 -O 2 -t 10 -J \
    >"$result_directory/ingress-client-b-concurrent.json" &
client_b_pid=$!
wait "$client_a_pid"
wait "$client_b_pid"

python3 "$script_directory/assert_rates.py" \
    ingress 12 3 \
    "$result_directory/ingress-client-b-alone.json" \
    "$result_directory/ingress-client-a-alone.json" \
    "$result_directory/ingress-client-a-concurrent.json" \
    "$result_directory/ingress-client-b-concurrent.json"

docker compose -f "$compose_file" exec -T router \
    tc -s class show dev mifb8306f8208e
docker compose -f "$compose_file" exec -T router \
    tc -s filter show dev lan0 ingress

# Flush must remove the Mignis-owned IFB, redirect, clsact and runtime state.
docker compose -f "$compose_file" exec -T router \
    python3 /opt/mignis/mignis.py -F -f
docker compose -f "$compose_file" exec -T router /bin/sh -ec \
    '! ip link show dev mifb8306f8208e >/dev/null 2>&1; \
     ! tc qdisc show dev lan0 | grep -q "qdisc clsact "; \
     test ! -e /run/mignis/tc-state.json'

# The generated ingress runner must create its prerequisites and be repeatable.
docker compose -f "$compose_file" exec -T router \
    python3 /opt/mignis/mignis.py \
    -c /etc/mignis/router-ingress.config -w /tmp/router.rules -f
docker compose -f "$compose_file" exec -T router \
    /tmp/router.rules.tc.sh
docker compose -f "$compose_file" exec -T router \
    /tmp/router.rules.tc.sh
docker compose -f "$compose_file" exec -T router /bin/sh -ec \
    'tc qdisc show dev mifb8306f8208e | grep -q "qdisc htb 1d00:"; \
     tc filter show dev lan0 ingress | grep -q "Redirect to device mifb8306f8208e"'
