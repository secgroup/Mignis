#!/bin/bash

thisdir="$(dirname "$0")"
sec=10
echo "Testing firewall config for $sec seconds..."
screen -S mignis_reset -d -m bash -c "sleep $sec; cd '$thisdir'; ./reset.sh"
( sleep $sec; echo "Firewall resetted." ) &
"$@"
