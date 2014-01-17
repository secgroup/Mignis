#!/bin/bash

cd "$(dirname "$0")"
iptables-restore reset.iptables
