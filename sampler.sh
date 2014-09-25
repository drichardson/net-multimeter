#!/bin/bash
set -e
DIR=/tmp/net-multimeter/capture
mkdir -p "$DIR"
sudo tcpdump -i eth0 -G 10 -w "$DIR/%s.pcap" -s 58
