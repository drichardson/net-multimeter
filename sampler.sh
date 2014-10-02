#!/usr/bin/bash
set -e

usage() {
    echo "Usage: sampler.sh <interface> <capture_dir>"
}

if [ -z "$1" ]; then
    echo "Missing interface"
    usage
    exit 1
fi
INTERFACE=$1

if [ -z "$2" ]; then
    echo "Missing capture_dir"
    usage
    exit 1
fi
CAPTURE_DIR=$2

ROTATE_SEC=2
SNARF_LEN=58

/usr/bin/mkdir -p "$CAPTURE_DIR"
/usr/bin/chmod 777 "$CAPTURE_DIR"
/usr/bin/tcpdump -i "$INTERFACE" -G $ROTATE_SEC -w "$CAPTURE_DIR/%s.pcap" -s $SNARF_LEN

