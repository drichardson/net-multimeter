#!/usr/bin/bash
set -e

usage() {
    echo "Usage: sampler.sh <interface> <capture_dir> <process_dir>"
}

#
# Get parameters
#
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

if [ -z "$3" ]; then
    echo "Missing process_dir"
    usage
    exit 1
fi
PROCESS_DIR=$3

#
# Sanity checks
#
if [ $(readlink -f $CAPTURE_DIR) == "/" ]; then
    echo "capture_dir cannot be /"
    exit 1
fi

if [ $(readlink -f $PROCESS_DIR) == "/" ]; then
    echo "process_dir cannot be /"
    exit 1
fi

#
# Capture packets using tcpdump. Move rotated pcap files to process_dir.
#
ROTATE_SEC=2
SNARF_LEN=58

# If the accumulator isn't keeping up with the captured files, the process
# directory can get really big. It can get so big even listing the contents
# is slow. To handle this problem, we'll have a size threshold
# of the process directory in bytes, which, if exceeded, causes the directory
# to be cleared out.
# NOTE: tmpfs has small empty directory sizes relative to, say, ext4 (60 bytes vs 4096
# on my test system), so this number has to be experimentally set.
MAX_PROCESS_DIR_SIZE=10000

# tcpdump -z option only allows commands of the format "command <file>", so we need to capture
# the directory to move to somehow. We will accomplish this by creating a temporary script.
MOVE_SCRIPT=$(mktemp "/tmp/move_script.XXXXX")
chmod 700 "$MOVE_SCRIPT"
cat >"$MOVE_SCRIPT"<<EOF
#!/bin/bash
set -e
mkdir -p "$PROCESS_DIR"
chmod 777 "$PROCESS_DIR"
if [ \$(stat --format="%s" "$PROCESS_DIR") -gt $MAX_PROCESS_DIR_SIZE ]; then
    echo "$PROCESS_DIR has too many entries. Cleanup up."
    find "$PROCESS_DIR" -type f -name '*.pcap' -delete;
fi
mv "\$1" "$PROCESS_DIR"
echo "Moved \$1 to $PROCESS_DIR"
EOF

trap "rm \"$MOVE_SCRIPT\"" SIGINT SIGTERM

mkdir -p "$CAPTURE_DIR"
tcpdump -i "$INTERFACE" -G $ROTATE_SEC -s $SNARF_LEN -w "$CAPTURE_DIR/%s.pcap" -z "$MOVE_SCRIPT"

