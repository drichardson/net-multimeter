#!/bin/bash

INSTALL_ROOT=$1
shift

if [ -z "$INSTALL_ROOT" ]; then
    echo "Usage install.sh <install_root>"
    exit 1
fi

set -e

inst() {
    local mode=$1
    shift
    local dest=$(readlink -m ${INSTALL_ROOT}/$1)
    shift
    mkdir -p -m755 "${dest}"
    install -m${mode} -t "${dest}" $@
}

install_files() {
    inst 644 $@
}

install_executables() {
    inst 755 $@
}

install_executables /usr/bin accumulator/accumulator sampler.sh
install_files /usr/share/net-multimeter/html html/index.html
install_files /etc/nginx systemd/net-multimeter-nginx.conf
install_files /etc/systemd/system/nginx.service.d systemd/net-multimeter-nginx.service.conf 

echo "OK"
