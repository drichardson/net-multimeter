systemd service files
=====================
Install systemd service files to /lib/systemd/system on Arch Linux.

To enable, use systemctl like so:
$ systemctl enable accumulator.service
$ systemctl enable sampler.service

You also need to enable nginx, but before doing so, copy the custom nginx.conf file to /etc/nginx.
$ systemctl enable nginx
