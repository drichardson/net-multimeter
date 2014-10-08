Network Multimeter
==================
Summarize network traffic through a port.

- sampler.sh uses tcpdump to capture packets and atomically move completed captures to
a processing directory.
- accumulator watches a processing directory for pcap files, processes them, and then publishes
running results to a JSON file.
- html presents the data from the published JSON file
