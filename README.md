# Prometheus

Welcome to the Prometheus repo!

Prometheus is a collection of two recon scripts for Red Team and Web blackbox auditing:

- Asset_discovery: a small script that allows to perform DNS asset discovery, Nuclei scans, determine used technologies, find known URLs, take screenshots of found web assets by combining the output of several tools.
- Blackbox_audit: script that does a lot of blackbox tests (Ping, Nmap, DNS+DNSSec tests, sslscan + testssl) on a set of hosts you provide to the script.

To start, check the [Installation](../../wiki/2.-Installation) page and the [Recommended User Guide](../../wiki/3.-User-Guide-‐-With-Docker-‐-Recommended) that describes the usage of the tool with a Docker container and a simple wrapper script.

Alternatively you can check the [Not Recommended User Guide](../../wiki/4.-User-Guide-‐-Standalone-‐-Not-recommended) that describes the usage of the recon scripts without Docker container.
