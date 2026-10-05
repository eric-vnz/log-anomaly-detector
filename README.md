# log-anomaly-detector

A security lab project for building and testing log-based anomaly detection.

## Status

In development. The NorthShip API deployment and initial hardening are complete.
The log parser and detection rules are planned next.

## Completed work

- Migrated a Flask API to Gunicorn behind Nginx.
- Configured systemd for service management and startup at boot.
- Restricted the backend to localhost.
- Enabled UFW and verified access from Kali.
- Captured HTTP access logs, including a backend outage and recovery.

## Lab write-up

- [Hardening the NorthShip API with Nginx, Gunicorn, and systemd](docs/01-nginx-gunicorn-hardening.md)

## Planned work

- Parse Nginx access logs.
- Detect HTTP error spikes and suspicious request patterns.
- Add SSH authentication-log analysis.
- Test detection rules against labelled lab samples.
