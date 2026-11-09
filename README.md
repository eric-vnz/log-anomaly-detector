# log-anomaly-detector

A security lab project for building and testing log-based anomaly detection.

Sibling project to [ssh-auth-monitor](https://github.com/eric-vnz/ssh-auth-monitor),
which analyses Ubuntu SSH authentication logs.

## Status

In development. The NorthShip API deployment and hardening and the Nginx log
anomaly detector are complete. SSH authentication-log analysis was completed and
moved to its own repository,
[ssh-auth-monitor](https://github.com/eric-vnz/ssh-auth-monitor).

## Completed work

- Migrated a Flask API to Gunicorn behind Nginx.
- Configured systemd for service management and startup at boot.
- Restricted the backend to localhost.
- Enabled UFW and verified access from Kali.
- Captured HTTP access logs, including a backend outage and recovery.
- Built a Python Nginx access-log parser with edge-case handling (6 tests passing).
- Added detection rules for 502 spikes, repeated per-client 404s, and per-client
  request bursts, with configurable windows and thresholds.
- Added a unified CLI that prints summary, status counts, top clients and all
  detections in one report.
- Built a separate SSH auth-log analyser - parser, summary, burst / spray /
  success-after-failure rules and CLI - validated against a labelled sample and
  a live hydra attack; now maintained at
  [ssh-auth-monitor](https://github.com/eric-vnz/ssh-auth-monitor).

## Lab write-up

- [Hardening the NorthShip API with Nginx, Gunicorn, and systemd](docs/01-nginx-gunicorn-hardening.md)
- [Building a rule-based Nginx log anomaly detector](docs/02-log-anomaly-detector.md)
- [Building an SSH auth-log detector](https://github.com/eric-vnz/ssh-auth-monitor/blob/main/docs/02-ssh-auth-monitor.md)

## Planned work

- Add Python packaging (`pyproject.toml` / `setup.py`) so the tool installs and runs as a command.
- Test detection rules against additional labelled lab samples to measure false positives and false negatives.
