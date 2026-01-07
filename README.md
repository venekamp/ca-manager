# ca-manager

[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/venekamp/ca-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/venekamp/ca-manager/actions/workflows/ci.yml)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type checked: basedpyright](https://img.shields.io/badge/type%20checked-basedpyright%20strict-blue.svg)](https://github.com/DetachHead/basedpyright)

A CLI tool for managing a private Certificate Authority (CA). Handles CA
initialization, server/client certificate issuance, and certificate management.
Designed for home labs and small self-hosted environments.

## Features

- Initialize a root CA with RSA 4096-bit keys
- Issue server certificates with SAN support (DNS names and IP addresses)
- Issue client certificates for authentication
- List and inspect issued certificates
- Append-only metadata tracking

## Requirements

- Python 3.14 or higher
- [uv](https://github.com/astral-sh/uv) package manager

## Installation

```bash
git clone https://github.com/venekamp/ca-manager.git
cd ca-manager
uv sync
```

## Usage

```bash
# Initialize a new CA
uv run ca-manager init

# Issue a server certificate
uv run ca-manager issue server myserver --dns myserver.local --ip 192.168.1.10

# Issue a client certificate
uv run ca-manager issue client myclient

# List issued certificates
uv run ca-manager list issued

# Inspect a certificate
uv run ca-manager inspect myserver --type server

# Show configuration
uv run ca-manager config show
```

## Configuration

Configuration is loaded from `/etc/ca-manager/config.yaml`.

## License

GPL-3.0
