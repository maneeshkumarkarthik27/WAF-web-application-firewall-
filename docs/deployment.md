# Deployment Guide

## Local Development

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

## Nginx Reverse Proxy

Use Nginx to terminate TLS and forward traffic to the WAF service.

## Docker

Build the container and run it behind a private network.

```bash
docker build -f docker/Dockerfile -t automated-waf .
docker run --rm -p 8080:8080 --env-file .env automated-waf
```

## Hardening Checklist

- Run as a non-root user.
- Mount persistent storage for logs and SQLite data.
- Restrict outbound traffic from the WAF container.
- Enable OS-level blocking only after validating firewall rules in staging.
