# Vulnerable Shop (demo target)

A tiny Flask shop that is insecure **on purpose**, so you can watch ChainBreaker link its
weaknesses into attack chains. Do not deploy it.

```bash
chainbreaker scan examples/vulnerable-shop --html report.html
```

Planted weaknesses: debug mode, SQL injection, command injection, unsafe YAML, an admin route with
no auth, a hardcoded JWT secret, a committed `.env`, open CORS, a root container, a mounted Docker
socket, a published Postgres port and two vulnerable dependencies.
