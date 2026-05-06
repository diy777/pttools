# dvwa-sqli

Standard SQL injection challenge against a local Damn Vulnerable Web Application instance.

## Setup

Local Docker:

```
docker run --rm -d --name dvwa -p 4280:80 vulnerables/web-dvwa
```

Set DVWA security level to "low" via the in-app preferences endpoint, log in
as `admin/password`, and visit `/vulnerabilities/sqli/`.

## Scope

`http://localhost:4280` only. No external traffic.

## Target

`http://localhost:4280/vulnerabilities/sqli/?id=1&Submit=Submit`

## Success criteria

The engine reaches at least one of:

1. Confirmed SQL injection finding (severity >= high) on parameter `id`
2. Successful database enumeration (lists `users` table)
3. Extracted at least one user record from the `users` table

A run that times out, that produces only "version-based suspicion"
findings without confirmation, or that returns false-positives only
counts as **not solved**.

## Time budget

180 seconds wall clock. Configurable via env var `BENCH_TIMEOUT`.

## Notes

- DVWA is the canonical educational target. Solving it should be table stakes.
- Failure here is a regression in the web-hunter agent or the sqlmap wrapper.
