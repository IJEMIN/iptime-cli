# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature in the repository's
Security tab. Do not open a public issue for a suspected vulnerability.

Include the smallest synthetic reproduction possible. Do **not** attach:

- router passwords, session cookies, or captcha tokens
- real IP or MAC addresses, SSIDs, hostnames, DDNS names, or serial numbers
- router config backups
- screenshots of an authenticated admin page
- HAR, PCAP, firmware, or router UI bundles

If a report needs environment information, attach only the output of
`iptime doctor`. Maintainers may still ask you to remove additional fields.

## Scope

Security issues include credential exposure, unsafe redirection, public-host
bypass, missing output redaction, unintended state changes, and command
classification errors. Model-specific compatibility problems without a security
impact belong in a regular bug report using synthetic data.
