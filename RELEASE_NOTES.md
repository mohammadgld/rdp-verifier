# RDP Verifier v1.0.1

This bugfix release tightens the credential-free RDP verification criteria to reduce transient and connection-stage false positives.

- A target is included only after **two independent successful RDP/CredSSP probes**, separated by 250 ms. Each probe keeps its own 3-second deadline.
- CredSSP errors, SPNEGO negotiation rejections, and malformed NTLM Type 2 challenges are rejected. After a challenge, the TLS connection must stay open without an error for a 300 ms observation period within the probe deadline.
- Progress still counts each target once. The compact window, 1–3,000 concurrent-check setting, input formats, and automatic Desktop TXT output are unchanged.

Download **RDP-Verifier-Windows.zip**, extract the entire archive, and run **RDP Verifier.exe** with its `resources` folder. If you scanned a list with v1.0.0, run it again with this release to apply the stricter filter.

SHA-256 of **RDP-Verifier-Windows.zip**: `34548c37c6eb468442d0f0d262dee5513126570d2ade226a4c37026897c265e3`

The check remains credential-free and protocol-level. It cannot prove that an RDP client will display a graphical login window, accept credentials, or open a usable desktop session. Live endpoint behavior can change after a scan.

See the [README](https://github.com/mohammadgld/rdp-verifier/blob/v1.0.1/README.md) for the full operating details, limits, build instructions, and troubleshooting.
