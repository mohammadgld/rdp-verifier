# RDP Verifier v1.0.0

First Windows desktop release. Download **RDP-Verifier-Windows.zip**, extract it, and run **RDP Verifier.exe** with its `resources` folder.

- Minimal English window for a local text file, 1–3,000 concurrent checks, progress, and verified count.
- Input supports IPv4 addresses, `IP:port`, CIDR blocks, inclusive ranges, CSV style `ip,port`, and default port 3389.
- A result requires an RDP X.224 negotiation, TLS, and a CredSSP NTLM Type 2 challenge within three seconds. An open port alone is excluded.
- A completed scan automatically writes only verified `IP:port` lines to a uniquely named TXT file on the Desktop.
- No username or password is sent. The protocol check does not prove the appearance of a graphical login window or successful sign-in.

See the [README](https://github.com/mohammadgld/rdp-verifier/blob/v1.0.0/README.md) for the full operating details, limits, build instructions, and troubleshooting.

SHA-256 of `RDP-Verifier-Windows.zip`: `3e2ad0db0b58506180e61694d37a3c9549ef954313c5fb1996fc7b0958b262db`
