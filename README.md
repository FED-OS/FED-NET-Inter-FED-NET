# OpenTether – Experimental IPv4 TCP-over-USB test tool [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/W3T61ZU5FS)

OpenTether is an **experimental personal-use IPv4 TCP routing test** that uses an Android SOCKS5 proxy exposed over ADB and a Wintun/tun2socks path on Windows.

## How it works

- Android app runs a TCP-only SOCKS5 proxy on port 1080.
- Windows desktop uses ADB to forward that port to localhost.
- tun2socks + wintun.dll create a virtual network adapter.
- A low-metric IPv4 default route sends traffic through the adapter.
- The desktop script validates route selection and performs a TLS-authenticated HTTPS test.

## Current limitations

- **IPv4 TCP only** – IPv6, UDP, and other protocols are not handled.
- **IPv6 traffic will leak** unless you disable IPv6 on physical adapters.
- **DNS behavior** depends on Windows interface selection and policies.
- **Hard process termination** (Task Manager) may leave routes behind.
- **Android app is a basic SOCKS5 proxy** – no VpnService, no UDP ASSOCIATE.

## For testing only

This is not a polished commercial product. It is meant for developers who want to understand and control their tethering stack. Use at your own risk.

## Build & run

1. Push the repository to GitHub.
2. Download the `OpenTether-APK` and `OpenTether-Desktop` artifacts from Actions.
3. Install the APK, enable USB debugging, plug in your phone.
4. Run `OpenTetherRouter.exe` as Administrator.
5. Monitor the console – it will show the egress IP after successful connection.

## License

MIT
