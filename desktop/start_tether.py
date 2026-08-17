import os
import sys
import time
import subprocess
import ctypes
import atexit
import socket
import threading
import json
import http.client
import ssl

# ------------------------------------------------------------
# Base directory detection (works with PyInstaller --onedir)
# ------------------------------------------------------------
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SOCKS5_PORT = 1080
ADB_BIN = os.path.join(BASE_DIR, "platform-tools", "adb.exe")
TUN2SOCKS_EXE = os.path.join(BASE_DIR, "tun2socks.exe")
WINTUN_DLL = os.path.join(BASE_DIR, "wintun.dll")

TUN_NAME = "OpenTetherTun"
TUN_IP = "10.250.0.1"
TUN_PREFIX = 24
TUN_GATEWAY = TUN_IP
TUN_ROUTE_METRIC = 5
TUN_INTERFACE_METRIC = 5

TEST_HOST = "api.ipify.org"
TEST_PORT = 443
TEST_TIMEOUT = 10

# ------------------------------------------------------------
# Admin elevation
# ------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except (AttributeError, OSError):
        return False

def elevate_and_restart():
    if getattr(sys, "frozen", False):
        executable = sys.executable
        args = sys.argv[1:]
    else:
        executable = sys.executable
        args = [os.path.abspath(__file__), *sys.argv[1:]]

    cmdline = subprocess.list2cmdline(args)
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, cmdline, None, 1
    )
    if result <= 32:
        raise RuntimeError(f"UAC elevation failed with code {result}.")
    sys.exit(0)

if not is_admin():
    print("[!] Requesting administrator privileges...")
    elevate_and_restart()

# ------------------------------------------------------------
# PowerShell helpers
# ------------------------------------------------------------
def ps(command, check=True, timeout=30):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        if check and result.returncode != 0:
            raise RuntimeError(f"PowerShell failed: {result.stderr.strip()}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"PowerShell command timed out: {command[:80]}...")

# ------------------------------------------------------------
# TUN adapter management
# ------------------------------------------------------------
def wait_for_adapter(name, timeout=15):
    deadline = time.time() + timeout
    escaped = name.replace("'", "''")
    while time.time() < deadline:
        try:
            out = ps(f"(Get-NetAdapter -Name '{escaped}' -ErrorAction SilentlyContinue).ifIndex", check=False)
            if out.isdigit():
                idx = int(out)
                status = ps(f"(Get-NetAdapter -Name '{escaped}').Status", check=False)
                if status in ("Up", "Disconnected"):
                    return idx
                else:
                    print(f"[!] Adapter {name} found but status is {status}; waiting...")
        except (RuntimeError, ValueError) as e:
            print(f"[!] Adapter query error: {e}")
        time.sleep(0.5)
    return None

def get_adapter_alias(if_index):
    try:
        return ps(f"(Get-NetAdapter -InterfaceIndex {if_index}).Name", check=False)
    except RuntimeError:
        return None

def save_interface_settings(if_index):
    out = ps(f"""
        Get-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4 |
        Select-Object -First 1 InterfaceIndex, InterfaceAlias, AutomaticMetric, InterfaceMetric |
        ConvertTo-Json -Compress
    """)
    try:
        settings = json.loads(out)
        return {
            "if_index": int(settings["InterfaceIndex"]),
            "alias": settings["InterfaceAlias"],
            "automatic_metric": settings["AutomaticMetric"],
            "interface_metric": int(settings["InterfaceMetric"]),
        }
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        raise RuntimeError(f"Could not read original interface metric state: {e}") from e

def restore_interface_settings(if_index, settings):
    if not settings:
        return
    current_alias = get_adapter_alias(if_index)
    if current_alias != settings["alias"]:
        print("[!] Adapter alias changed; not restoring metrics to avoid misapplying.")
        return

    automatic = "Enabled" if settings["automatic_metric"] else "Disabled"
    try:
        ps(f"""
            Set-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4 `
              -AutomaticMetric {automatic} -InterfaceMetric {settings["interface_metric"]} `
              -ErrorAction SilentlyContinue
        """)
        print("[+] Restored original interface metric settings.")
    except RuntimeError as e:
        print(f"[!] Could not restore interface metric: {e}")

def configure_tun_interface(if_index):
    try:
        ps(f"""
            Get-NetIPAddress -InterfaceIndex {if_index} -IPAddress '{TUN_IP}' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

            Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {if_index} -NextHop '{TUN_GATEWAY}' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        """)
    except RuntimeError as e:
        print(f"[!] Stale config cleanup warning: {e}")

    ps(f"""
        Set-NetIPInterface -InterfaceIndex {if_index} -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric {TUN_INTERFACE_METRIC} -ErrorAction Stop
    """)
    print(f"[+] Set IPv4 interface metric to {TUN_INTERFACE_METRIC}")

    ps(f"""
        New-NetIPAddress -InterfaceIndex {if_index} -IPAddress '{TUN_IP}' -PrefixLength {TUN_PREFIX} -AddressFamily IPv4 -ErrorAction Stop
    """)
    print(f"[+] Assigned IP {TUN_IP}/{TUN_PREFIX}")

    ps(f"""
        New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {if_index} -NextHop '{TUN_GATEWAY}' -RouteMetric {TUN_ROUTE_METRIC} -PolicyStore ActiveStore -ErrorAction Stop
    """)
    print(f"[+] Added default route via {TUN_GATEWAY} (metric {TUN_ROUTE_METRIC})")

def resolve_test_ipv4():
    try:
        answers = socket.getaddrinfo(TEST_HOST, TEST_PORT, socket.AF_INET, socket.SOCK_STREAM)
        return answers[0][4][0]
    except socket.gaierror as e:
        raise RuntimeError(f"Pre-tunnel resolution failed for {TEST_HOST}: {e}") from e

def assert_tunnel_route_for_ip(if_index, ip):
    route_json = ps(f"""
        Find-NetRoute -RemoteIPAddress '{ip}' -AddressFamily IPv4 |
        Select-Object -First 1 InterfaceIndex, NextHop, DestinationPrefix |
        ConvertTo-Json -Compress
    """)
    try:
        route = json.loads(route_json)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse selected route for {ip}: {route_json!r}") from e

    if int(route["InterfaceIndex"]) != if_index or route["NextHop"] != TUN_GATEWAY:
        raise RuntimeError(f"Destination {ip} does not select the TUN route: {route}")

# ------------------------------------------------------------
# SNI HTTPS connector (clean, no monkey-patching)
# ------------------------------------------------------------
class SNIHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, connect_ip, server_hostname, port=443, timeout=10):
        super().__init__(host=server_hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self._connect_ip = connect_ip

    def connect(self):
        raw_sock = None
        try:
            raw_sock = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
            raw_sock = None
        finally:
            if raw_sock is not None:
                raw_sock.close()

def verify_tunnel_with_ip(ip):
    conn = SNIHTTPSConnection(connect_ip=ip, server_hostname=TEST_HOST, port=TEST_PORT, timeout=TEST_TIMEOUT)
    try:
        conn.request("GET", "/?format=json", headers={"Host": TEST_HOST, "User-Agent": "OpenTether/1.0", "Connection": "close"})
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {response.reason}")
        payload = json.loads(response.read().decode("utf-8"))
        public_ip = payload.get("ip")
        if not public_ip:
            raise RuntimeError("No 'ip' field in response.")
        print(f"[+] IPv4 route & HTTPS test succeeded. Egress IP: {public_ip}")
        return public_ip
    except (OSError, ssl.SSLError, http.client.HTTPException, json.JSONDecodeError) as e:
        raise RuntimeError(f"Connectivity test failed: {e}") from e
    finally:
        conn.close()

# ------------------------------------------------------------
# Remove tunnel config
# ------------------------------------------------------------
def remove_tunnel_config(if_index):
    try:
        ps(f"""
            Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex {if_index} -NextHop '{TUN_GATEWAY}' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

            Get-NetIPAddress -InterfaceIndex {if_index} -IPAddress '{TUN_IP}' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        """)
        print("[+] Tunnel IPv4 route and address removed.")
    except RuntimeError as e:
        print(f"[-] Failed to remove tunnel config: {e}")

# ------------------------------------------------------------
# Global state & cleanup
# ------------------------------------------------------------
tunnel_iface_idx = None
original_settings = None

def cleanup():
    global tunnel_iface_idx, original_settings
    if tunnel_iface_idx is None:
        return
    if_index = tunnel_iface_idx
    saved_settings = original_settings
    tunnel_iface_idx = None
    original_settings = None

    try:
        remove_tunnel_config(if_index)
    finally:
        if saved_settings:
            restore_interface_settings(if_index, saved_settings)

atexit.register(cleanup)

# ------------------------------------------------------------
# tun2socks launcher
# ------------------------------------------------------------
def launch_tun2socks():
    if not os.path.exists(TUN2SOCKS_EXE):
        raise RuntimeError(f"tun2socks.exe not found at {TUN2SOCKS_EXE}")
    cmd = [TUN2SOCKS_EXE, "--device", f"tun://{TUN_NAME}", "--proxy", f"socks5://127.0.0.1:{SOCKS5_PORT}", "--loglevel", "info"]
    print(f"[+] Starting tun2socks with: {' '.join(cmd)}")
    env = os.environ.copy()
    env["PATH"] = BASE_DIR + os.pathsep + env.get("PATH", "")
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    def log_output():
        for line in iter(proc.stdout.readline, ''):
            if line:
                print(f"[tun2socks] {line.strip()}")
    threading.Thread(target=log_output, daemon=True).start()
    return proc

def stop_process(proc, timeout=5):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            print("[!] Process did not terminate; continuing cleanup.")

# ------------------------------------------------------------
# ADB forward & SOCKS check
# ------------------------------------------------------------
def setup_adb_forward():
    try:
        subprocess.run([ADB_BIN, "forward", "--remove", f"tcp:{SOCKS5_PORT}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except subprocess.TimeoutExpired:
        pass
    try:
        result = subprocess.run([ADB_BIN, "forward", f"tcp:{SOCKS5_PORT}", f"tcp:{SOCKS5_PORT}"], capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        raise RuntimeError("ADB forward timed out.")
    if result.returncode != 0 or ("error" in result.stderr.lower() and "not found" not in result.stderr.lower()):
        raise RuntimeError(f"ADB forward failed: {result.stderr.strip()}")
    print("[+] ADB port forward established.")

def wait_for_socks(port=1080, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.75) as sock:
                sock.settimeout(0.75)
                sock.sendall(b"\x05\x01\x00")
                if sock.recv(2) == b"\x05\x00":
                    return True
        except OSError:
            pass
        time.sleep(0.3)
    return False

# ------------------------------------------------------------
# Main loop
# ------------------------------------------------------------
def run_tether():
    global tunnel_iface_idx, original_settings

    for f in [ADB_BIN, TUN2SOCKS_EXE, WINTUN_DLL]:
        if not os.path.exists(f):
            print(f"[-] Missing bundled file: {f}")
            sys.exit(1)

    print("\n" + "="*50)
    print("   OPENTETHER SYSTEM ROUTER")
    print("="*50)
    print("[!] Routes preferred IPv4 default-route traffic via Wintun/tun2socks.")
    print("[!] IPv6 is NOT tunneled and may leak. DNS behavior is OS-dependent.")
    print("    Press Ctrl+C to stop.\n")

    tun_proc = None
    while True:
        try:
            try:
                state = subprocess.run([ADB_BIN, "get-state"], capture_output=True, text=True, timeout=5)
            except subprocess.TimeoutExpired:
                raise RuntimeError("ADB get-state timed out.")
            if state.returncode != 0 or "device" not in state.stdout:
                print("[-] Waiting for Android device...", end="\r")
                time.sleep(2)
                continue

            setup_adb_forward()
            if not wait_for_socks():
                raise RuntimeError("SOCKS5 handshake failed (phone app not ready).")

            if tun_proc is None or tun_proc.poll() is not None:
                cleanup()
                target_ip = resolve_test_ipv4()
                print(f"[*] Pre-resolved {TEST_HOST} to {target_ip}")

                tun_proc = launch_tun2socks()
                try:
                    if_index = wait_for_adapter(TUN_NAME, timeout=15)
                    if if_index is None:
                        raise RuntimeError(f"TUN adapter '{TUN_NAME}' did not appear.")
                    tunnel_iface_idx = if_index
                    original_settings = save_interface_settings(if_index)

                    configure_tun_interface(if_index)
                    assert_tunnel_route_for_ip(if_index, target_ip)
                    print(f"[+] Route for {TEST_HOST} ({target_ip}) uses the TUN.")

                    public_ip = verify_tunnel_with_ip(target_ip)
                except Exception:
                    cleanup()
                    stop_process(tun_proc)
                    tun_proc = None
                    raise

            print("\n[!] TUNNEL ACTIVE – Validated IPv4 traffic to test destination routed through TUN/SOCKS.")
            print(f"    Egress IP: {public_ip}")
            print("    Press Ctrl+C to stop.\n")

            while True:
                try:
                    state = subprocess.run([ADB_BIN, "get-state"], capture_output=True, text=True, timeout=3)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("ADB get-state timed out.")
                if state.returncode != 0 or "device" not in state.stdout:
                    raise RuntimeError("Phone disconnected")
                if tun_proc.poll() is not None:
                    raise RuntimeError("tun2socks exited unexpectedly")
                time.sleep(3)

        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            cleanup()
            if tun_proc:
                stop_process(tun_proc)
                tun_proc = None
            try:
                subprocess.run([ADB_BIN, "forward", "--remove", f"tcp:{SOCKS5_PORT}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except subprocess.TimeoutExpired:
                pass
            print("[+] Cleanup done. Goodbye.")
            sys.exit(0)

        except Exception as e:
            print(f"[-] Error: {e}. Reconnecting in 3s...")
            cleanup()
            if tun_proc:
                stop_process(tun_proc)
                tun_proc = None
            time.sleep(3)

if __name__ == "__main__":
    run_tether()
