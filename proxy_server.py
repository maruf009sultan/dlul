from flask import Flask, render_template_string
import socket
import threading
import socks
import requests
from ping3 import ping
import time
import humanize
import logging
from concurrent.futures import ThreadPoolExecutor  # Added import

# Configure logging to console only
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Proxy configuration
PROXY_PORT = 1083
PROXY_HOST = '0.0.0.0'
PROXY_RUNNING = False
USERNAME = 'proxyuser'
PASSWORD = 'proxypass'
MAX_WORKERS = 20
ACTIVE_USERS = 0
TOTAL_DOWNLOAD_BYTES = 0
TOTAL_UPLOAD_BYTES = 0
START_TIME = time.time()
LOCK = threading.Lock()

# Network metrics
PUBLIC_IP = '52.1.65.187'  # Match web interface
LOCATION = 'Ashburn, United States'
PING = 'N/A'
DOWNLOAD_SPEED = 'N/A'
UPLOAD_SPEED = 'N/A'
LAST_METRIC_UPDATE = 0
METRIC_UPDATE_INTERVAL = 3600

def update_network_metrics():
    """Update network metrics with retries."""
    global PUBLIC_IP, LOCATION, PING, DOWNLOAD_SPEED, UPLOAD_SPEED, LAST_METRIC_UPDATE
    if time.time() - LAST_METRIC_UPDATE < METRIC_UPDATE_INTERVAL:
        return
    for attempt in range(3):
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            response.raise_for_status()
            PUBLIC_IP = response.text
            geo_response = requests.get(f'http://ip-api.com/json/{PUBLIC_IP}', timeout=5)
            geo_response.raise_for_status()
            GEO_DATA = geo_response.json()
            LOCATION = f"{GEO_DATA.get('city', 'Unknown')}, {GEO_DATA.get('country', 'Unknown')}"
            PING = ping('8.8.8.8', unit='ms', timeout=2) or 'N/A'
            # Speedtest disabled to avoid crashes
            # import speedtest
            # st = speedtest.Speedtest()
            # st.get_best_server()
            # DOWNLOAD_SPEED = st.download() / 1_000_000
            # UPLOAD_SPEED = st.upload() / 1_000_000
            LAST_METRIC_UPDATE = time.time()
            logging.info(f"Network metrics updated: IP={PUBLIC_IP}, Location={LOCATION}, Ping={PING}")
            break
        except Exception as e:
            logging.error(f"Metrics update attempt {attempt+1} failed: {e}")
            time.sleep(2)
    else:
        logging.error("Failed to update network metrics after retries")

def handle_client(client_socket, client_addr):
    """Handle incoming client connections for the proxy."""
    global ACTIVE_USERS, TOTAL_DOWNLOAD_BYTES, TOTAL_UPLOAD_BYTES
    logging.info(f"Handling client from {client_addr}")
    try:
        with LOCK:
            ACTIVE_USERS += 1
        data = client_socket.recv(4096)
        if not data:
            logging.warning(f"Client {client_addr} sent empty handshake")
            return
        with LOCK:
            TOTAL_UPLOAD_BYTES += len(data)

        if data[0] != 0x05:
            logging.warning(f"Client {client_addr} sent invalid SOCKS5 version")
            return
        client_socket.send(b'\x05\x02')
        auth_data = client_socket.recv(4096)
        with LOCK:
            TOTAL_UPLOAD_BYTES += len(auth_data)
        
        if not auth_data or auth_data[0] != 0x01:
            logging.warning(f"Client {client_addr} sent invalid auth data")
            return
        ulen = auth_data[1]
        username = auth_data[2:2+ulen].decode('utf-8', errors='ignore')
        plen = auth_data[2+ulen]
        password = auth_data[3+ulen:3+ulen+plen].decode('utf-8', errors='ignore')

        if username != USERNAME or password != PASSWORD:
            client_socket.send(b'\x01\x01')
            logging.warning(f"Client {client_addr} failed authentication")
            return
        client_socket.send(b'\x01\x00')

        request = client_socket.recv(4096)
        with LOCK:
            TOTAL_UPLOAD_BYTES += len(request)
        if not request or request[0] != 0x05 or request[1] != 0x01:
            logging.warning(f"Client {client_addr} sent invalid request")
            return

        addr_type = request[3]
        if addr_type == 0x01:
            host = socket.inet_ntoa(request[4:8])
            port = int.from_bytes(request[8:10], 'big')
        elif addr_type == 0x03:
            addr_len = request[4]
            host = request[5:5+addr_len].decode('utf-8', errors='ignore')
            port = int.from_bytes(request[5+addr_len:7+addr_len], 'big')
        else:
            logging.warning(f"Client {client_addr} sent unsupported address type")
            return

        client_socket.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        logging.info(f"Client {client_addr} connected to {host}:{port}")

        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.settimeout(10)
        try:
            dest_socket.connect((host, port))
            client_to_dest = threading.Thread(
                target=relay_data, args=(client_socket, dest_socket, True, client_addr)
            )
            dest_to_client = threading.Thread(
                target=relay_data, args=(dest_socket, client_socket, False, client_addr)
            )
            client_to_dest.start()
            dest_to_client.start()
            client_to_dest.join()
            dest_to_client.join()
        except Exception as e:
            logging.error(f"Client {client_addr} failed to connect to {host}:{port}: {e}")
        finally:
            dest_socket.close()
    except Exception as e:
        logging.error(f"Error handling client {client_addr}: {e}")
    finally:
        client_socket.close()
        with LOCK:
            ACTIVE_USERS -= 1
        logging.info(f"Client {client_addr} disconnected")

def relay_data(src, dst, is_upload, client_addr):
    """Relay data between source and destination sockets."""
    global TOTAL_DOWNLOAD_BYTES, TOTAL_UPLOAD_BYTES
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            with LOCK:
                if is_upload:
                    TOTAL_UPLOAD_BYTES += len(data)
                else:
                    TOTAL_DOWNLOAD_BYTES += len(data)
            dst.sendall(data)
    except Exception as e:
        logging.error(f"Relay error for client {client_addr}: {e}")

def get_bandwidth():
    """Calculate average download and upload bandwidth in Mbps."""
    elapsed = time.time() - START_TIME
    if elapsed < 1:
        return "0.00 Mbps", "0.00 Mbps"
    download_mbps = (TOTAL_DOWNLOAD_BYTES * 8) / (elapsed * 1_000_000)
    upload_mbps = (TOTAL_UPLOAD_BYTES * 8) / (elapsed * 1_000_000)
    return f"{download_mbps:.2f} Mbps", f"{upload_mbps:.2f} Mbps"

def start_proxy():
    """Start the SOCKS5 proxy server with retry on failure."""
    global PROXY_RUNNING
    while True:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind((PROXY_HOST, PROXY_PORT))
            server_socket.listen(5)
            PROXY_RUNNING = True
            logging.info(f"Proxy server running on {PROXY_HOST}:{PROXY_PORT} (Public IP: {PUBLIC_IP})")
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                while PROXY_RUNNING:
                    try:
                        client_socket, addr = server_socket.accept()
                        logging.info(f"New client connection from {addr}")
                        executor.submit(handle_client, client_socket, addr)
                    except Exception as e:
                        logging.error(f"Error accepting client: {e}")
                        time.sleep(1)
        except Exception as e:
            logging.error(f"Proxy server failed to start on port {PROXY_PORT}: {e}")
            PROXY_RUNNING = False
            time.sleep(5)
        finally:
            server_socket.close()
            if PROXY_RUNNING:
                logging.info("Proxy server stopped")
                PROXY_RUNNING = False
            time.sleep(5)

# HTML template for Flask web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Server Status</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #333; }
        .status { font-size: 18px; margin: 20px; }
        .running { color: green; }
        .stopped { color: red; }
        .config { font-size: 16px; margin: 10px; }
        .metrics { font-size: 16px; margin: 10px; }
    </style>
</head>
<body>
    <h1>Proxy Server Status</h1>
    <p class="status {{ 'running' if proxy_running else 'stopped' }}">
        Proxy is {{ 'Running' if proxy_running else 'Stopped' }}
    </p>
    <div class="config">
        <p><strong>Proxy Type:</strong> SOCKS5 (supports HTTPS)</p>
        <p><strong>Host:</strong> {{ public_ip }}</p>
        <p><strong>Port:</strong> {{ proxy_port }}</p>
        <p><strong>Username:</strong> {{ username }}</p>
        <p><strong>Password:</strong> {{ password }}</p>
        <p><strong>Location:</strong> {{ location }}</p>
    </div>
    <div class="metrics">
        <p><strong>Active Users:</strong> {{ active_users }}</p>
        <p><strong>Ping (to 8.8.8.8):</strong> {{ ping }} ms</p>
        <p><strong>Server Download Speed:</strong> {{ download_speed }} Mbps</p>
        <p><strong>Server Upload Speed:</strong> {{ upload_speed }} Mbps</p>
        <p><strong>Total Download Bandwidth:</strong> {{ download_bandwidth }}</p>
        <p><strong>Total Upload Bandwidth:</strong> {{ upload_bandwidth }}</p>
    </div>
    <p><em>Note: Configure your client to use SOCKS5 with the above credentials.</em></p>
</body>
</html>
"""

@app.route('/')
def index():
    """Render the proxy status page."""
    update_network_metrics()
    download_bandwidth, upload_bandwidth = get_bandwidth()
    return render_template_string(
        HTML_TEMPLATE,
        proxy_running=PROXY_RUNNING,
        public_ip=PUBLIC_IP,
        proxy_port=PROXY_PORT,
        username=USERNAME,
        password=PASSWORD,
        location=LOCATION,
        active_users=ACTIVE_USERS,
        ping=f"{PING:.2f}" if isinstance(PING, float) else PING,
        download_speed=f"{DOWNLOAD_SPEED:.2f}" if isinstance(DOWNLOAD_SPEED, float) else DOWNLOAD_SPEED,
        upload_speed=f"{UPLOAD_SPEED:.2f}" if isinstance(UPLOAD_SPEED, float) else UPLOAD_SPEED,
        download_bandwidth=download_bandwidth,
        upload_bandwidth=upload_bandwidth
    )

if __name__ == '__main__':
    proxy_thread = threading.Thread(target=start_proxy, daemon=True)
    proxy_thread.start()
    time.sleep(1)
    update_network_metrics()
    app.run(host='0.0.0.0', port=7860, debug=False)