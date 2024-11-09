import socket
import ssl
from enum import Enum
import threading
import queue

import fire


class TCPProxyServer:
    def __init__(
        self, cdn_addr: str, cdn_port: int, origin_addr: str, origin_port: int
    ):
        """Level 1: TCP Proxy that forwards traffic between client and origin server
        - cdn_addr: IP address of the CDN server
        - cdn_port: Port number of the CDN server
        - origin_addr: IP address of the origin server
        - origin_port: Port number of the origin server
        """
        self.cdn_addr = cdn_addr
        self.cdn_port = cdn_port
        self.origin_addr = origin_addr
        self.origin_port = origin_port
        print(f"Initialized TCPProxyServer with CDN ({self.cdn_addr}:{self.cdn_port}) and Origin ({self.origin_addr}:{self.origin_port})")


    def start(self):
            """Start the proxy server
            - Create a socket to listen for client connections
            - Accept client connections and ``handle_client()`` in a separate thread
            """
            print("Starting the proxy server...")
            # Create a socket to listen for client connections
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.cdn_socket:
                print(f"Binding CDN socket to {self.cdn_addr}:{self.cdn_port}...")
                self.cdn_socket.bind((self.cdn_addr, self.cdn_port))
                self.cdn_socket.listen(10)
                print(f"Listening for connections on {self.cdn_addr}:{self.cdn_port}")

                # Accept client connections and handle them in separate threads
                while True:
                    print("Waiting for a client to connect...")
                    client_socket, address = self.accept_client_connection()
                    print(f"Client connected from {address}")
                    # Create a new thread for each client
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket, address)
                    )
                    client_thread.start()
                    print(f"Started thread {client_thread.name} for client {address}")

    def accept_client_connection(self) -> tuple[socket.socket, tuple[str, int]]:
        """Accept client connection and return client socket and address"""
        # accept connections from outside
        client_socket, address = self.cdn_socket.accept()
        print(f"Accepted connection from client: {address}")
        return client_socket, address


    def handle_client(
        self, client_socket: socket.socket, client_address: tuple[str, int]
    ):
        """Handle client connection by relaying traffic between client and origin server
        - The CDN server communicates with the client through ``client_socket`` and the
        origin server through ``origin_socket`` (see below)
        - Establish a TCP connection to the origin server
        - Create two threads to ``relay_messages()`` bidirectionally
        """
        print(f"Handling client {client_address} in a separate thread...")
        origin_socket = None
        try:
            # Connect to the origin server
            origin_socket = self.connect_to_origin()

            # Create threads to relay messages in both directions
            client_to_origin_thread = threading.Thread(
                target=self.relay_messages, args=(client_socket, origin_socket)
            )
            origin_to_client_thread = threading.Thread(
                target=self.relay_messages, args=(origin_socket, client_socket)
            )

            # Start both threads
            client_to_origin_thread.start()
            origin_to_client_thread.start()

            print(f"Started message relay threads for client {client_address}")

            # Wait for both threads to finish
            client_to_origin_thread.join()
            origin_to_client_thread.join()
            print(f"Message relay completed for client {client_address}")

        except Exception as e:
            print(f"Error while handling client {client_address}: {e}")
        finally:
            # Ensure both sockets are closed after the forwarding is done
            print("Closing client and origin sockets...")
            client_socket.close()
            if origin_socket:
                origin_socket.close()
            print(f"Both sockets closed for client {client_address}.")


    def connect_to_origin(self) -> socket.socket:
        """Connect to the origin server and return the socket object"""
        ...
        print(f"Connecting to the origin server at {self.origin_addr}:{self.origin_port}...")
        origin_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        origin_socket.connect((self.origin_addr, self.origin_port))
        print(f"Connected to the origin server at {self.origin_addr}:{self.origin_port}")
        return origin_socket

    def relay_messages(self, src_socket: socket.socket, dst_socket: socket.socket):
        """Relay messages from the source socket to the destination socket
        - This method should receive data from the source socket and send it to the
        destination socket.
        - This method returns when the source finishes sending data and initiates 
        graceful closure of TCP connection (i.e., when ``socket.recv()`` returns 
        an empty byte string). The connection will enter a half-closed state.
        """
        print(f"Starting message relay from {src_socket.getsockname()} to {dst_socket.getsockname()}...")
        while True:
            try:
                data = src_socket.recv(4096)
                if not data:
                    print(f"No more data from {src_socket.getsockname()}. Closing connection...")
                    break
                print(f"Received {len(data)} bytes. Forwarding to {dst_socket.getsockname()}...")
                dst_socket.sendall(data)
            except socket.error as e:
                print(f"Socket error during message relay: {e}")
                break
        print(f"Message relay from {src_socket.getsockname()} completed.")


class HTTPSProxyServer(TCPProxyServer):
    def __init__(
        self,
        cdn_addr: str,
        cdn_port: int,
        origin_addr: str,
        origin_port: int,
        cert_file: str,
        key_file: str,
        origin_domain: str,
    ):
        """Level 2: HTTPS Proxy that forwards traffic between client and origin server over HTTPS
        - cdn_addr: IP address of the CDN server
        - cdn_port: Port number of the CDN server
        - origin_addr: IP address of the origin server
        - origin_port: Port number of the origin server
        - cert_file: Path to the SSL certificate file
        - key_file: Path to the SSL key file
        - origin_domain: Domain name of the origin server
        """
        super().__init__(cdn_addr, cdn_port, origin_addr, origin_port)
        self.cert_file = cert_file
        self.key_file = key_file
        self.origin_domain = origin_domain

    def accept_client_connection(self) -> tuple[ssl.SSLSocket, tuple[str, int]]:
        """Accept client connection and return client's SSL socket and address"""
        print("Waiting for a client to connect...")
        client_socket, address = self.cdn_socket.accept()  # Accept client connection
        print(f"Accepted connection from client: {address}")
        
        print("Initializing SSL context...")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        print(f"Loading certificate from {self.cert_file} and key from {self.key_file}...")
        context.load_cert_chain(self.cert_file, self.key_file)
        
        # Now wrap the client socket in SSL
        client_ssl_socket = context.wrap_socket(client_socket, server_side=True)
        print("SSL context initialized, connection secured.")
        
        return client_ssl_socket, address

    def handle_client(
        self, client_socket: ssl.SSLSocket, client_address: tuple[str, int]
    ):
        """Handle client connection by forwarding traffic to the origin server over HTTPS
        - client_socket: SSL socket object for the client connection
        - client_address: Address of the client (may not be used)
        """
        print(f"Handling client {client_address} in a separate thread...")
        origin_socket = None
        try:
            # Connect to the origin server
            print(f"Connecting to origin server for client {client_address}...")
            origin_socket = self.connect_to_origin()

            # Step 2: Receive the client's request
            print(f"Receiving request from client {client_address}...")
            request_data = self.receive_client_request(client_socket)

            # Step 3: Modify the request
            print(f"Modifying request from client {client_address}...")
            modified_request = self.modify_request(request_data)

            # Step 4: Send the modified request to the origin server
            print(f"Sending modified request to origin server for client {client_address}...")
            origin_socket.sendall(modified_request)

            # Step 5: Receive the response from the origin server
            print(f"Receiving response from origin server for client {client_address}...")
            response_data = self.receive_origin_response(origin_socket)

            # Step 6: Send the response back to the client
            print(f"Sending response back to client {client_address}...")
            client_socket.sendall(response_data)

            print(f"Completed request-response cycle for client {client_address}")

        except Exception as e:
            print(f"Error while handling client {client_address}: {e}")
        finally:
            # Ensure both sockets are closed after the forwarding is done
            print("Closing client and origin sockets...")
            client_socket.close()
            if origin_socket:
                origin_socket.close()
            print(f"Both sockets closed for client {client_address}.")

    def connect_to_origin(self) -> socket.socket:
        """Connect to the origin server over TLS and return the socket object"""
        print("Creating a default SSL context")
        context = ssl.create_default_context()
        print("Creating a TCP socket")
        sock = socket.create_connection((self.origin_addr, self.origin_port))
        ssock = context.wrap_socket(sock, server_hostname=self.origin_domain)
        return ssock

    def receive_client_request(self, client_socket: socket.socket) -> bytes:
        """Receive the request from the client and return the request data
        - You may assume the request is a ``GET`` request with no body:
        ``GET /path/to/file HTTP/1.1\\r\\nHeader1: value1\\r\\nHeader2: value2\\r\\n\\r\\n``.
        Determine the end of request according to this format.
        """
        request_data = b''
        while True:
            chunk = client_socket.recv(4096)
            request_data += chunk
            # Check if we've reached the end of the HTTP headers (denoted by '\r\n\r\n')
            if b'\r\n\r\n' in request_data:
                break
        return request_data

    def receive_origin_response(self, origin_socket: socket.socket) -> bytes:
        """Receive the response from the origin server and return the response data
        - Determine the end of response by connection close (i.e., when
        ``socket.recv()`` returns an empty byte string)
        """
        response_data = b''
        while True:
            chunk = origin_socket.recv(4096)
            if not chunk:
                # Connection closed by the origin server
                break
            response_data += chunk
        return response_data

    def modify_request(self, request_data: bytes) -> bytes:
        """Modify the client request before forwarding it to the origin server
        - Decode the request message encoded in ``iso-8859-1``
        - You may assume the request is a ``GET`` request with no body:
        ``GET /path/to/file HTTP/1.1\\r\\nHeader1: value1\\r\\nHeader2: value2\\r\\n\\r\\n``
        - Add a ``Connection: close`` header to the request.
        Note that the request may already contain a ``Connection`` header
        """
        request_text = request_data.decode('iso-8859-1')
        
        # Add 'Connection: close' header, replacing the existing one if it exists
        headers, body = request_text.split('\r\n\r\n', 1)
        header_lines = headers.split('\r\n')
        connection_header_present = False
        
        for i, line in enumerate(header_lines):
            if line.lower().startswith('connection:'):
                header_lines[i] = 'Connection: close'
                connection_header_present = True
                break
        
        if not connection_header_present:
            header_lines.append('Connection: close')
        
        # Reconstruct the request
        modified_request = '\r\n'.join(header_lines) + '\r\n\r\n' + body
        return modified_request.encode('iso-8859-1')

class PersistentProxyServer(HTTPSProxyServer):
    def __init__(
        self,
        cdn_addr: str,
        cdn_port: int,
        origin_addr: str,
        origin_port: int,
        cert_file: str,
        key_file: str,
        origin_domain: str,
    ):
        """Level 3: Persistent Proxy that reuses connections to the origin server"""
        super().__init__(cdn_addr, cdn_port, origin_addr, origin_port, cert_file, key_file, origin_domain)
        self.connection_pool = queue.LifoQueue(8)  # LifoQueue for connection reuse (LIFO)

    def handle_client(self, client_socket: ssl.SSLSocket, client_address: tuple[str, int]):
        """Handle client connection by forwarding traffic to the origin server over HTTPS"""
        print(f"Handling client {client_address} in a separate thread...")
        origin_socket = None
        try:
            # Connect to the origin server, reusing a connection if available
            origin_socket = self.connect_to_origin()

            # Receive the client's request
            request_data = self.receive_client_request(client_socket)

            # Modify the request to keep the connection alive
            modified_request = self.modify_request(request_data)

            # Send the modified request to the origin server
            origin_socket.sendall(modified_request)

            # Receive the response from the origin server
            response_data = self.receive_origin_response(origin_socket)

            # Send the response back to the client
            client_socket.sendall(response_data)

            print(f"Completed request-response cycle for client {client_address}")

        except Exception as e:
            print(f"Error while handling client {client_address}: {e}")
        finally:
            # Return the connection to the pool or close it
            if origin_socket and not self.connection_is_closed(origin_socket):
                self.release_connection(origin_socket)
            else:
                if origin_socket:
                    origin_socket.close()

            # Ensure the client socket is closed
            client_socket.close()

    def connect_to_origin(self) -> socket.socket:
        """Connect to the origin server and return the socket object"""
        while not self.connection_pool.empty():
            origin_socket = self.connection_pool.get()
            if not self.connection_is_closed(origin_socket):
                return origin_socket

        # No reusable connection found, create a new one
        origin_socket = super().connect_to_origin()
        return origin_socket

    def connection_is_closed(self, origin_socket: socket.socket) -> bool:
        """Check if the connection to the origin server is closed"""
        try:
            origin_socket.setblocking(False)
            data = origin_socket.recv(1)
            origin_socket.setblocking(True)
            if data == b'':
                return True
        except (socket.error, BlockingIOError):
            pass
        finally:
            origin_socket.setblocking(True)
        return False

    def release_connection(self, origin_socket: socket.socket):
        """Release the connection to the origin server back to the connection pool"""
        self.connection_pool.put(origin_socket)

    def receive_origin_response(self, origin_socket: socket.socket) -> bytes:
        """Receive the response from the origin server and return the response data"""
        response_data = b''
        content_length = None
        while True:
            chunk = origin_socket.recv(4096)
            if not chunk:
                break
            response_data += chunk

            if b'\r\n\r\n' in response_data:  # Check if headers are received
                headers, body = response_data.split(b'\r\n\r\n', 1)
                header_lines = headers.split(b'\r\n')

                for line in header_lines:
                    if line.lower().startswith(b'content-length:'):
                        content_length = int(line.split(b': ')[1])
                        break

            if content_length and len(response_data.split(b'\r\n\r\n', 1)[1]) >= content_length:
                break

        return response_data

    def modify_request(self, request_data: bytes) -> bytes:
        """Modify the client request to keep the connection alive"""
        request_text = request_data.decode('iso-8859-1')
        
        headers, body = request_text.split('\r\n\r\n', 1)
        header_lines = headers.split('\r\n')

        connection_header_present = False
        for i, line in enumerate(header_lines):
            if line.lower().startswith('connection:'):
                header_lines[i] = 'Connection: keep-alive'
                connection_header_present = True
            if line == '':
                continue
        
        if not connection_header_present:
            header_lines.append('Connection: keep-alive')
        
        modified_request = '\r\n'.join(header_lines) + '\r\n\r\n' + body
        print(f"Modified request: {modified_request}")
        return modified_request.encode('iso-8859-1')

class CachingProxyServer(PersistentProxyServer):
    def __init__(
        self,
        cdn_addr: str,
        cdn_port: int,
        origin_addr: str,
        origin_port: int,
        cert_file: str,
        key_file: str,
        origin_domain: str,
        ignore_query_string: bool = False
    ):
        """Level 4: Caching Proxy that caches responses from the origin server
        - cdn_addr: IP address of the CDN server
        - cdn_port: Port number of the CDN server
        - origin_addr: IP address of the origin server
        - origin_port: Port number of the origin server
        - cert_file: Path to the SSL certificate file
        - key_file: Path to the SSL key file
        - origin_domain: Domain name of the origin server
        - ignore_query_string: Whether to ignore query string in cache key
        """
        super().__init__(cdn_addr, cdn_port, origin_addr, origin_port, cert_file, key_file, origin_domain)
        self.ignore_query_string = ignore_query_string
        self.cache = {}
        self.lock = threading.Lock()

   
    def handle_client(
        self, client_socket: ssl.SSLSocket, client_address: tuple[str, int]
    ):
        """Handle client connection by forwarding traffic to the origin server over HTTPS
        - Parse the request line to extract the request method and path.
        Format of request line: ``METHOD /path/to/file HTTP/1.1\\r\\n...``
        - You should only cache responses to ``GET`` requests
        - Derive the cache key from the request path based on the ``ignore_query_string`` flag
        - Return cached response if available, otherwise forward the request to the origin server
        - Cache the response from the origin server if it ``is_cacheable()``
        """
        print(f"Handling client {client_address} in a separate thread...")
        origin_socket = None

        try:
            # Receive and decode the client's request
            request_data = self.receive_client_request(client_socket)
            request_text = request_data.decode('iso-8859-1')
            request_line = request_text.split('\r\n')[0]
            method, path, _ = request_line.split(' ', 2)
            print(f"Received {method} request for {path} from client {client_address}")
            # Cache only GET requests
            if method == "GET":
                # Check if the response is cached
                 # Derive the cache key from the request path
                cache_key = path if not self.ignore_query_string else path.split('?', 1)[0]
                cached_response = self.cache_get(cache_key)
                print(f"Cache key: {cache_key}")
                if cached_response is not None:
                    print(f"Cache hit for {cache_key}. Sending cached response to client {client_address}")
                    client_socket.sendall(cached_response)
                else:
                    # Connect to the origin server
                    origin_socket = self.connect_to_origin()

                    # Send the request to the origin server
                    origin_socket.sendall(request_data)

                    # Receive the response from the origin server
                    response_data = self.receive_origin_response(origin_socket)

                    # Send the response to the client
                    client_socket.sendall(response_data)

                    # Cache the response if it is cacheable
                    response_headers = self.parse_response_headers(response_data.decode('iso-8859-1'))
                    if self.is_cacheable(path, response_headers):
                        print(f"Caching response for {cache_key}")
                        self.cache_put(response_data, cache_key)
            else:
                print(f"Non-GET request {method}. Forwarding without caching.")
                # Handle non-GET requests (no caching)
                origin_socket = self.connect_to_origin()
                origin_socket.sendall(request_data)
                response_data = self.receive_origin_response(origin_socket)
                client_socket.sendall(response_data)

            print(f"Completed request-response cycle for client {client_address}")

        except Exception as e:
            print(f"Error while handling client {client_address}: {e}")
        finally:
            # Close the origin socket if it was opened
            if origin_socket:
                try:
                    if not self.connection_is_closed(origin_socket):
                        self.release_connection(origin_socket)
                    else:
                        origin_socket.close()
                except Exception as e:
                    print(f"Error releasing origin connection: {e}")

            # Ensure the client socket is closed
            client_socket.close()


    def cache_get(self, path: str) -> bytes | None:
        """Query the cache for the response data associated with the given path
        - Return the response data if it is found in the cache, otherwise return ``None``
        """
        with self.lock:
            return self.cache.get(path)

    def cache_put(self, response_data: bytes, path: str):
        """Store the response data in the cache associated with the given path"""
        with self.lock:
            return self.cache.update({path: response_data})

    def is_cacheable(self, path: str, response_headers: dict) -> bool:
        """Check if the response is cacheable based on the request path and response headers
        - ``response_headers`` is obtained by ``parse_response_headers()``
        - You should make decisions based on the ``Cache-Control`` header (handling the
        ``no-store`` directive would be enough) and the file extension in the request path.
        - You are NOT required to handle headers such as ``ETag`` or ``Expires``.
        - You may want to handle the ``/`` path as a special case.
        """
        # Handle the '/' path as a special case (consider it non cacheable).
        if path == "/":
            return False
        
        # Get the Cache-Control header, if it exists.
        cache_control = response_headers.get("Cache-Control", "").lower()

        # If the 'no-store' directive is present, the response is not cacheable.
        if "no-store" in cache_control:
            return False
        
        # check if the path ends with an extension for dynamic content
        if path.endswith(('.php', '.cgi', '.asp', '.aspx', '.jsp','/time')):
            return False
        return True

    def parse_response_headers(self, header_str: str) -> dict:
        """A helper function to parse the response headers and return a dictionary
        - For example, given the headers ``HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n...``,
            return ``{'Content-Type': 'text/html', ...}``
        - ``header_str`` is a decoded string containing the response headers
        """
        headers = header_str.split('\r\n\r\n', 1)[0]
        header_lines = headers.split('\r\n')[1:]
        header_dict = {}
        for line in header_lines:
            key, value = line.split(': ', 1)
            header_dict[key] = value
        return header_dict
    


class ProxyServerLevel(Enum):
    TCP = 1
    TLS = 2
    PERSISTENT = 3
    CACHING = 4


def create_proxy_server(
    level: ProxyServerLevel | int,
    cdn_addr: str,
    cdn_port: int,
    origin_addr: str,
    origin_port: int,
    cert_file: str = "",
    key_file: str = "",
    origin_domain: str = "",
    ignore_query_string: bool = False,
):
    level = ProxyServerLevel(level)

    ServerClass = {
        ProxyServerLevel.TCP: TCPProxyServer,
        ProxyServerLevel.TLS: HTTPSProxyServer,
        ProxyServerLevel.PERSISTENT: PersistentProxyServer,
        ProxyServerLevel.CACHING: CachingProxyServer,
    }[level]

    args = (cdn_addr, cdn_port, origin_addr, origin_port)

    if level.value > 1:
        if not cert_file or not key_file or not origin_domain:
            raise ValueError(
                "cert_file, key_file, and origin_domain are required for Level 2 and above"
            )
        args += (cert_file, key_file, origin_domain)

    if level == ProxyServerLevel.CACHING:
        args += (ignore_query_string,)

    return ServerClass(*args)


def run_proxy(
    level: ProxyServerLevel | int,
    cdn_addr: str = "127.0.0.1",
    cdn_port: int = 4444,
    origin_addr: str = "",
    origin_port: int = 443,
    cert_file: str = "certs/cdn_cert.pem",
    key_file: str = "certs/cdn_key.pem",
    origin_domain: str = "",
    ignore_query_string: bool = False,
):
    proxy_server = create_proxy_server(
        level,
        cdn_addr,
        cdn_port,
        origin_addr,
        origin_port,
        cert_file,
        key_file,
        origin_domain,
        ignore_query_string,
    )
    proxy_server.start()


if __name__ == "__main__":
    fire.Fire(run_proxy)
