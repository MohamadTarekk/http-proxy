# Don't forget to change this file's name before submission.
import sys
import os
import enum
import re
import socket
import threading


cached_objects = {}


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        if requested_path == "":
            self.requested_path = "/"
        else:
            self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        (just join the already existing fields by \r\n)

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        try:
            request_line = self.method + ' ' + self.requested_path + ' ' + self.http_version
        except AttributeError:
            request_line = self.method + ' ' + self.requested_path + ' ' + 'HTTP/1.0'
        http_string = request_line + '\r\n'
        for i in range(0, len(self.headers)):
            http_string += (self.headers[i][0] + ': ' + self.headers[i][1] + '\r\n')
        http_string += '\r\n'
        return http_string

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        return str(self.code) + ' ' + self.message

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1
    BAD_REQUEST = 400, 'bad request\n'
    NOT_FOUND = 404, 'not found\n'
    NOT_IMPLEMENTED = 501, 'not implemented\n'


def entry_point(proxy_port_number):
    """
    Entry point, start your code here.

    Please don't delete this function,
    but feel free to modify the code
    inside it.
    """
    # 1 Setup sockets
    proxy_socket = setup_sockets(proxy_port_number)
    while True:
        # Establish connection
        client_socket, client_address = proxy_socket.accept()
        # Handle multiple clients
        new_client_thread = \
            threading.Thread(target=client_handler,
                             args=(proxy_socket, client_socket, client_address))
        new_client_thread.start()
        # Handle single client
        # client_handler(proxy_socket, client_socket, client_address)
    pass


def client_handler(proxy_socket: socket.socket,
                   client_socket: socket.socket,
                   client_address):
    # 1 Receive request from client
    raw_request_data = receive_request(client_socket, client_address)
    if raw_request_data == HttpRequestState.INVALID_INPUT:
        error_response_string = 'Cannot decode input!'
        print(error_response_string)
        error_response = HttpErrorResponse(HttpRequestState.BAD_REQUEST.value[0],
                                           HttpRequestState.BAD_REQUEST.value[1])
        error_response_string = error_response.to_http_string()
        error_response_bytes = \
            error_response.to_byte_array(error_response_string)
        send_reply(proxy_socket, client_socket, error_response_bytes)
        return
    # 2 Parse request and return error if any
    sanitized_request \
        = http_request_pipeline(client_address, raw_request_data)
    if isinstance(sanitized_request, HttpErrorResponse):
        error_response_string = sanitized_request.to_http_string()
        error_response_bytes = \
            sanitized_request.to_byte_array(error_response_string)
        send_reply(proxy_socket, client_socket, error_response_bytes)
        return
    # 3 Process request and get response
    html_response = process_request(sanitized_request)
    # 4 Send the response to the client
    send_reply(proxy_socket, client_socket, html_response)
    pass


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_address = ("127.0.0.1", proxy_port_number)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind(proxy_address)
    proxy_socket.listen(12)
    print("Starting HTTP proxy on port:", proxy_port_number)
    print(50 * '*')
    return proxy_socket


def receive_request(client_socket: socket.socket,
                    client_address):
    print("\n[LOG] Receiving HTTP request")
    # Receive request
    raw_request_data = ""
    while True:
        message = client_socket.recv(1024)
        try:
            message = message.decode("UTF-8")
        except UnicodeDecodeError:
            return client_socket, client_address, HttpRequestState.INVALID_INPUT
        if message == '\r\n':
            break
        raw_request_data += message
    raw_request_data = raw_request_data.splitlines()
    return raw_request_data


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    # Validate request
    try:
        request_state = check_http_request_validity(http_raw_data)
    # Return error if needed, then:
    except TypeError:
        error_response \
            = HttpErrorResponse(HttpRequestState.BAD_REQUEST.value[0],
                                HttpRequestState.BAD_REQUEST.value[1])
        return error_response
    # Return error if needed, then:
    if request_state == HttpRequestState.INVALID_INPUT:
        error_response \
            = HttpErrorResponse(HttpRequestState.BAD_REQUEST.value[0],
                                HttpRequestState.BAD_REQUEST.value[1])
        return error_response
    if request_state == HttpRequestState.NOT_SUPPORTED:
        error_response \
            = HttpErrorResponse(HttpRequestState.NOT_IMPLEMENTED.value[0],
                                HttpRequestState.NOT_IMPLEMENTED.value[1])
        return error_response
    # Parse the request
    request_info = parse_http_request(source_addr, http_raw_data)
    sanitize_http_request(request_info)
    return request_info


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid

    returns:
    One of values in HttpRequestState
    """
    print("[LOG] validating request")
    # Check if input data is empty
    if len(http_raw_data) == 0:
        return HttpRequestState.INVALID_INPUT
    # Split lines if needed
    if isinstance(http_raw_data, str):
        http_raw_data = http_raw_data.splitlines()
        while http_raw_data[-1] == '':
            http_raw_data.pop()
    # Parse request
    # noinspection RegExpRedundantEscape
    matches = re.findall(r'^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE'
                         r'|get|head|post|put|delete|conect|options|trace)'
                         r' (\/(?:(?:[\w\.\-_~@%#?&+=]+\/?)*)?'
                         r'|'
                         r'(?:http:\/\/)?'
                         r'([\w\.\-_~]{2,256}\.[a-z]{2,6})'
                         r'(?::([1-6][0-5][0-5][0-3][0-5]|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9]))?'
                         r'(\/(?:(?:[\w\.\-_~@%#?&+=]+\/?)*)?)?) '
                         r'(HTTP\/(?:0\.9|1\.0|1\.1|2\.0|3\.0))$', http_raw_data[0])
    # Check if format is valid
    if not matches:
        print(f"[WARN] Request is invalid (Invalid body) [{http_raw_data[0]}]")
        return HttpRequestState.INVALID_INPUT
    method = matches[0][0]
    # Validate headers
    host = matches[0][1]
    host_found = False
    for i in range(1, len(http_raw_data)):
        matches = re.findall(r'^(\w+): (.+)$', http_raw_data[i])
        if not matches:
            print(f"[WARN] Request is invalid (Invalid header) at {http_raw_data[i]}")
            return HttpRequestState.INVALID_INPUT
        if matches[0][0].lower() == 'host':
            # Check if no host header is needed
            if host[0] != '/':
                return HttpRequestState.INVALID_INPUT
            # Validate host name
            # noinspection RegExpRedundantEscape
            host_url = re.findall(r'^(?:http:\/\/)?'
                                  r'([\w\.\-_~]{2,256}\.[a-z]{2,6})'
                                  r'(?::([1-6][0-5][0-5][0-3][0-5]|'
                                  r'[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9]))?',
                                  matches[0][1])
            if host_url:
                host_found = True
    # Check host name
    if (host[0] == '/') and (not host_found):
        print(f"[WARN] Request is invalid [{http_raw_data}]")
        return HttpRequestState.INVALID_INPUT
    # Validate method
    if method.upper() != 'GET':
        print(f"[WARN] Method not implemented [{http_raw_data}]")
        return HttpRequestState.NOT_SUPPORTED
    print(f"[LOG] Request is correct.")
    return HttpRequestState.GOOD


def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    print("[LOG] Parsing request")
    # Split lines if needed
    if isinstance(http_raw_data, str):
        http_raw_data = http_raw_data.splitlines()
        while http_raw_data[-1] == '':
            http_raw_data.pop()
    # Parse request
    # noinspection RegExpRedundantEscape
    matches = re.findall(r'^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE'
                         r'|get|head|post|put|delete|conect|options|trace)'
                         r' (\/(?:(?:[\w\.\-_~@%#?&+=]+\/?)*)?'
                         r'|'
                         r'(?:http:\/\/)?'
                         r'([\w\.\-_~]{2,256}\.[a-z]{2,6})'
                         r'(?::([1-6][0-5][0-5][0-3][0-5]|[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9]))?'
                         r'(\/(?:(?:[\w\.\-_~@%#?&+=]+\/?)*)?)?) '
                         r'(HTTP\/\d\.\d)$', http_raw_data[0])[0]
    # Extract request parameters
    method = matches[0].upper()
    host = matches[2]
    port = matches[3]
    path = matches[4]
    version = matches[5]
    # Extract headers
    headers = []
    for i in range(1, len(http_raw_data)):
        header = re.findall(r'^(\w+): (.+)$', http_raw_data[i])[0]
        if header[0].lower() == 'host':
            # noinspection RegExpRedundantEscape
            host_url = re.findall(r'^(?:http:\/\/)?'
                                  r'([\w\.\-_~]{2,256}\.[a-z]{2,6})'
                                  r'(?::([1-6][0-5][0-5][0-3][0-5]|'
                                  r'[1-9][0-9]{3}|[1-9][0-9]{2}|[1-9][0-9]|[0-9]))?',
                                  header[1])[0]
            path = matches[1]
            host = host_url[0]
            port = host_url[1]
            headers.append(['Host', host])
            continue
        headers.append([header[0], header[1]])
    try:
        ret = HttpRequestInfo(source_addr, method, host, int(port), path, headers)
        ret.http_version = version
    except ValueError:
        ret = HttpRequestInfo(source_addr, method, host, 80, path, headers)
        ret.http_version = version
    return ret


def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.

    for example, expand a full URL to relative path + Host header.

    returns:
    nothing, but modifies the input object
    """
    print("[LOG] Sanitizing request")
    found_host = False
    for i in range(0, len(request_info.headers)):
        if request_info.headers[i][0] == 'Host':
            found_host = True
            break
    if not found_host:
        host_url = request_info.requested_host
        request_info.headers.append(["Host", host_url])
    return


def process_request(sanitized_request: HttpRequestInfo):
    # Get the response from cache if any
    if sanitized_request.to_http_string() in cached_objects:
        return cached_objects[sanitized_request.to_http_string()]
    # Setup a client socket for the proxy to communicate with the server
    proxy_client_socket = setup_proxy_client(sanitized_request.requested_host,
                                             sanitized_request.requested_port)
    # Send request to server
    send_request(proxy_client_socket, sanitized_request)
    # Receive response from server
    html_response = receive_html(proxy_client_socket, sanitized_request)
    # Cache the server response
    cached_objects[sanitized_request.to_http_string()] = html_response
    return html_response


def setup_proxy_client(server_address, server_port):
    print("[LOG] Setup socket for contacting ", server_address, " at port ", server_port)
    proxy_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_client_socket.connect((server_address, server_port))
    return proxy_client_socket


def send_request(proxy_client_socket: socket.socket, sanitized_request: HttpRequestInfo):
    print("[LOG] Sending request to server")
    http_request_string = sanitized_request.to_http_string()
    http_request_bytes = sanitized_request.to_byte_array(http_request_string)
    print(http_request_string)
    proxy_client_socket.send(http_request_bytes)
    return


def receive_html(proxy_client_socket: socket.socket, sanitized_request: HttpRequestInfo):
    server_address = (sanitized_request.requested_host,
                      sanitized_request.requested_port)
    print("[LOG] Receiving server response")
    html_response = bytes("", "UTF-8")
    while True:
        response, source_address = proxy_client_socket.recvfrom(64)
        if not response:
            break
        html_response += response
    return html_response


def send_reply(proxy_socket: socket.socket, client_socket: socket.socket, html_response):
    print("[LOG] Sending response to client")
    client_socket.send(html_response)
    client_socket.close()
    # proxy_socket.shutdown(1)
    # proxy_socket.close()
    return


#######################################
# Leave the code below as is.
#######################################


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = int(get_arg(1, 18888))
    entry_point(proxy_port_number)
    '''
    strng = ['GET / HTTP/1.0', 'Host: www.google.com']
    check_http_request_validity(strng)
    strng = ['GET /MohamadTarekk/xinu-bare HTTP/1.0', 'Host: github.com:80']
    check_http_request_validity(strng)
    strng = ['GET github.com/MohamadTarekk/xinu-bare HTTP/1.0']
    check_http_request_validity(strng)
    strng = ['GET http://www.github.com/MohamadTarekk/xinu-bare HTTP/1.0']
    check_http_request_validity(strng)
    strng = ['GET http://www.github.com:5/MohamadTarekk/xinu-bare HTTP/1.0']
    check_http_request_validity(strng)
    strng = ['GET google.com HTTP/1.0']
    check_http_request_validity(strng)
    '''


if __name__ == "__main__":
    main()
