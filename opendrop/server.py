"""
OpenDrop: an open source AirDrop implementation
Copyright (C) 2018  Milan Stute
Copyright (C) 2018  Alexander Heinrich

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import io
import json
import logging
import os
import platform
import plistlib
import socket
import struct
import time
import traceback
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

import libarchive
import libarchive.extract
import libarchive.read
from zeroconf import IPVersion, ServiceInfo, Zeroconf

from .util import AirDropUtil

logger = logging.getLogger(__name__)


def _dvzip_decompress(data: bytes) -> bytes:
    """Decompress Apple DVZip: repeated (4-byte BE length + zlib block) until exhausted."""
    out = io.BytesIO()
    offset = 0
    while offset + 4 <= len(data):
        (chunk_len,) = struct.unpack_from(">I", data, offset)
        offset += 4
        if chunk_len == 0:
            break
        if offset + chunk_len > len(data):
            logger.warning(f"DVZip: truncated chunk at offset {offset}, expected {chunk_len} bytes")
            break
        chunk = data[offset: offset + chunk_len]
        offset += chunk_len
        try:
            out.write(zlib.decompress(chunk, wbits=-15))  # raw deflate
        except zlib.error:
            try:
                out.write(zlib.decompress(chunk))  # zlib wrapper
            except zlib.error:
                try:
                    import gzip
                    out.write(gzip.decompress(chunk))  # gzip wrapper
                except Exception:
                    out.write(chunk)  # store raw on failure
    return out.getvalue()


class AirDropServer:
    """
    Announces an HTTPS AirDrop server in the local network via mDNS.
    """

    def __init__(self, config):
        self.config = config

        # Use IPv6
        self.serveraddress = ("::", self.config.port)
        self.ServerClass = HTTPServerV6
        self.ServerClass.allow_reuse_address = False

        self.ip_addr = AirDropUtil.get_ip_for_interface(
            self.config.interface, ipv6=True
        )
        if self.ip_addr is None:
            if self.config.interface == "awdl0":
                raise RuntimeError(
                    f"Interface {self.config.interface} does not have an IPv6 address. Make sure that `owl` is running."
                )
            else:
                raise RuntimeError(
                    f"Interface {self.config.interface} does not have an IPv6 address"
                )

        self.Handler = AirDropServerHandler
        self.Handler.config = self.config

        self.zeroconf = Zeroconf(
            interfaces=[str(self.ip_addr)],
            ip_version=IPVersion.V6Only,
            apple_p2p=platform.system() == "Darwin",
        )

        self.http_server = self._init_server()
        self.service_info = self._init_service()

    def _init_service(self):
        properties = self.get_properties()
        server = self.config.host_name + ".local."
        service_name = self.config.service_id + "._airdrop._tcp.local."
        info = ServiceInfo(
            "_airdrop._tcp.local.",
            service_name,
            port=self.config.port,
            properties=properties,
            server=server,
            addresses=[self.ip_addr.packed],
        )
        return info

    def start_service(self):
        logger.info(
            f"Announcing service: host {self.config.host_name}, address {self.ip_addr}, port {self.config.port}"
        )
        self.zeroconf.register_service(self.service_info)

    def _init_server(self):
        try:
            httpd = self.ServerClass(self.serveraddress, self.Handler)
        except OSError:
            # Address in use. Change port
            self.config.port = self.config.port + 1
            self.serveraddress = (self.serveraddress[0], self.config.port)
            httpd = self.ServerClass(self.serveraddress, self.Handler)

        # Adapt socket for awdl0
        if self.config.interface == "awdl0" and platform.system() == "Darwin":
            httpd.socket.setsockopt(socket.SOL_SOCKET, 0x1104, 1)

        httpd.socket = self.config.get_ssl_context().wrap_socket(
            sock=httpd.socket, server_side=True
        )

        return httpd

    def start_server(self):
        logger.info("Starting HTTPS server")
        self.http_server.serve_forever()

    def stop(self):
        self.zeroconf.unregister_all_services()
        self.http_server.shutdown()

    def get_properties(self):
        properties = {b"flags": str(self.config.flags).encode("utf-8")}
        return properties


class HTTPServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def handle_error(self, request, client_address):
        import traceback, logging
        logging.getLogger(__name__).error(
            f"Error handling request from {client_address}:\n{traceback.format_exc()}"
        )


class AirDropServerHandler(BaseHTTPRequestHandler):
    """
    Server which responds to AirDrop HTTP POST requests
    """

    protocol_version = "HTTP/1.1"
    config = None

    def _set_response(self, content_length, keep_alive=True):
        """
        Setting the default values for a successful response
        """
        self.send_response(200)
        self.send_header("Content-Length", content_length)
        self.send_header("Content-Type", "application/octet-stream")
        if keep_alive:
            self.send_header("Connection", "keep-alive")
        self.end_headers()

    def do_HEAD(self):
        """
        Answer head requests
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """
        Answer get requests
        """
        logger.debug(f"GET request at {self.path}")
        body = "\n".encode("utf-8")
        self._set_response(len(body))
        self.wfile.write(body)

    def _read_request_body(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            body = b""
            while True:
                line = self.rfile.readline().rstrip(b"\r\n")
                chunk_size = int(line, 16)
                if chunk_size == 0:
                    self.rfile.readline()  # trailing CRLF
                    break
                body += self.rfile.read(chunk_size)
                self.rfile.readline()  # CRLF after chunk
            return body
        else:
            content_length = int(self.headers.get("Content-Length") or self.headers.get("content-length") or 0)
            return self.rfile.read(content_length)

    def handle_discover(self):
        post_data = self._read_request_body()

        AirDropUtil.write_debug(
            self.config, post_data, "receive_discover_request.plist"
        )

        # sample media capabilities as recorded from macOS 10.13.3
        media_capabilities = {
            "Version": 1,
            # don't advertise any codec/container support so we receive legacy file formats (JPEG instead of HEIF, etc.)
            # 'Codecs': {
            #     'hvc1': {
            #         'Profiles': {
            #             'VTPerProfileSupport': {
            #                 '1': {'VTMaxPlaybackLevel': 120},
            #                 '2': {'VTMaxPlaybackLevel': 120},
            #                 '3': {}
            #             },
            #             'VTSupportedProfiles': [1, 2, 3]
            #         }
            #     }
            # },
            # 'ContainerFormats': {
            #     'public.heif-standard': {
            #         'HeifSubtypes': ['public.avci', 'public.heic', 'public.heif']
            #     }
            # },
            # 'Vendor': {
            #     'com.apple': {
            #         'OSVersion': [10, 13, 3],
            #         'OSBuildVersion': '17D102',
            #         'LivePhotoFormatVersion': '1'
            #     }
            # }
        }
        media_capabilities_json = json.JSONEncoder().encode(media_capabilities)
        media_capabilities_binary = media_capabilities_json.encode("utf-8")
        discover_answer = {
            "ReceiverMediaCapabilities": media_capabilities_binary,
            "ReceiverComputerName": self.config.computer_name,
            "ReceiverModelName": self.config.computer_model,
        }
        if self.config.record_data:
            discover_answer["ReceiverRecordData"] = self.config.record_data

        discover_answer_binary = plistlib.dumps(
            discover_answer, fmt=plistlib.FMT_BINARY  # pylint: disable=no-member
        )

        AirDropUtil.write_debug(
            self.config, discover_answer_binary, "receive_discover_response.plist"
        )

        # Change to actual length
        self._set_response(len(discover_answer_binary))
        self.wfile.write(discover_answer_binary)

    def handle_ask(self):
        conn_header = self.headers.get("Connection", "<not set>")
        logger.info(f"/Ask Connection header from client: {conn_header!r}")
        post_data = self._read_request_body()

        AirDropUtil.write_debug(self.config, post_data, "receive_ask_request.plist")

        ask_response = {
            "ReceiverModelName": self.config.computer_model,
            "ReceiverComputerName": self.config.computer_name,
        }
        ask_resp_binary = plistlib.dumps(
            ask_response, fmt=plistlib.FMT_BINARY  # pylint: disable=no-member
        )

        AirDropUtil.write_debug(
            self.config, ask_resp_binary, "receive_ask_response.plist"
        )

        # Force the connection to stay open so /Upload can arrive on the same
        # persistent TLS connection. iOS interprets a FIN after /Ask as "declined".
        self.close_connection = False
        self._set_response(len(ask_resp_binary))
        self.wfile.write(ask_resp_binary)
        self.wfile.flush()
        logger.info("/Ask response sent, keeping connection alive for /Upload")

    def handle_upload(self):
        content_type = self.headers.get("content-type", "").lower()
        if content_type not in ("application/x-cpio", "application/x-dvzip"):
            logger.warning(f"Unsupported content-type: {content_type}")
            self.send_response(406)
            self.send_header("Content-Length", 0)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # If pipelining is not support, 'Expect: 100-continue' is sent to which we need to respond
        if self.headers.get("expect", "").lower() == "100-continue":
            self.send_response(100)
            self.send_header("Content-Length", 0)
            self.end_headers()

        if self.headers.get("transfer-encoding", "").lower() != "chunked":
            logger.warning("Expect chunked transfer encoding")
            self.send_response(400)  # Bad Request
            self.send_header("Transfer-Encoding", "Chunked")
            self.send_header("Content-Length", 0)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        class HTTPChunkedReader(io.RawIOBase):
            def __init__(self, rfile, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.rfile = rfile
                self.chunk = None
                self.total = 0

            def _next_chunk(self):
                if self.chunk is None or len(self.chunk) == 0:
                    length = int(self.rfile.readline().rstrip(), 16)
                    self.chunk = self.rfile.read(length)
                    self.rfile.readline()  # strip trailing \n\r

            def readinto(self, buf):
                self._next_chunk()
                length = min(len(self.chunk), len(buf))
                buf[:length] = self.chunk[:length]
                self.chunk = self.chunk[length:]
                self.total += length
                return length

        logger.info("Receiving file(s) ...")
        start = time.time()
        reader = HTTPChunkedReader(self.rfile)
        raw = reader.read()  # read all chunks into memory

        content_type = self.headers.get("content-type", "").lower()
        dest_dir = "/home/vardhv/Downloads"
        os.makedirs(dest_dir, exist_ok=True)
        orig_dir = os.getcwd()
        os.chdir(dest_dir)
        try:
            if "dvzip" in content_type:
                cpio_data = _dvzip_decompress(raw)
                logger.info(f"DVZip: {len(raw)} → {len(cpio_data)} bytes CPIO")
                with libarchive.read.memory_reader(cpio_data) as archive:
                    libarchive.extract.extract_entries(archive)
            else:
                with libarchive.read.memory_reader(raw) as archive:
                    libarchive.extract.extract_entries(archive)
        except Exception as e:
            logger.error(f"Extraction failed: {e}\n{traceback.format_exc()}")
            os.chdir(orig_dir)
            self.send_response(500)
            self.send_header("Content-Length", 0)
            self.send_header("Connection", "close")
            self.end_headers()
            return
        finally:
            os.chdir(orig_dir)

        transferred = len(raw) / 1024.0 / 1024.0
        speed = transferred / (time.time() - start)
        logger.info(f"File(s) received in {dest_dir} ({transferred:.02f} MB, {speed:.02f} MB/s)")

        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Length", 0)
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self):
        """
        Handle post requests
        """

        logger.info(
            f"POST {self.path} from {self.client_address[0]} "
            f"[Connection: {self.headers.get('Connection', '<not set>')!r}]"
        )
        logger.debug(f"Headers\n{self.headers}")

        if self.path == "/Discover":
            self.handle_discover()
        elif self.path == "/Ask":
            self.handle_ask()
        elif self.path == "/Upload":
            self.handle_upload()
        else:
            logger.debug(f"POST request at {self.path}")
            self.send_response(400)
            self.send_header("Content-Length", 0)
            self.end_headers()

    def log_message(self, format, *args):
        # pylint: disable=redefined-builtin
        logger.debug(
            f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format % args}"
        )
