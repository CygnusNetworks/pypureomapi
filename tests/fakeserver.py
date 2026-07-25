"""A minimal in-process OMAPI server for end-to-end client tests.

It speaks the real wire protocol using pypureomapi's own InBuffer/OmapiMessage
code over a loopback socket, so the full Omapi client path (TCPClientTransport,
handshake, signing, query/response) is exercised without a real dhcpd.

Usage:

    def responder(request):
        return OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[(b"ip-address", ...)])

    with FakeOmapiServer(responder) as srv:
        omapi = pypureomapi.Omapi("127.0.0.1", srv.port)
        ...
"""

import socket
import threading

import pypureomapi
from pypureomapi import OmapiMessage, OMAPI_OP_UPDATE


class FakeOmapiServer:
	"""Serve exactly one connection on 127.0.0.1.

	@param responder: callable(OmapiMessage) -> OmapiMessage. Called for every
		client message except the authenticator handshake, which is answered
		automatically when key/user are given.
	@param key: base64 key (bytes) matching the client, enabling HMAC-MD5. When
		set, the server assigns authid and signs post-handshake responses.
	"""

	def __init__(self, responder, user=b"user", key=None, authid=3,
			auth_response=None, bad_rid=False, corrupt_sig=False,
			unsigned_response=False):
		self.responder = responder
		self.user = user
		self.key = key
		self.authid = authid
		# Override the reply to the authenticator open (to exercise client-side
		# error handling); defaults to a successful UPDATE handing out authid.
		self.auth_response = auth_response
		self.bad_rid = bad_rid
		self.corrupt_sig = corrupt_sig
		# Reply under the null authenticator even after HMAC negotiation, to
		# exercise the client's "wrong authenticator" check.
		self.unsigned_response = unsigned_response
		self.exc = None
		self._closing = False
		self._conn = None
		self._sock = socket.socket()
		self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self._sock.bind(("127.0.0.1", 0))
		self._sock.listen(1)
		self.port = self._sock.getsockname()[1]
		self._thread = threading.Thread(target=self._serve, daemon=True)

	def __enter__(self):
		self._thread.start()
		return self

	def __exit__(self, *exc):
		# Unblock the server thread even if a test left the connection open
		# (e.g. after an expected client-side error).
		self._closing = True
		self._sock.close()
		if self._conn is not None:
			# shutdown() (not just close()) reliably wakes a recv() blocked in
			# the server thread when a test left its client socket open.
			try:
				self._conn.shutdown(socket.SHUT_RDWR)
			except OSError:
				pass
			self._conn.close()
		self._thread.join(timeout=5)
		# Surface genuine server-side failures to the test.
		if self.exc is not None:
			raise self.exc

	@staticmethod
	def _read_next(conn, inbuf, parser):
		"""Drive a pypureomapi parser, feeding socket data until it yields a value."""
		while True:
			result = next(parser)
			if result is not None:
				return result
			data = conn.recv(4096)
			if not data:
				return None
			inbuf.feed(data)

	def _serve(self):
		try:
			conn, _ = self._sock.accept()
			self._conn = conn
			inbuf = pypureomapi.InBuffer()

			# Protocol handshake: read the client's startup, reply with ours.
			startup = self._read_next(conn, inbuf, inbuf.parse_startup_message())
			assert startup is not None
			startup.validate()
			inbuf.resetsize()
			conn.sendall(pypureomapi.OmapiStartupMessage().as_string())

			authenticator = None
			auth_active = False
			if self.key is not None:
				authenticator = pypureomapi.OmapiHMACMD5Authenticator(self.user, self.key)
				authenticator.authid = self.authid

			while True:
				request = self._read_next(conn, inbuf, inbuf.parse_message())
				if request is None:
					break
				inbuf.resetsize()

				# The authenticator-open response itself is still verified under
				# the null authenticator; only later messages use HMAC.
				sign_with_hmac = auth_active
				if authenticator is not None and dict(request.message).get(b"type") == b"authenticator":
					if self.auth_response is not None:
						response = self.auth_response
					else:
						response = OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=self.authid)
						auth_active = True
				else:
					response = self.responder(request)

				if response is None:
					# Simulate the server hanging up mid-conversation.
					break

				response.rid = request.tid + 1 if self.bad_rid else request.tid
				if sign_with_hmac and not self.unsigned_response:
					response.sign(authenticator)
				else:
					response.authid = 0
					response.signature = b"\x01" if self.corrupt_sig else b""
				conn.sendall(response.as_string())

			# Hang up so a waiting client sees the connection close promptly.
			conn.close()
		except Exception as exc:  # pragma: no cover - surfaced via __exit__
			# A socket error caused by __exit__ closing the connection is expected.
			if not self._closing:
				self.exc = exc
