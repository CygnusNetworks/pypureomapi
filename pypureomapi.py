#!/usr/bin/env python3
# pylint:disable=too-many-lines

# library for communicating with an isc dhcp server over the omapi protocol
#
# Copyright 2010-2017 Cygnus Networks GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Message format:

# authid (netint32)
# authlen (netint32)
# opcode (netint32)
# handle (netint32)
# tid (netint32)
# rid (netint32)
# message (dictionary)
# object (dictionary)
# signature (length is authlen)

# dictionary = entry* 0x00 0x00
# entry = key (net16str) value (net32str)

import binascii
import struct
import hashlib
import hmac
import io
import logging
import socket
import random
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

_T = TypeVar("_T")
_U = TypeVar("_U")

__author__ = "Helmut Grohne, Dr. Torge Szczepanek"
__copyright__ = "Cygnus Networks GmbH"
__license__ = "Apache-2.0"
__version__ = "1.0"
__maintainer__ = "Dr. Torge Szczepanek"
__email__ = "debian@cygnusnetworks.de"


__all__ = []

logger = logging.getLogger("pypureomapi")
sysrand = random.SystemRandom()

__all__.extend("OMAPI_OP_OPEN OMAPI_OP_REFRESH OMAPI_OP_UPDATE".split())
__all__.extend("OMAPI_OP_NOTIFY OMAPI_OP_STATUS OMAPI_OP_DELETE".split())
OMAPI_OP_OPEN = 1
OMAPI_OP_REFRESH = 2
OMAPI_OP_UPDATE = 3
OMAPI_OP_NOTIFY = 4
OMAPI_OP_STATUS = 5
OMAPI_OP_DELETE = 6


def repr_opcode(opcode: int) -> str:
	"""Returns a textual representation for the given opcode."""
	opmap = {1: "open", 2: "refresh", 3: "update", 4: "notify", 5: "status", 6: "delete"}
	return opmap.get(opcode, f"unknown ({opcode:d})")


__all__.append("OmapiError")


class OmapiError(Exception):
	"""OMAPI exception base class."""


__all__.append("OmapiSizeLimitError")


class OmapiSizeLimitError(OmapiError):
	"""Packet size limit reached."""
	def __init__(self) -> None:
		OmapiError.__init__(self, "Packet size limit reached.")


__all__.append("OmapiErrorNotFound")


class OmapiErrorNotFound(OmapiError):
	"""Not found."""
	def __init__(self) -> None:
		OmapiError.__init__(self, "not found")


__all__.append("OmapiErrorAttributeNotFound")


class OmapiErrorAttributeNotFound(OmapiErrorNotFound):
	"""Attribute not found."""
	def __init__(self) -> None:  # pylint:disable=super-init-not-called
		OmapiError.__init__(self, "attribute not found")  # pylint:disable=non-parent-init-called


class OutBuffer:
	"""Helper class for constructing network packets."""
	sizelimit = 65536

	def __init__(self) -> None:
		self.buff = io.BytesIO()

	def __len__(self) -> int:
		"""Return the number of bytes in the buffer."""
		return int(self.buff.tell())

	def add(self, data: bytes) -> "OutBuffer":
		"""
		>>> ob = OutBuffer().add(OutBuffer.sizelimit * b"x")
		>>> ob.add(b"y") # doctest: +ELLIPSIS
		Traceback (most recent call last):
		...
		OmapiSizeLimitError: ...

		@raises OmapiSizeLimitError:
		"""
		if len(self) + len(data) > self.sizelimit:
			raise OmapiSizeLimitError()
		self.buff.write(data)
		return self

	def add_net32int(self, integer: int) -> "OutBuffer":
		"""Append a 32bit unsigned integer.
		@raises OmapiSizeLimitError:
		"""
		if integer < 0 or integer >= (1 << 32):
			raise ValueError("not a 32bit unsigned integer")
		return self.add(struct.pack("!L", integer))

	def add_net16int(self, integer: int) -> "OutBuffer":
		"""Append a 16bit unsigned integer.
		@raises OmapiSizeLimitError:
		"""
		if integer < 0 or integer >= (1 << 16):
			raise ValueError("not a 16bit unsigned integer")
		return self.add(struct.pack("!H", integer))

	def add_net32string(self, string: bytes) -> "OutBuffer":
		"""Append a string prefixed with its length as a 32bit integer.

		>>> r = b'\\x00\\x00\\x00\\x01x'
		>>> OutBuffer().add_net32string(b"x").getvalue() == r
		True

		@raises OmapiSizeLimitError:
		"""
		if len(string) >= (1 << 32):
			raise ValueError("string too long")
		return self.add_net32int(len(string)).add(string)

	def add_net16string(self, string: bytes) -> "OutBuffer":
		"""Append a string prefixed with its length as a 16bit integer.

		>>> OutBuffer().add_net16string(b"x").getvalue() == b'\\x00\\x01x'
		True

		@raises OmapiSizeLimitError:
		"""
		if len(string) >= (1 << 16):
			raise ValueError("string too long")
		return self.add_net16int(len(string)).add(string)

	def add_bindict(self, items: "list[tuple[bytes, bytes]] | dict[bytes, bytes]") -> "OutBuffer":
		"""
		>>> r = b'\\x00\\x03foo\\x00\\x00\\x00\\x03bar\\x00\\x00'
		>>> OutBuffer().add_bindict({b"foo": b"bar"}).getvalue() == r
		True

		@raises OmapiSizeLimitError:
		"""
		if isinstance(items, dict):
			items = list(items.items())
		for key, value in items:
			self.add_net16string(key).add_net32string(value)
		return self.add(b"\x00\x00")  # end marker

	def getvalue(self) -> bytes:
		"""
		>>> OutBuffer().add(b"sp").add(b"am").getvalue() == b"spam"
		True
		"""
		return self.buff.getvalue()

	def consume(self, length: int) -> "OutBuffer":
		"""
		>>> OutBuffer().add(b"spam").consume(2).getvalue() == b"am"
		True
		"""
		self.buff = io.BytesIO(self.getvalue()[length:])
		return self


class OmapiStartupMessage:
	"""Class describing the protocol negotiation messages.

	>>> s = OmapiStartupMessage().as_string()
	>>> s == b"\\0\\0\\0\\x64\\0\\0\\0\\x18"
	True
	>>> next(InBuffer(s).parse_startup_message()).validate()
	>>> OmapiStartupMessage(42).validate()
	Traceback (most recent call last):
	...
	OmapiError: protocol mismatch
	"""
	implemented_protocol_version = 100
	implemented_header_size = 4 * 6

	def __init__(self, protocol_version: "int | None" = None, header_size: "int | None" = None) -> None:
		if protocol_version is None:
			protocol_version = self.implemented_protocol_version
		if header_size is None:
			header_size = self.implemented_header_size
		self.protocol_version = protocol_version
		self.header_size = header_size

	def validate(self) -> None:
		"""Checks whether this OmapiStartupMessage matches the implementation.
		@raises OmapiError:
		"""
		if self.implemented_protocol_version != self.protocol_version:
			raise OmapiError("protocol mismatch")
		if self.implemented_header_size != self.header_size:
			raise OmapiError("header size mismatch")

	def as_string(self) -> bytes:
		ret = OutBuffer()
		self.serialize(ret)
		return ret.getvalue()

	def serialize(self, outbuffer: OutBuffer) -> None:
		"""Serialize this OmapiStartupMessage to the given outbuffer."""
		outbuffer.add_net32int(self.protocol_version)
		outbuffer.add_net32int(self.header_size)

	def dump_oneline(self) -> str:
		"""@returns: a human readable representation in one line"""
		return f"protocol_version={self.protocol_version:d} header_size={self.header_size:d}"


class OmapiAuthenticatorBase:
	"""Base class for OMAPI authenticators.
	@cvar authlen: is the length of a signature as returned by the sign method
	@cvar algorithm: is a textual name for the algorithm
	@ivar authid: is the authenticator id as assigned during the handshake
	"""
	authlen = -1  # must be overwritten
	algorithm: "bytes | None" = None
	authid = -1  # will be an instance attribute

	def __init__(self) -> None:
		pass

	def auth_object(self) -> "dict[bytes, bytes]":
		"""@returns: object part of an omapi authentication message"""
		raise NotImplementedError

	def sign(self, message: bytes) -> bytes:
		"""@returns: a signature of length self.authlen"""
		raise NotImplementedError()


class OmapiNullAuthenticator(OmapiAuthenticatorBase):
	authlen = 0
	authid = 0  # always 0

	def __init__(self) -> None:
		OmapiAuthenticatorBase.__init__(self)

	def auth_object(self) -> "dict[bytes, bytes]":
		return {}

	def sign(self, message: bytes) -> bytes:
		return b""


class OmapiHMACMD5Authenticator(OmapiAuthenticatorBase):
	authlen = 16
	algorithm = b"hmac-md5.SIG-ALG.REG.INT."

	def __init__(self, user: bytes, key: bytes) -> None:
		"""
		@param key: base64 encoded key
		@raises binascii.Error: for bad base64 encoding
		"""
		OmapiAuthenticatorBase.__init__(self)
		assert isinstance(user, bytes)
		self.user = user
		assert isinstance(key, bytes)
		self.key = binascii.a2b_base64(key)

	def auth_object(self) -> "dict[bytes, bytes]":
		return {b"name": self.user, b"algorithm": self.algorithm}

	def sign(self, message: bytes) -> bytes:
		"""
		>>> authlen = OmapiHMACMD5Authenticator.authlen
		>>> len(OmapiHMACMD5Authenticator(b"foo", 16*b"x").sign(b"baz")) == authlen
		True

		@returns: a signature of length self.authlen
		"""
		return hmac.HMAC(self.key, message, digestmod=hashlib.md5).digest()


__all__.append("OmapiMessage")


class OmapiMessage:  # pylint:disable=too-many-instance-attributes
	"""
	@ivar authid: The id of the message authenticator.
	@ivar opcode: One out of
			OMAPI_OP_{OPEN,REFRESH,UPDATE,NOTIFY,STATUS,DELETE}.
	@ivar handle: The id of a handle acquired from a previous request or 0.
	@ivar tid: Transmission identifier.
	@ivar rid: Receive identifier (of a response is the tid of the request).
	@ivar message: A list of (key, value) pairs.
	@ivar obj: A list of (key, value) pairs.
	@ivar signature: A signature on this message as generated by an
			authenticator.
	"""
	def __init__(self, authid: int = 0, opcode: int = 0, handle: int = 0, tid: int = 0, rid: int = 0, message: "list[tuple[bytes, bytes]] | None" = None, obj: "list[tuple[bytes, bytes]] | None" = None, signature: bytes = b"") -> None:  # pylint:disable=too-many-arguments
		"""
		Construct an OmapiMessage from the given fields. No error
		checking is performed.

		@param tid: The special value -1 causes a tid to be generated randomly.
		"""
		self.authid, self.opcode, self.handle = authid, opcode, handle
		self.handle, self.tid, self.rid = handle, tid, rid
		self.message = message or []
		self.obj = obj or []
		self.signature = signature

		if self.tid == -1:
			self.generate_tid()

	def generate_tid(self) -> None:
		"""Generate a random transmission id for this OMAPI message.

		>>> OmapiMessage(tid=-1).tid != OmapiMessage(tid=-1).tid
		True
		"""
		self.tid = sysrand.randrange(0, 1 << 32)

	def serialize(self, outbuffer: OutBuffer, forsigning: bool = False) -> None:
		"""
		@raises OmapiSizeLimitError:
		"""
		if not forsigning:
			outbuffer.add_net32int(self.authid)
		outbuffer.add_net32int(len(self.signature))
		outbuffer.add_net32int(self.opcode)
		outbuffer.add_net32int(self.handle)
		outbuffer.add_net32int(self.tid)
		outbuffer.add_net32int(self.rid)
		outbuffer.add_bindict(self.message)
		outbuffer.add_bindict(self.obj)
		if not forsigning:
			outbuffer.add(self.signature)

	def as_string(self, forsigning: bool = False) -> bytes:
		"""
		>>> len(OmapiMessage().as_string(True)) >= 24
		True

		@raises OmapiSizeLimitError:
		"""
		ret = OutBuffer()
		self.serialize(ret, forsigning)
		return ret.getvalue()

	def sign(self, authenticator: OmapiAuthenticatorBase) -> None:
		"""Sign this OMAPI message."""
		self.authid = authenticator.authid
		self.signature = b"\0" * authenticator.authlen  # provide authlen
		self.signature = authenticator.sign(self.as_string(forsigning=True))
		assert len(self.signature) == authenticator.authlen

	def verify(self, authenticators: "dict[int, OmapiAuthenticatorBase]") -> bool:
		"""Verify this OMAPI message.

		>>> a1 = OmapiHMACMD5Authenticator(b"egg", b"spam")
		>>> a2 = OmapiHMACMD5Authenticator(b"egg", b"tomatoes")
		>>> a1.authid = a2.authid = 5
		>>> m = OmapiMessage.open(b"host")
		>>> m.verify({a1.authid: a1})
		False
		>>> m.sign(a1)
		>>> m.verify({a1.authid: a1})
		True
		>>> m.sign(a2)
		>>> m.verify({a1.authid: a1})
		False
		"""
		try:
			return authenticators[self.authid].sign(self.as_string(forsigning=True)) == self.signature
		except KeyError:
			return False

	@classmethod
	def open(cls, typename: bytes) -> "OmapiMessage":
		"""Create an OMAPI open message with given typename."""
		return cls(opcode=OMAPI_OP_OPEN, message=[(b"type", typename)], tid=-1)

	@classmethod
	def update(cls, handle: int) -> "OmapiMessage":
		"""Create an OMAPI update message for the given handle."""
		return cls(opcode=OMAPI_OP_UPDATE, handle=handle, tid=-1)

	@classmethod
	def delete(cls, handle: int) -> "OmapiMessage":
		"""Create an OMAPI delete message for given handle."""
		return cls(opcode=OMAPI_OP_DELETE, handle=handle, tid=-1)

	def is_response(self, other: "OmapiMessage") -> bool:
		"""Check whether this OMAPI message is a response to the given
		OMAPI message.
		"""
		return self.rid == other.tid

	def update_object(self, update: "dict[bytes, bytes]") -> None:
		self.obj = [(key, value) for key, value in self.obj if key not in update]
		self.obj.extend(update.items())

	def dump(self) -> str:
		"""@returns: a human readable representation of the message"""
		return "".join(("Omapi message attributes:\n", f"authid:\t\t{self.authid:d}\n", f"authlen:\t{len(self.signature):d}\n", f"opcode:\t\t{repr_opcode(self.opcode)}\n", f"handle:\t\t{self.handle:d}\n", f"tid:\t\t{self.tid:d}\n", f"rid:\t\t{self.rid:d}\n", f"message:\t{self.message!r}\n", f"obj:\t\t{self.obj!r}\n", f"signature:\t{self.signature!r}\n"))

	def dump_oneline(self) -> str:
		"""@returns: a barely human readable representation in one line"""
		return f"authid={self.authid:d} authlen={len(self.signature):d} opcode={repr_opcode(self.opcode)} handle={self.handle:d} tid={self.tid:d} rid={self.rid:d} message={self.message!r} obj={self.obj!r} signature={self.signature!r}"


def parse_map(filterfun: "Callable[[_T], _U]", parser: "Iterator[_T | None]") -> "Iterator[_U | None]":
	"""Creates a new parser that passes the result of the given parser through
	the given filterfun.

	>>> list(parse_map(int, iter((None, "42"))))
	[None, 42]

	@param parser: parser
	@returns: parser
	"""
	for element in parser:
		if element is None:
			yield None
		else:
			yield filterfun(element)
			break


def parse_chain(*args: "Callable[..., Iterator[Any]]") -> "Iterator[Any]":
	"""Creates a new parser that executes the passed parsers (args) with the
	previous results and yields a tuple of the results.

	>>> list(parse_chain(lambda: iter((None, 1)), lambda one: iter((None, 2))))
	[None, None, (1, 2)]

	@param args: parsers
	@returns: parser
	"""
	items: "list[Any]" = []
	for parser in args:
		for element in parser(*items):
			if element is None:
				yield None
			else:
				items.append(element)
				break
	yield tuple(items)


class InBuffer:
	sizelimit = 65536

	def __init__(self, initial: bytes = b"") -> None:
		"""
		@param initial: initial value of the buffer
		@raises OmapiSizeLimitError:
		"""
		self.buff = b""
		self.totalsize = 0
		if initial:
			self.feed(initial)

	def feed(self, data: bytes) -> "InBuffer":
		"""
		@raises OmapiSizeLimitError:
		"""
		if self.totalsize + len(data) > self.sizelimit:
			raise OmapiSizeLimitError()
		self.buff += data
		self.totalsize += len(data)
		return self

	def resetsize(self) -> None:
		"""This method is to be called after handling a packet to
		reset the total size to be parsed at once and that way not
		overflow the size limit.
		"""
		self.totalsize = len(self.buff)

	def parse_fixedbuffer(self, length: int) -> "Iterator[bytes | None]":
		while len(self.buff) < length:
			yield None
		result = self.buff[:length]
		self.buff = self.buff[length:]
		yield result

	def parse_net16int(self) -> "Iterator[int | None]":
		"""
		>>> hex(next(InBuffer(b"\\x01\\x02").parse_net16int()))
		'0x102'
		"""
		return parse_map(lambda data: struct.unpack("!H", data)[0], self.parse_fixedbuffer(2))

	def parse_net32int(self) -> "Iterator[int | None]":
		"""
		>>> hex(int(next(InBuffer(b"\\x01\\0\\0\\x02").parse_net32int())))
		'0x1000002'
		"""
		return parse_map(lambda data: struct.unpack("!L", data)[0], self.parse_fixedbuffer(4))

	def parse_net16string(self) -> "Iterator[bytes | None]":
		"""
		>>> next(InBuffer(b"\\0\\x03eggs").parse_net16string()) == b'egg'
		True
		"""
		return parse_map(lambda pair: pair[1], parse_chain(self.parse_net16int, self.parse_fixedbuffer))

	def parse_net32string(self) -> "Iterator[bytes | None]":
		"""
		>>> next(InBuffer(b"\\0\\0\\0\\x03eggs").parse_net32string()) == b'egg'
		True
		"""
		return parse_map(lambda pair: pair[1], parse_chain(self.parse_net32int, self.parse_fixedbuffer))

	def parse_bindict(self) -> "Iterator[list[tuple[bytes, bytes]] | None]":
		"""
		>>> d = b"\\0\\x01a\\0\\0\\0\\x01b\\0\\0spam"
		>>> next(InBuffer(d).parse_bindict()) == [(b'a', b'b')]
		True
		"""
		entries = []
		while True:  # pylint:disable=too-many-nested-blocks
			done = False
			for key in self.parse_net16string():
				if key is None:
					yield None
				elif not key:
					done = True  # empty key marks the end of the dictionary
				else:
					for value in self.parse_net32string():
						if value is None:
							yield None
						else:
							entries.append((key, value))
							break
					break
			if done:
				break
		yield entries

	def parse_startup_message(self) -> "Iterator[OmapiStartupMessage | None]":
		"""results in an OmapiStartupMessage

		>>> d = b"\\0\\0\\0\\x64\\0\\0\\0\\x18"
		>>> next(InBuffer(d).parse_startup_message()).validate()
		"""
		return parse_map(lambda args: OmapiStartupMessage(*args), parse_chain(self.parse_net32int, lambda _: self.parse_net32int()))

	def parse_message(self) -> "Iterator[OmapiMessage | None]":
		"""results in an OmapiMessage"""
		parser = parse_chain(self.parse_net32int,  # authid
							lambda *_: self.parse_net32int(),  # authlen
							lambda *_: self.parse_net32int(),  # opcode
							lambda *_: self.parse_net32int(),  # handle
							lambda *_: self.parse_net32int(),  # tid
							lambda *_: self.parse_net32int(),  # rid
							lambda *_: self.parse_bindict(),  # message
							lambda *_: self.parse_bindict(),  # object
							lambda *args: self.parse_fixedbuffer(args[1]))  # signature
		return parse_map(lambda args:  # skip authlen in args:
				OmapiMessage(*(args[0:1] + args[2:])), parser)


__all__.append("pack_ip")


def pack_ip(ipstr: str) -> bytes:
	"""Converts an ip address given in dotted notation to a four byte
	string in network byte order.

	>>> len(pack_ip("127.0.0.1"))
	4
	>>> pack_ip("foo")
	Traceback (most recent call last):
	...
	ValueError: given ip address has an invalid number of dots

	@raises ValueError: for badly formatted ip addresses
	"""
	if not isinstance(ipstr, str):
		raise ValueError("given ip address is not a string")
	parts = ipstr.split('.')
	if len(parts) != 4:
		raise ValueError("given ip address has an invalid number of dots")
	return bytes(int(x) for x in parts)  # raises ValueError


__all__.append("unpack_ip")


def unpack_ip(fourbytes: bytes) -> str:
	"""Converts an ip address given in a four byte string in network
	byte order to a string in dotted notation.

	>>> unpack_ip(b"dead")
	'100.101.97.100'
	>>> unpack_ip(b"alive")
	Traceback (most recent call last):
	...
	ValueError: given buffer is not exactly four bytes long

	@raises ValueError: for bad input
	"""
	if not isinstance(fourbytes, bytes):
		raise ValueError("given buffer is not a string")
	if len(fourbytes) != 4:
		raise ValueError("given buffer is not exactly four bytes long")
	return ".".join(str(x) for x in fourbytes)


__all__.append("pack_mac")


def pack_mac(macstr: str) -> bytes:
	"""Converts a mac address given in colon delimited notation to a
	six byte string in network byte order.

	>>> pack_mac("30:31:32:33:34:35") == b'012345'
	True
	>>> pack_mac("bad")
	Traceback (most recent call last):
	...
	ValueError: given mac addresses has an invalid number of colons


	@raises ValueError: for badly formatted mac addresses
	"""
	if not isinstance(macstr, str):
		raise ValueError("given mac addresses is not a string")
	parts = macstr.split(":")
	if len(parts) != 6:
		raise ValueError("given mac addresses has an invalid number of colons")
	return bytes(int(part, 16) for part in parts)  # raises ValueError


__all__.append("unpack_mac")


def unpack_mac(sixbytes: bytes) -> str:
	"""Converts a mac address given in a six byte string in network
	byte order to a string in colon delimited notation.

	>>> unpack_mac(b"012345")
	'30:31:32:33:34:35'
	>>> unpack_mac(b"bad")
	Traceback (most recent call last):
	...
	ValueError: given buffer is not exactly six bytes long

	@raises ValueError: for bad input
	"""
	if not isinstance(sixbytes, bytes):
		raise ValueError("given buffer is not a string")
	if len(sixbytes) != 6:
		raise ValueError("given buffer is not exactly six bytes long")
	return ":".join(f"{x:02x}" for x in sixbytes)


__all__.append("encode_classless_static_routes")


def encode_classless_static_routes(routes):
	"""Encode classless static routes (RFC 3442 / Microsoft option 249) into the
	colon-hex byte string expected in an ISC DHCP ``supersede`` statement.

	Each route is a ``(destination_cidr, gateway)`` pair. The wire format per
	route is: one width byte (the prefix length), the significant octets of the
	destination network (``ceil(width / 8)`` of them), then the four gateway
	octets. The result can be dropped straight into a statement such as
	``supersede classless-static-routes = <value>;`` (or the Microsoft variant
	``ms-classless-static-routes``, option code 249).

	>>> encode_classless_static_routes([("10.0.0.0/8", "192.168.1.1")])
	'08:0a:c0:a8:01:01'
	>>> encode_classless_static_routes([("0.0.0.0/0", "192.168.1.1")])
	'00:c0:a8:01:01'
	>>> encode_classless_static_routes([("16.11.0.0/16", "10.10.10.1")])
	'10:10:0b:0a:0a:0a:01'

	@type routes: [(str, str)]
	@param routes: list of (destination in CIDR notation, gateway) pairs
	@rtype: str
	@raises ValueError: for badly formatted routes
	"""
	out = bytearray()
	for dest, gateway in routes:
		network, sep, prefix = dest.partition("/")
		if not sep:
			raise ValueError("destination must be in CIDR notation, e.g. 10.0.0.0/8")
		width = int(prefix)  # raises ValueError
		if not 0 <= width <= 32:
			raise ValueError("prefix length must be between 0 and 32")
		significant = (width + 7) // 8
		out.append(width)
		out.extend(pack_ip(network)[:significant])  # raises ValueError
		out.extend(pack_ip(gateway))  # raises ValueError
	return ":".join(f"{b:02x}" for b in out)


class LazyStr:  # pylint:disable=too-few-public-methods
	def __init__(self, fnc: "Callable[[], str]") -> None:
		self.function = fnc

	def __str__(self) -> str:
		return self.function()


class TCPClientTransport:
	"""PEP 3156 dummy transport class to support OmapiProtocol class."""
	def __init__(self, protocol: "OmapiProtocol", host: str, port: int, timeout: "float | None" = None) -> None:
		self.protocol = protocol
		self.connection: "socket.socket | None" = socket.socket()
		self.connection.settimeout(timeout)
		self.connection.connect((host, port))
		self.protocol.connection_made(self)

	def close(self) -> None:
		"""Close the omapi connection if it is open."""
		if self.connection:
			self.connection.close()
			self.connection = None

	def fill_inbuffer(self) -> None:
		"""Read bytes from the connection and hand them to the protocol.
		@raises OmapiError:
		@raises socket.error:
		"""
		if not self.connection:
			raise OmapiError("not connected")
		try:
			data = self.connection.recv(2048)
		except socket.error:
			self.close()
			raise
		if not data:
			self.close()
			raise OmapiError("connection closed")
		try:
			self.protocol.data_received(data)
		except OmapiSizeLimitError:
			self.close()
			raise

	def write(self, data: bytes) -> None:
		"""Send all of data to the connection.

		@raises socket.error:
		"""
		if self.connection is None:
			raise OmapiError("not connected")
		try:
			self.connection.sendall(data)
		except socket.error:
			self.close()
			raise


class OmapiProtocol:
	"""PEP 3156 like protocol class for Omapi.

	This interface is not yet to be relied upon.
	"""
	def __init__(self) -> None:
		self.transport: "TCPClientTransport | None" = None
		self.authenticators: "dict[int, OmapiAuthenticatorBase]" = {0: OmapiNullAuthenticator()}
		self.defauth = 0
		self.inbuffer = InBuffer()
		self.current_parser: "Iterator[object] | None" = self.inbuffer.parse_startup_message()

	def connection_made(self, transport: "TCPClientTransport") -> None:
		self.transport = transport
		message = OmapiStartupMessage()
		logger.debug("sending omapi startup message %s", LazyStr(message.dump_oneline))
		self.transport.write(message.as_string())

	def data_received(self, data: bytes) -> None:
		self.inbuffer.feed(data)
		while True:
			if self.current_parser is None:
				self.current_parser = self.inbuffer.parse_message()
			result = next(self.current_parser)
			if result is None:
				return
			self.current_parser = None
			self.inbuffer.resetsize()
			if isinstance(result, OmapiStartupMessage):
				logger.debug("received omapi startup message %s", LazyStr(result.dump_oneline))
				self.startup_received(result)
			else:
				assert isinstance(result, OmapiMessage)
				logger.debug("received %s", LazyStr(result.dump_oneline))
				self.message_received(result)

	def startup_received(self, startup_message: OmapiStartupMessage) -> None:
		assert self.transport is not None
		try:
			startup_message.validate()
		except OmapiError:
			self.transport.close()
			raise
		self.startup_completed()

	@staticmethod
	def startup_completed() -> None:
		logger.debug("omapi connection initialized")

	def message_received(self, message: OmapiMessage) -> None:
		pass

	def send_message(self, message: OmapiMessage, sign: bool = True) -> None:
		"""Send the given message to the connection.

		@param sign: whether the message needs to be signed
		@raises OmapiError:
		@raises socket.error:
		"""
		if sign:
			message.sign(self.authenticators[self.defauth])
		logger.debug("sending %s", LazyStr(message.dump_oneline))
		assert self.transport is not None
		self.transport.write(message.as_string())


__all__.append("Omapi")


class Omapi:  # pylint:disable=too-many-public-methods
	def __init__(self, hostname: str, port: int, username: "bytes | None" = None, key: "bytes | None" = None, timeout: "float | None" = None) -> None:  # pylint:disable=too-many-arguments
		"""
		@param key: if given, it must be base64 encoded
		@raises binascii.Error: for bad base64 encoding
		@raises socket.error:
		@raises OmapiError:
		"""
		self.hostname = hostname
		self.port = port
		self.protocol = OmapiProtocol()
		self.recv_message_queue: "list[OmapiMessage | None]" = []
		self.protocol.startup_completed = lambda: self.recv_message_queue.append(None)  # type: ignore[method-assign]
		self.protocol.message_received = self.recv_message_queue.append  # type: ignore[method-assign,assignment]

		newauth = None
		if username is not None and key is not None:
			newauth = OmapiHMACMD5Authenticator(username, key)

		self.transport = TCPClientTransport(self.protocol, hostname, port, timeout=timeout)

		self.recv_protocol_initialization()

		if newauth:
			self.initialize_authenticator(newauth)

	def close(self) -> None:
		"""Close the omapi connection if it is open."""
		self.transport.close()

	def check_connected(self) -> None:
		"""Raise an OmapiError unless connected.
		@raises OmapiError:
		"""
		if not self.transport.connection:
			raise OmapiError("not connected")

	def recv_protocol_initialization(self) -> None:
		"""
		@raises OmapiError:
		@raises socket.error:
		"""
		while not self.recv_message_queue:
			self.transport.fill_inbuffer()
		message = self.recv_message_queue.pop(0)
		assert message is None

	def receive_message(self) -> OmapiMessage:
		"""Read the next message from the connection.
		@raises OmapiError:
		@raises socket.error:
		"""
		while not self.recv_message_queue:
			self.transport.fill_inbuffer()
		message = self.recv_message_queue.pop(0)
		assert message is not None
		if not message.verify(self.protocol.authenticators):
			self.close()
			raise OmapiError("bad omapi message signature")
		return message

	def receive_response(self, message: OmapiMessage, insecure: bool = False) -> OmapiMessage:
		"""Read the response for the given message.
		@param insecure: avoid an OmapiError about a wrong authenticator
		@raises OmapiError:
		@raises socket.error:
		"""
		response = self.receive_message()
		if not response.is_response(message):
			raise OmapiError("received message is not the desired response")
		# signature already verified
		if response.authid != self.protocol.defauth and not insecure:
			raise OmapiError("received message is signed with wrong authenticator")
		return response

	def send_message(self, message: OmapiMessage, sign: bool = True) -> None:
		"""Sends the given message to the connection.
		@param sign: whether the message needs to be signed
		@raises OmapiError:
		@raises socket.error:
		"""
		self.check_connected()
		self.protocol.send_message(message, sign)

	def query_server(self, message: OmapiMessage) -> OmapiMessage:
		"""Send the message and receive a response for it.
		@raises OmapiError:
		@raises socket.error:
		"""
		self.send_message(message)
		return self.receive_response(message)

	def initialize_authenticator(self, authenticator: OmapiAuthenticatorBase) -> None:
		"""
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"authenticator")
		msg.update_object(authenticator.auth_object())
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("received non-update response for open")
		authid = response.handle
		if authid == 0:
			raise OmapiError("received invalid authid from server")
		self.protocol.authenticators[authid] = authenticator
		authenticator.authid = authid
		self.protocol.defauth = authid
		logger.debug("successfully initialized default authid %d", authid)

	def lookup_ip_host(self, mac: str) -> str:
		"""Lookup a host object with with given mac address.

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given mac could be found
		@raises OmapiErrorAttributeNotFound: if lease could be found, but objects lacks a ip
		@raises socket.error:
		"""
		res = self.lookup_by_host(mac=mac)
		try:
			return res["ip-address"]
		except KeyError:
			raise OmapiErrorAttributeNotFound() from None

	def lookup_ip(self, mac: str) -> str:
		"""Look for a lease object with given mac address and return the
		assigned ip address.

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given mac could be found
		@raises OmapiErrorAttributeNotFound: if lease could be found, but objects lacks a ip
		@raises socket.error:
		"""
		res = self.lookup_by_lease(mac=mac)
		try:
			return res["ip-address"]
		except KeyError:
			raise OmapiErrorAttributeNotFound() from None

	def lookup_mac(self, ip: str) -> str:
		"""Look up a lease object with given ip address and return the
		associated mac address.

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given ip could be found
		@raises OmapiErrorAttributeNotFound: if lease could be found, but objects lacks a mac
		@raises socket.error:
		"""
		res = self.lookup_by_lease(ip=ip)
		try:
			return res["hardware-address"]
		except KeyError:
			raise OmapiErrorAttributeNotFound() from None

	def lookup_host(self, name: str) -> dict:
		"""Look for a host object with given name and return the
		name, mac, and ip address

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no host object with the given name could be found
		@raises OmapiErrorAttributeNotFound: if lease could be found, but objects lacks ip, mac or name
		@raises socket.error:
		"""
		res = self.lookup_by_host(name=name)
		try:
			return dict(ip=res["ip-address"], mac=res["hardware-address"], hostname=res["name"].decode('utf-8'))
		except KeyError:
			raise OmapiErrorAttributeNotFound() from None

	def lookup_host_by_ip(self, ip: str) -> dict:
		"""Look for a host object with given ip address and return the
		name, mac, and ip address

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no host object with the given ip could be found
		@raises OmapiErrorAttributeNotFound: if lease could be found, but objects lacks ip, mac or name
		@raises socket.error:
		"""
		res = self.lookup_by_host(ip=ip)
		try:
			return dict(ip=res["ip-address"], mac=res["hardware-address"], hostname=res["name"].decode('utf-8'))
		except KeyError:
			raise OmapiErrorAttributeNotFound() from None

	def lookup_host_host(self, mac: str) -> dict:
		"""Look for a host object with given mac address and return the
		name, mac, and ip address

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no host object with the given mac address could be found
		@raises OmapiErrorAttributeNotFound: if lease could be found, but objects lacks ip, mac or name
		@raises socket.error:
		"""
		res = self.lookup_by_host(mac=mac)
		try:
			return dict(ip=res["ip-address"], mac=res["hardware-address"], name=res["name"].decode('utf-8'))
		except KeyError:
			raise OmapiErrorAttributeNotFound() from None

	def lookup_hostname(self, ip: str) -> str:
		"""Look up a lease object with given ip address and return the associated client hostname.

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given ip address could be found
		@raises OmapiErrorAttributeNotFound: if lease could be found, but objects lacks a hostname
		@raises socket.error:
		"""
		res = self.lookup_by_lease(ip=ip)
		if "client-hostname" not in res:
			raise OmapiErrorAttributeNotFound()
		return res["client-hostname"].decode('utf-8')

	def lookup_failoverstate(self, name: str, attribute: str) -> object:
		"""Look up a failover-state object with given peer name and return the associated attribute.

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no failover-state object with the given name could be found
		@raises OmapiErrorAttributeNotFound: if failover-state object could be found, but object lacks the attribute
		@raises socket.error:
		"""
		res = self.lookup_by_failoverstate(name=name)
		if attribute not in res:
			raise OmapiErrorAttributeNotFound()
		return res[attribute]

	def lookup_by_host(self, *, raw: bool = False, **kwargs: str) -> dict:
		return self.__lookup("host", raw=raw, **kwargs)

	def lookup_by_lease(self, *, raw: bool = False, **kwargs: str) -> dict:
		return self.__lookup("lease", raw=raw, **kwargs)

	def lookup_by_failoverstate(self, *, raw: bool = False, **kwargs: str) -> dict:
		return self.__lookup("failover-state", raw=raw, **kwargs)

	def __lookup(self, ltype: str, *, raw: bool = False, **kwargs: str) -> dict:
		"""Generic Lookup function

		@param raw: if True, return the object attributes undecoded (bytes keys
				and values) instead of the human readable representation
		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no host object with the given name
				could be found or the object lacks an ip address or mac
		@raises socket.error:
		"""
		ltype_utf = ltype.encode("utf-8")
		assert ltype_utf in [b"host", b"lease", b"failover-state"]
		msg = OmapiMessage.open(ltype_utf)
		for k in kwargs:
			_k = k.replace("_", "-")
			if _k in ["ip", "ip-address"]:
				msg.obj.append((b"ip-address", pack_ip(kwargs[k])))
			elif _k in ["mac", "hardware-address"]:
				msg.obj.append((b"hardware-address", pack_mac(kwargs[k])))
				msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
			elif _k == "name":
				msg.obj.append((b"name", kwargs[k].encode('utf-8')))
			else:
				msg.obj.append((_k.encode(), kwargs[k].encode('utf-8')))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		if raw:
			return dict(response.obj)
		res: "dict[str, object]" = {}
		for key, rawvalue in dict(response.obj).items():
			_k = key.decode('utf-8')
			value: object = rawvalue
			try:
				if _k == "ip-address":
					value = unpack_ip(rawvalue)
				elif _k == "hardware-address":
					value = unpack_mac(rawvalue)
				elif _k in ["starts", "ends", "tstp", "tsfp", "atsfp", "cltt", "subnet", "pool", "state", "hardware-type", "flags"]:
					value = struct.unpack(">I", rawvalue)[0]
			except struct.error:
				pass
			res[_k] = value
		return res

	def add_host(self, ip: str, mac: str) -> None:
		"""Create a host object with given ip address and and mac address.

		@raises ValueError:
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"host")
		msg.message.append((b"create", struct.pack("!I", 1)))
		msg.message.append((b"exclusive", struct.pack("!I", 1)))
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
		msg.obj.append((b"ip-address", pack_ip(ip)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("add failed")

	def add_host_supersede_name(self, ip: str, mac: str, name: str) -> None:
		"""Add a host with a fixed-address and override its hostname with the given name.
		@raises ValueError:
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"host")
		msg.message.append((b"create", struct.pack("!I", 1)))
		msg.message.append((b"exclusive", struct.pack("!I", 1)))
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
		msg.obj.append((b"ip-address", pack_ip(ip)))
		msg.obj.append((b"name", name.encode('utf-8')))
		msg.obj.append((b"statements", f'supersede host-name "{name}";'.encode('utf-8')))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("add failed")

	def add_host_without_ip(self, mac: str) -> None:
		"""Create a host object with given mac address without assigning a static ip address.
		@raises ValueError:
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"host")
		msg.message.append((b"create", struct.pack("!I", 1)))
		msg.message.append((b"exclusive", struct.pack("!I", 1)))
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("add failed")

	def add_host_supersede(self, ip: str, mac: str, name: str, hostname: "str | None" = None, router: "str | None" = None, domain: "str | None" = None, statements: "str | None" = None) -> None:  # pylint:disable=too-many-arguments
		"""Create a host object with given ip, mac, name, hostname, router and
		domain. hostname, router and domain are optional arguments.

		@param statements: additional raw ISC DHCP statements appended verbatim,
				e.g. a ``supersede classless-static-routes = ...;`` produced by
				L{encode_classless_static_routes}.
		@raises OmapiError:
		@raises socket.error:
		"""
		stmts = []

		msg = OmapiMessage.open(b"host")
		msg.message.append((b"create", struct.pack("!I", 1)))
		msg.obj.append((b"name", name.encode('utf-8')))
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
		msg.obj.append((b"ip-address", pack_ip(ip)))
		if hostname:
			stmts.append(f'supersede host-name "{hostname}";\n ')
		if router:
			stmts.append(f'supersede routers {router};\n ')
		if domain:
			stmts.append(f'supersede domain-name "{domain}";')
		if statements:
			stmts.append(statements)
		if stmts:
			encoded_stmts = "".join(stmts).encode("utf-8")
			msg.obj.append((b"statements", encoded_stmts))

		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("add failed")

	def del_host(self, mac: str) -> None:
		"""Delete a host object with with given mac address.

		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given
				mac address could be found
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"host")
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		if response.handle == 0:
			raise OmapiError("received invalid handle from server")
		response = self.query_server(OmapiMessage.delete(response.handle))
		if response.opcode != OMAPI_OP_STATUS:
			raise OmapiError("delete failed")

	def add_group(self, groupname: str, statements: str) -> None:
		"""Adds a group."""
		msg = OmapiMessage.open(b"group")
		msg.message.append((b"create", struct.pack("!I", 1)))
		msg.obj.append((b"name", groupname.encode('utf-8')))
		msg.obj.append((b"statements", statements.encode('utf-8')))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("add group failed")

	def add_host_with_group(self, ip: str, mac: str, groupname: str) -> None:
		"""Adds a host with given ip and mac in a group named groupname."""
		msg = OmapiMessage.open(b"host")
		msg.message.append((b"create", struct.pack("!I", 1)))
		msg.message.append((b"exclusive", struct.pack("!I", 1)))
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
		msg.obj.append((b"ip-address", pack_ip(ip)))
		msg.obj.append((b"group", groupname.encode('utf-8')))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("add failed")

	def change_group(self, name: str, group: str) -> None:
		"""Change the group of a host given the name of the host."""
		m1 = OmapiMessage.open(b"host")
		m1.update_object({b"name": name.encode('utf-8')})
		r1 = self.query_server(m1)
		if r1.opcode != OMAPI_OP_UPDATE:
			raise OmapiError(f"opening host {name} failed")
		m2 = OmapiMessage.update(r1.handle)
		m2.update_object({b"group": group.encode('utf-8')})
		r2 = self.query_server(m2)
		if r2.opcode != OMAPI_OP_UPDATE:
			raise OmapiError(f"changing group of host {name} to {group} failed")

	def signal_shutdown(self) -> None:
		"""Gracefully shut down the DHCP server via the OMAPI control object.

		This opens the server's singleton ``control`` object and sets its state
		to 2 (shutdown), equivalent to the omshell sequence
		``new control; open; set state = 2; update``.

		ISC dhcpd does not answer the state update — it just shuts down — so the
		server dropping the connection or the read timing out is treated as
		success. For that reason the connection should be created with a
		C{timeout} (otherwise the final read blocks indefinitely).

		@raises OmapiError:
		@raises socket.error:
		"""
		response = self.query_server(OmapiMessage.open(b"control"))
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("opening control object failed")
		if response.handle == 0:
			raise OmapiError("received invalid handle from server")
		msg = OmapiMessage.update(response.handle)
		msg.update_object({b"state": struct.pack("!I", 2)})
		try:
			response = self.query_server(msg)
		except (OmapiError, OSError):
			# The server shut down without answering (dropped connection or
			# read timeout); that is the expected, successful outcome.
			return
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("setting control state to shutdown failed")


if __name__ == "__main__":
	import doctest
	doctest.testmod()
