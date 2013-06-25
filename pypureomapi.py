#!/usr/bin/python
# -*- coding: utf8 -*-
#
# library for communicating with an isc dhcp server over the omapi protocol
#
# Copyright (C) 2010-2013 Cygnus Networks GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""
For an example see http://code.google.com/p/pypureomapi/wiki/Example.
"""

# Message format:
# 
# authid (netint32)
# authlen (netint32)
# opcode (netint32)
# handle (netint32)
# tid (netint32)
# rid (netint32)
# message (dictionary)
# object (dictionary)
# signature (length is authlen)
# 
# dictionary = entry* 0x00 0x00
# entry = key (net16str) value (net32str)

__author__      = "Helmut Grohne, Torge Szczepanek"
__copyright__   = "Cygnus Networks GmbH"
__licence__     = "GPL-3"
__version__     = "0.3"
__maintainer__  = "Torge Szczepanek"
__email__       = "info@cygnusnetworks.de"

__all__ = []

import binascii
import struct
import hmac
import io
import logging
import socket
import random
import operator
try:
	basestring
except NameError:
	basestring = str

logger = logging.getLogger("pypureomapi")
sysrand = random.SystemRandom()

__all__.extend("OMAPI_OP_OPEN OMAPI_OP_REFRESH OMAPI_OP_UPDATE".split())
__all__.extend("OMAPI_OP_NOTIFY OMAPI_OP_STATUS OMAPI_OP_DELETE".split())
OMAPI_OP_OPEN    = 1
OMAPI_OP_REFRESH = 2
OMAPI_OP_UPDATE  = 3
OMAPI_OP_NOTIFY  = 4
OMAPI_OP_STATUS  = 5
OMAPI_OP_DELETE  = 6

def repr_opcode(opcode):
	"""Returns a textual representation for the given opcode.
	@type opcode: int
	@rtype: str
	"""
	opmap = {1: "open", 2: "refresh", 3: "update", 4: "notify", 5: "status",
			6: "delete"}
	return opmap.get(opcode, "unknown (%d)" % opcode)

__all__.append("OmapiError")
class OmapiError(Exception):
	"""OMAPI exception base class."""

__all__.append("OmapiSizeLimitError")
class OmapiSizeLimitError(OmapiError):
	"""Packet size limit reached."""
	def __init__(self):
		OmapiError.__init__(self, "Packet size limit reached.")

__all__.append("OmapiErrorNotFound")
class OmapiErrorNotFound(OmapiError):
	"""Not found."""
	def __init__(self):
		OmapiError.__init__(self, "not found")

class OutBuffer(object):
	"""Helper class for constructing network packets."""
	sizelimit = 65536
	def __init__(self):
		self.buff = io.BytesIO()

	def __len__(self):
		"""Return the number of bytes in the buffer.
		@rtype: int
		"""
		# On Py2.7 tell returns long, but __len__ is required to return int.
		return int(self.buff.tell())

	def add(self, data):
		"""
		>>> ob = OutBuffer().add(OutBuffer.sizelimit * b"x")
		>>> ob.add(b"y") # doctest: +ELLIPSIS
		Traceback (most recent call last):
		...
		OmapiSizeLimitError: ...

		@type data: bytes
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if len(self) + len(data) > self.sizelimit:
			raise OmapiSizeLimitError()
		self.buff.write(data)
		return self

	def add_net32int(self, integer):
		"""
		@type integer: int
		@param integer: a 32bit unsigned integer
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if integer < 0 or integer >= (1 << 32):
			raise ValueError("not a 32bit unsigned integer")
		return self.add(struct.pack("!L", integer))

	def add_net16int(self, integer):
		"""
		@type integer: int
		@param integer: a 16bit unsigned integer
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if integer < 0 or integer >= (1 << 16):
			raise ValueError("not a 16bit unsigned integer")
		return self.add(struct.pack("!H", integer))

	def add_net32string(self, string):
		"""
		>>> r = b'\\x00\\x00\\x00\\x01x'
		>>> OutBuffer().add_net32string(b"x").getvalue() == r
		True

		@type string: bytes
		@param string: maximum length must fit in a 32bit integer
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if len(string) >= (1 << 32):
			raise ValueError("string too long")
		return self.add_net32int(len(string)).add(string)

	def add_net16string(self, string):
		"""
		>>> OutBuffer().add_net16string(b"x").getvalue() == b'\\x00\\x01x'
		True

		@type string: bytes
		@param string: maximum length must fit in a 16bit integer
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if len(string) >= (1 << 16):
			raise ValueError("string too long")
		return self.add_net16int(len(string)).add(string)

	def add_bindict(self, items):
		"""
		>>> r = b'\\x00\\x03foo\\x00\\x00\\x00\\x03bar\\x00\\x00'
		>>> OutBuffer().add_bindict({b"foo": b"bar"}).getvalue() == r
		True

		@type items: [(bytes, bytes)] or {bytes: bytes}
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if not isinstance(items, list):
			items = items.items()
		for key, value in items:
			self.add_net16string(key).add_net32string(value)
		return self.add(b"\x00\x00") # end marker

	def getvalue(self):
		"""
		>>> OutBuffer().add(b"sp").add(b"am").getvalue() == b"spam"
		True

		@rtype: bytes
		"""
		return self.buff.getvalue()

	def consume(self, length):
		"""
		>>> OutBuffer().add(b"spam").consume(2).getvalue() == b"am"
		True

		@type length: int
		@returns: self
		"""
		self.buff = io.BytesIO(self.getvalue()[length:])
		return self

class OmapiStartupMessage(object):
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

	def __init__(self, protocol_version=None, header_size=None):
		"""
		@type protocol_version: int or None
		@type header_size: int or None
		"""
		if protocol_version is None:
			protocol_version = self.implemented_protocol_version
		if header_size is None:
			header_size = self.implemented_header_size
		self.protocol_version = protocol_version
		self.header_size = header_size

	def validate(self):
		"""Checks whether this OmapiStartupMessage matches the implementation.
		@raises OmapiError:
		"""
		if self.implemented_protocol_version != self.protocol_version:
			raise OmapiError("protocol mismatch")
		if self.implemented_header_size != self.header_size:
			raise OmapiError("header size mismatch")

	def as_string(self):
		"""
		@rtype: bytes
		"""
		ret = OutBuffer()
		self.serialize(ret)
		return ret.getvalue()

	def serialize(self, outbuffer):
		"""Serialize this OmapiStartupMessage to the given outbuffer.
		@type outbuffer: OutBuffer
		"""
		outbuffer.add_net32int(self.protocol_version)
		outbuffer.add_net32int(self.header_size)

	def dump_oneline(self):
		"""
		@rtype: str
		@returns: a human readable representation in one line
		"""
		return "protocol_version=%d header_size=%d" % (self.protocol_version,
				self.header_size)

class OmapiAuthenticatorBase(object):
	"""Base class for OMAPI authenticators.
	@cvar authlen: is the length of a signature as returned by the sign method
	@type authlen: int
	@cvar algorithm: is a textual name for the algorithm
	@type algorithm: str or None
	@ivar authid: is the authenticator id as assigned during the handshake
	@type authid: int
	"""
	authlen = -1 # must be overwritten
	algorithm = None
	authid = -1 # will be an instance attribute
	def __init__(self):
		pass
	def auth_object(self):
		"""
		@rtype: {bytes: bytes}
		@returns: object part of an omapi authentication message
		"""
		raise NotImplementedError
	def sign(self, message):
		"""
		@type message: bytes
		@rtype: bytes
		@returns: a signature of length self.authlen
		"""
		raise NotImplementedError()

class OmapiNullAuthenticator(OmapiAuthenticatorBase):
	authlen = 0
	authid = 0 # always 0
	def __init__(self):
		OmapiAuthenticatorBase.__init__(self)
	def auth_object(self):
		return {}
	def sign(self, _):
		return b""

class OmapiHMACMD5Authenticator(OmapiAuthenticatorBase):
	authlen = 16
	algorithm = b"hmac-md5.SIG-ALG.REG.INT."
	def __init__(self, user, key):
		"""
		@type user: bytes
		@type key: bytes
		@param key: base64 encoded key
		@raises binascii.Error: for bad base64 encoding
		"""
		OmapiAuthenticatorBase.__init__(self)
		self.user = user
		self.key = binascii.a2b_base64(key)

	def auth_object(self):
		return {b"name": self.user, b"algorithm": self.algorithm}

	def sign(self, message):
		"""
		>>> authlen = OmapiHMACMD5Authenticator.authlen
		>>> len(OmapiHMACMD5Authenticator(b"foo", 16*b"x").sign(b"baz")) == authlen
		True

		@type message: bytes
		@rtype: bytes
		@returns: a signature of length self.authlen
		"""
		return hmac.HMAC(self.key, message).digest()

__all__.append("OmapiMessage")
class OmapiMessage(object):
	"""
	@type authid: int
	@ivar authid: The id of the message authenticator.
	@type opcode: int
	@ivar opcode: One out of
			OMAPI_OP_{OPEN,REFRESH,UPDATE,NOTIFY,STATUS,DELETE}.
	@type handle: int
	@ivar handle: The id of a handle acquired from a previous request or 0.
	@type tid: int
	@ivar tid: Transmission identifier.
	@type rid: int
	@ivar rid: Receive identifier (of a response is the tid of the request).
	@type message: [(bytes, bytes)]
	@ivar message: A list of (key, value) pairs.
	@type obj: [(bytes, bytes)]
	@ivar obj: A list of (key, value) pairs.
	@type signature: bytes
	@ivar signature: A signature on this message as generated by an
			authenticator.
	"""
	def __init__(self, authid=0, opcode=0, handle=0, tid=0, rid=0,
			message=None, obj=None, signature=b""):
		"""
		Construct an OmapiMessage from the given fields. No error
		checking is performed.

		@type authid: int
		@type opcode: int
		@type handle: int
		@type tid: int
		@param tid: The special value -1 causes a tid to be generated randomly.
		@type rid: int
		@type message: [(bytes, bytes)]
		@type obj: [(bytes, bytes)]
		@type signature: str
		@rtype: OmapiMessage
		"""
		self.authid, self.opcode, self.handle = authid, opcode, handle
		self.handle, self.tid, self.rid = handle, tid, rid
		self.message = message or []
		self.obj = obj or []
		self.signature = signature

		if self.tid == -1:
			self.generate_tid()

	def generate_tid(self):
		"""Generate a random transmission id for this OMAPI message.

		>>> OmapiMessage(tid=-1).tid != OmapiMessage(tid=-1).tid
		True
		"""
		self.tid = sysrand.randrange(0, 1<<32)

	def serialize(self, outbuffer, forsigning=False):
		"""
		@type outbuffer: OutBuffer
		@type forsigning: bool
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

	def as_string(self, forsigning=False):
		"""
		>>> len(OmapiMessage().as_string(True)) >= 24
		True

		@type forsigning: bool
		@rtype: bytes
		@raises OmapiSizeLimitError:
		"""
		ret = OutBuffer()
		self.serialize(ret, forsigning)
		return ret.getvalue()

	def sign(self, authenticator):
		"""Sign this OMAPI message.
		@type authenticator: OmapiAuthenticatorBase
		"""
		self.authid = authenticator.authid
		self.signature = b"\0" * authenticator.authlen # provide authlen
		self.signature = authenticator.sign(self.as_string(forsigning=True))
		assert len(self.signature) == authenticator.authlen

	def verify(self, authenticators):
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

		@type authenticators: {int: OmapiAuthenticatorBase}
		@rtype: bool
		"""
		try:
			return authenticators[self.authid]. \
					sign(self.as_string(forsigning=True)) == \
					self.signature
		except KeyError:
			return False

	@classmethod
	def open(cls, typename):
		"""Create an OMAPI open message with given typename.
		@type typename: bytes
		@rtype: OmapiMessage
		"""
		return cls(opcode=OMAPI_OP_OPEN, message=[(b"type", typename)], tid=-1)

	@classmethod
	def update(cls, handle):
		"""Create an OMAPI update message for the given handle.
		@type handle: int
		@rtype: OmapiMessage
		"""
		return cls(opcode=OMAPI_OP_UPDATE, handle=handle, tid=-1)

	@classmethod
	def delete(cls, handle):
		"""Create an OMAPI delete message for given handle.
		@type handle: int
		@rtype: OmapiMessage
		"""
		return cls(opcode=OMAPI_OP_DELETE, handle=handle, tid=-1)

	def is_response(self, other):
		"""Check whether this OMAPI message is a response to the given
		OMAPI message.
		@rtype: bool
		"""
		return self.rid == other.tid

	def update_object(self, update):
		"""
		@type update: {bytes: bytes}
		"""
		self.obj = [(key, value) for key, value in self.obj
					if key not in update]
		self.obj.extend(update.items())

	def dump(self):
		"""
		@rtype: str
		@returns: a human readable representation of the message
		"""
		return "".join(("Omapi message attributes:\n",
				"authid:\t\t%d\n" % self.authid,
				"authlen:\t%d\n" % len(self.signature),
				"opcode:\t\t%s\n" % repr_opcode(self.opcode),
				"handle:\t\t%d\n" % self.handle,
				"tid:\t\t%d\n" % self.tid,
				"rid:\t\t%d\n" % self.rid,
				"message:\t%r\n" % self.message,
				"obj:\t\t%r\n" % self.obj,
				"signature:\t%r\n" % self.signature))

	def dump_oneline(self):
		"""
		@rtype: str
		@returns: a barely human readable representation in one line
		"""
		return ("authid=%d authlen=%d opcode=%s handle=%d tid=%d rid=%d " +
				"message=%r obj=%r signature=%r") % (self.authid,
						len(self.signature), repr_opcode(self.opcode),
						self.handle, self.tid, self.rid, self.message,
						self.obj, self.signature)

def parse_map(filterfun, parser):
	"""Creates a new parser that passes the result of the given parser through
	the given filterfun.

	>>> list(parse_map(int, (None, "42")))
	[None, 42]

	@type filterfun: obj -> obj
	@param parser: parser
	@returns: parser
	"""
	for element in parser:
		if element is None:
			yield None
		else:
			yield filterfun(element)
			break

def parse_chain(*args):
	"""Creates a new parser that executes the passed parsers (args) with the
	previous results and yields a tuple of the results.

	>>> list(parse_chain(lambda: (None, 1), lambda one: (None, 2)))
	[None, None, (1, 2)]

	@param args: parsers
	@returns: parser
	"""
	items = []
	for parser in args:
		for element in parser(*items):
			if element is None:
				yield None
			else:
				items.append(element)
				break
	yield tuple(items)

class InBuffer(object):
	sizelimit = 65536
	def __init__(self, initial=b""):
		"""
		@type initial: bytes
		@param initial: initial value of the buffer
		@raises OmapiSizeLimitError:
		"""
		self.buff = b""
		self.totalsize = 0
		if initial:
			self.feed(initial)

	def feed(self, data):
		"""
		@type data: bytes
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if self.totalsize + len(data) > self.sizelimit:
			raise OmapiSizeLimitError()
		self.buff += data
		self.totalsize += len(data)
		return self

	def resetsize(self):
		"""This method is to be called after handling a packet to
		reset the total size to be parsed at once and that way not
		overflow the size limit.
		"""
		self.totalsize = len(self.buff)

	def parse_fixedbuffer(self, length):
		"""
		@type length: int
		"""
		while len(self.buff) < length:
			yield None
		result = self.buff[:length]
		self.buff = self.buff[length:]
		yield result

	def parse_net16int(self):
		"""
		>>> hex(next(InBuffer(b"\\x01\\x02").parse_net16int()))
		'0x102'
		"""
		return parse_map(lambda data: struct.unpack("!H", data)[0],
				self.parse_fixedbuffer(2))

	def parse_net32int(self):
		"""
		>>> hex(int(next(InBuffer(b"\\x01\\0\\0\\x02").parse_net32int())))
		'0x1000002'
		"""
		return parse_map(lambda data: struct.unpack("!L", data)[0],
				self.parse_fixedbuffer(4))

	def parse_net16string(self):
		"""
		>>> next(InBuffer(b"\\0\\x03eggs").parse_net16string()) == b'egg'
		True
		"""
		return parse_map(operator.itemgetter(1),
				parse_chain(self.parse_net16int, self.parse_fixedbuffer))

	def parse_net32string(self):
		"""
		>>> next(InBuffer(b"\\0\\0\\0\\x03eggs").parse_net32string()) == b'egg'
		True
		"""
		return parse_map(operator.itemgetter(1),
				parse_chain(self.parse_net32int, self.parse_fixedbuffer))

	def parse_bindict(self):
		"""
		>>> d = b"\\0\\x01a\\0\\0\\0\\x01b\\0\\0spam"
		>>> next(InBuffer(d).parse_bindict()) == [(b'a', b'b')]
		True
		"""
		entries = []
		try:
			while True:
				for key in self.parse_net16string():
					if key is None:
						yield None
					elif not key:
						raise StopIteration()
					else:
						for value in self.parse_net32string():
							if value is None:
								yield None
							else:
								entries.append((key, value))
								break
						break
		# Abusing StopIteration here, since nothing should be throwing
		# it at us.
		except StopIteration:
			yield entries

	def parse_startup_message(self):
		"""results in an OmapiStartupMessage

		>>> d = b"\\0\\0\\0\\x64\\0\\0\\0\\x18"
		>>> next(InBuffer(d).parse_startup_message()).validate()
		"""
		return parse_map(lambda args: OmapiStartupMessage(*args),
				parse_chain(self.parse_net32int,
					lambda _: self.parse_net32int()))

	def parse_message(self):
		"""results in an OmapiMessage"""
		parser = parse_chain(self.parse_net32int, # authid
				lambda *_: self.parse_net32int(), # authlen
				lambda *_: self.parse_net32int(), # opcode
				lambda *_: self.parse_net32int(), # handle
				lambda *_: self.parse_net32int(), # tid
				lambda *_: self.parse_net32int(), # rid
				lambda *_: self.parse_bindict(), # message
				lambda *_: self.parse_bindict(), # object
				lambda *args: self.parse_fixedbuffer(args[1])) # signature
		return parse_map(lambda args: # skip authlen in args:
				OmapiMessage(*(args[0:1] + args[2:])), parser)

if isinstance(bytes(b"x")[0], int):
	def bytes_to_int_seq(b):
		return b
	int_seq_to_bytes = bytes # raises ValueError
else:
	def bytes_to_int_seq(b):
		return map(ord, b)
	def int_seq_to_bytes(s):
		return "".join(map(chr, s)) # raises ValueError

__all__.append("pack_ip")
def pack_ip(ipstr):
	"""Converts an ip address given in dotted notation to a four byte
	string in network byte order.

	>>> len(pack_ip("127.0.0.1"))
	4
	>>> pack_ip("foo")
	Traceback (most recent call last):
	...
	ValueError: given ip address has an invalid number of dots

	@type ipstr: str
	@rtype: bytes
	@raises ValueError: for badly formatted ip addresses
	"""
	if not isinstance(ipstr, basestring):
		raise ValueError("given ip address is not a string")
	parts = ipstr.split('.')
	if len(parts) != 4:
		raise ValueError("given ip address has an invalid number of dots")
	parts = map(int, parts) # raises ValueError
	return int_seq_to_bytes(parts) # raises ValueError

__all__.append("unpack_ip")
def unpack_ip(fourbytes):
	"""Converts an ip address given in a four byte string in network
	byte order to a string in dotted notation.

	>>> unpack_ip(b"dead")
	'100.101.97.100'
	>>> unpack_ip(b"alive")
	Traceback (most recent call last):
	...
	ValueError: given buffer is not exactly four bytes long

	@type fourbytes: bytes
	@rtype: str
	@raises ValueError: for bad input
	"""
	if not isinstance(fourbytes, bytes):
		raise ValueError("given buffer is not a string")
	if len(fourbytes) != 4:
		raise ValueError("given buffer is not exactly four bytes long")
	return ".".join(map(str, bytes_to_int_seq(fourbytes)))

__all__.append("pack_mac")
def pack_mac(macstr):
	"""Converts a mac address given in colon delimited notation to a
	six byte string in network byte order.

	>>> pack_mac("30:31:32:33:34:35") == b'012345'
	True
	>>> pack_mac("bad")
	Traceback (most recent call last):
	...
	ValueError: given mac addresses has an invalid number of colons


	@type macstr: str
	@rtype: bytes
	@raises ValueError: for badly formatted mac addresses
	"""
	if not isinstance(macstr, basestring):
		raise ValueError("given mac addresses is not a string")
	parts = macstr.split(":")
	if len(parts) != 6:
		raise ValueError("given mac addresses has an invalid number of colons")
	parts = [int(part, 16) for part in parts] # raises ValueError
	return int_seq_to_bytes(parts) # raises ValueError

__all__.append("unpack_mac")
def unpack_mac(sixbytes):
	"""Converts a mac address given in a six byte string in network
	byte order to a string in colon delimited notation.

	>>> unpack_mac(b"012345")
	'30:31:32:33:34:35'
	>>> unpack_mac(b"bad")
	Traceback (most recent call last):
	...
	ValueError: given buffer is not exactly six bytes long

	@type sixbytes: bytes
	@rtype: str
	@raises ValueError: for bad input
	"""
	if not isinstance(sixbytes, bytes):
		raise ValueError("given buffer is not a string")
	if len(sixbytes) != 6:
		raise ValueError("given buffer is not exactly six bytes long")
	return ":".join(map("%2.2x".__mod__, bytes_to_int_seq(sixbytes)))

class lazy_str(object):
	def __init__(self, function):
		self.function = function
	def __str__(self):
		return self.function()

__all__.append("Omapi")
class Omapi(object):
	def __init__(self, hostname, port, username=None, key=None):
		"""
		@type hostname: str
		@type port: int
		@type username: bytes or None
		@type key: bytes or None
		@param key: if given, it must be base64 encoded
		@raises binascii.Error: for bad base64 encoding
		@raises socket.error:
		@raises OmapiError:
		"""
		self.hostname = hostname
		self.port = port
		self.authenticators = {0: OmapiNullAuthenticator()}
		self.defauth = 0

		newauth = None
		if username is not None and key is not None:
			newauth = OmapiHMACMD5Authenticator(username, key)

		self.connection = socket.socket()
		self.inbuffer = InBuffer()
		self.connection.connect((hostname, port))

		self.send_protocol_initialization()
		self.recv_protocol_initialization()

		if newauth:
			self.initialize_authenticator(newauth)

	def close(self):
		"""Close the omapi connection if it is open."""
		if self.connection:
			self.connection.close()
			self.connection = None

	def check_connected(self):
		"""Raise an OmapiError unless connected.
		@raises OmapiError:
		"""
		if not self.connection:
			raise OmapiError("not connected")

	def recv_conn(self, length):
		"""Receive up to length bytes of data from the connection.

		@type length: int
		@rtype: bytes
		@raises OmapiError: if not connected
		@raises socket.error:
		"""
		self.check_connected()
		try:
			return self.connection.recv(length)
		except socket.error:
			self.close()
			raise

	def send_conn(self, data):
		"""Send all of data to the connection.

		@type data: bytes
		@raises OmapiError: if not connected
		@raises socket.error:
		"""
		self.check_connected()
		try:
			self.connection.sendall(data)
		except socket.error:
			self.close()
			raise

	def fill_inbuffer(self):
		"""
		@raises OmapiError:
		@raises socket.error:
		"""
		data = self.recv_conn(2048)
		if not data:
			self.close()
			raise OmapiError("connection closed")
		try:
			self.inbuffer.feed(data)
		except OmapiSizeLimitError:
			self.close()
			raise

	def send_protocol_initialization(self):
		"""
		@raises OmapiError:
		@raises socket.error:
		"""
		self.check_connected()
		message = OmapiStartupMessage()
		logger.debug("sending omapi startup message %s",
				lazy_str(message.dump_oneline))
		self.send_conn(message.as_string())

	def recv_protocol_initialization(self):
		"""
		@raises OmapiError:
		@raises socket.error:
		"""
		for result in self.inbuffer.parse_startup_message():
			if result is None:
				self.fill_inbuffer()
			else:
				self.inbuffer.resetsize()
				logger.debug("received omapi startup message %s",
						lazy_str(result.dump_oneline))
				try:
					result.validate()
				except OmapiError:
					self.close()
					raise

	def receive_message(self):
		"""Read the next message from the connection.
		@rtype: OmapiMessage
		@raises OmapiError:
		@raises socket.error:
		"""
		for message in self.inbuffer.parse_message():
			if message is None:
				self.fill_inbuffer()
			else:
				self.inbuffer.resetsize()
				logger.debug("received %s", lazy_str(message.dump_oneline))
				if not message.verify(self.authenticators):
					self.close()
					raise OmapiError("bad omapi message signature")
				return message

	def receive_response(self, message, insecure=False):
		"""Read the response for the given message.
		@type message: OmapiMessage
		@type insecure: bool
		@param insecure: avoid an OmapiError about a wrong authenticator
		@rtype: OmapiMessage
		@raises OmapiError:
		@raises socket.error:
		"""
		response = self.receive_message()
		if not response.is_response(message):
			raise OmapiError("received message is not the desired response")
		# signature already verified
		if response.authid != self.defauth and not insecure:
			raise OmapiError("received message is signed with wrong " +
						"authenticator")
		return response

	def send_message(self, message, sign=True):
		"""Sends the given message to the connection.
		@type message: OmapiMessage
		@type sign: bool
		@param sign: whether the message needs to be signed
		@raises OmapiError:
		@raises socket.error:
		"""
		self.check_connected()
		if sign:
			message.sign(self.authenticators[self.defauth])
		logger.debug("sending %s", lazy_str(message.dump_oneline))
		self.send_conn(message.as_string())

	def query_server(self, message):
		"""Send the message and receive a response for it.
		@type message: OmapiMessage
		@rtype: OmapiMessage
		@raises OmapiError:
		@raises socket.error:
		"""
		self.send_message(message)
		return self.receive_response(message)
		

	def initialize_authenticator(self, authenticator):
		"""
		@type authenticator: OmapiAuthenticatorBase
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
		self.authenticators[authid] = authenticator
		authenticator.authid = authid
		self.defauth = authid
		logger.debug("successfully initialized default authid %d", authid)

	def add_host(self, ip, mac):
		"""Create a host object with given ip address and and mac address.

		@type ip: str
		@type mac: str
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

	def del_host(self, mac):
		"""Delete a host object with with given mac address.

		@type mac: str
		@raises ValueError:
		@raises OmapiError:
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

	def lookup_ip(self, mac):
		"""Look for a lease object with given mac address and return the
		assigned ip address.

		@type mac: str
		@rtype: str or None
		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given mac
				address could be found or the object lacks an ip address
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"lease")
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		try:
			return unpack_ip(dict(response.obj)[b"ip-address"])
		except KeyError: # ip-address
			raise OmapiErrorNotFound()

	def lookup_mac(self, ip):
		"""Look up a lease object with given ip address and return the
		associated mac address.

		@type ip: str
		@rtype: str or None
		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given ip
				address could be found or the object lacks a mac address
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"lease")
		msg.obj.append((b"ip-address", pack_ip(ip)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		try:
			return unpack_mac(dict(response.obj)[b"hardware-address"])
		except KeyError: # hardware-address
			raise OmapiErrorNotFound()

if __name__ == '__main__':
	import doctest
	doctest.testmod()
