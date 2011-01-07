#!/usr/bin/python
# -*- coding: utf8 -*-

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
__version__     = "0.1"
__maintainer__  = "Torge Szczepanek"
__email__       = "info@cygnusnetworks.de"

__all__ = []

import struct
import hmac
import socket
import random
import operator
import sys
try:
	from cStringIO import StringIO
except ImportError:
	import StringIO

sysrand = random.SystemRandom()

OMAPI_OP_OPEN    = 1
OMAPI_OP_REFRESH = 2
OMAPI_OP_UPDATE  = 3
OMAPI_OP_NOTIFY  = 4
OMAPI_OP_STATUS  = 5
OMAPI_OP_DELETE  = 6

def repr_opcode(opcode):
	"""
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

class OutBuffer:
	"""Helper class for constructing network packets."""
	sizelimit = 65536
	def __init__(self):
		self.buff = StringIO()

	def add(self, data):
		"""
		@type data: str
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		self.buff.write(data)
		if self.buff.tell() > self.sizelimit:
			raise OmapiSizeLimitError()
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
		@type string: str
		@param string: maximum length must fit in a 32bit integer
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if len(string) >= (1 << 32):
			raise ValueError("string too long")
		return self.add_net32int(len(string)).add(string)

	def add_net16string(self, string):
		"""
		@type string: str
		@param string: maximum length must fit in a 16bit integer
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if len(string) >= (1 << 16):
			raise ValueError("string too long")
		return self.add_net16int(len(string)).add(string)

	def add_bindict(self, items):
		"""
		>>> OutBuffer().add_bindict(dict(foo="bar")).getvalue()
		'\\x00\\x03foo\\x00\\x00\\x00\\x03bar\\x00\\x00'

		@type items: [(str, str)] or {str: str}
		@returns: self
		@raises OmapiSizeLimitError:
		"""
		if not isinstance(items, list):
			items = items.items()
		for key, value in items:
			self.add_net16string(key).add_net32string(value)
		return self.add("\x00\x00") # end marker

	def getvalue(self):
		"""
		@rtype: str
		"""
		return self.buff.getvalue()

	def consume(self, length):
		"""
		@type length: int
		@returns: self
		"""
		self.buff = StringIO(self.getvalue()[length:])
		return self

class OmapiAuthenticatorBase:
	"""Base class for OMAPI authenticators."""
	authlen = -1 # must be overwritten
	algorithm = None
	authid = -1 # will be an instance attribute
	def __init__(self):
		pass
	def auth_object(self):
		"""
		@rtype: {str: str}
		@returns: object part of an omapi authentication message
		"""
		raise NotImplementedError
	def sign(self, message):
		"""
		@type message: str
		@rtype: str
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
		return ""

class OmapiHMACMD5Authenticator(OmapiAuthenticatorBase):
	authlen = 16
	algorithm = "hmac-md5.SIG-ALG.REG.INT."
	def __init__(self, user, key):
		"""
		@type user: str
		@type key: str
		@param key: base64 encoded key
		@raises binascii.Error: for bad base64 encoding
		"""
		OmapiAuthenticatorBase.__init__(self)
		self.user = user
		self.key = key.decode("base64")

	def auth_object(self):
		return dict(name=self.user, algorithm=self.algorithm)

	def sign(self, message):
		return hmac.HMAC(self.key, message).digest()

class OmapiMessage:
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
	@type message: [(str, str)]
	@ivar message: A list of (key, value) pairs.
	@type obj: [(str, str)]
	@ivar obj: A list of (key, value) pairs.
	@type signature: str
	@ivar signature: A signature on this message as generated by an
			authenticator.
	"""
	def __init__(self, authid=0, opcode=0, handle=0, tid=0, rid=0,
			message=None, obj=None, signature=""):
		"""
		Construct an OmapiMessage from the given fields. No error
		checking is performed.

		@type authid: int
		@type opcode: int
		@type handle: int
		@type tid: int
		@param tid: The special value -1 causes a tid to be generated randomly.
		@type rid: int
		@type message: [(str, str)]
		@type obj: [(str, str)]
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
		"""Generate a random transmission id for this OMAPI message."""
		self.tid = sysrand.randrange(0, 1<<32)

	def as_string(self, forsigning=False):
		"""
		@type forsigning: bool
		@rtype: str
		@raises OmapiSizeLimitError:
		"""
		ret = OutBuffer()
		if not forsigning:
			ret.add_net32int(self.authid)
		ret.add_net32int(len(self.signature))
		ret.add_net32int(self.opcode)
		ret.add_net32int(self.handle)
		ret.add_net32int(self.tid)
		ret.add_net32int(self.rid)
		ret.add_bindict(self.message)
		ret.add_bindict(self.obj)
		if not forsigning:
			ret.add(self.signature)
		return ret.getvalue()

	def sign(self, authenticator):
		"""Sign this OMAPI message.
		@type authenticator: OmapiAuthenticatorBase
		"""
		self.authid = authenticator.authid
		self.signature = "\0" * authenticator.authlen # provide authlen
		self.signature = authenticator.sign(self.as_string(forsigning=True))
		assert len(self.signature) == authenticator.authlen

	def verify(self, authenticators):
		"""Verify this OMAPI message.
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
		@type typename: str
		@rtype: OmapiMessage
		"""
		return cls(opcode=OMAPI_OP_OPEN, message=[("type", typename)], tid=-1)

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
		@type update: {str: str}
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

def parse_map(filterfun, parser):
	"""
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
	"""
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

class InBuffer:
	sizelimit = 65536
	def __init__(self):
		self.buff = ""
		self.totalsize = 0
		self.parsing = None

	def feed(self, data):
		"""
		@type data: str
		@raises OmapiSizeLimitError:
		"""
		self.buff += data
		self.totalsize += len(data)
		if self.totalsize > self.sizelimit:
			raise OmapiSizeLimitError()

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
		return parse_map(lambda data: struct.unpack("!H", data)[0],
				self.parse_fixedbuffer(2))

	def parse_net32int(self):
		return parse_map(lambda data: struct.unpack("!L", data)[0],
				self.parse_fixedbuffer(4))

	def parse_net16string(self):
		return parse_map(operator.itemgetter(1),
				parse_chain(self.parse_net16int, self.parse_fixedbuffer))

	def parse_net32string(self):
		return parse_map(operator.itemgetter(1),
				parse_chain(self.parse_net32int, self.parse_fixedbuffer))

	def parse_bindict(self):
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
		# results in (version, headersize)
		return parse_chain(self.parse_net32int, lambda _: self.parse_net32int())

	def parse_message(self):
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
	@rtype: str
	@raises ValueError: for badly formatted ip addresses
	"""
	if not isinstance(ipstr, str):
		raise ValueError("given ip address is not a string")
	parts = ipstr.split('.')
	if len(parts) != 4:
		raise ValueError("given ip address has an invalid number of dots")
	parts = map(int, parts) # raises ValueError
	parts = map(chr, parts) # raises ValueError
	return "".join(parts) # network byte order

def unpack_ip(fourbytes):
	"""Converts an ip address given in a four byte string in network
	byte order to a string in dotted notation.

	>>> unpack_ip("dead")
	'100.101.97.100'
	>>> unpack_ip("alive")
	Traceback (most recent call last):
	...
	ValueError: given buffer is not exactly four bytes long

	@type fourbytes: str
	@rtype: str
	@raises ValueError: for bad input
	"""
	if not isinstance(fourbytes, str):
		raise ValueError("given buffer is not a string")
	if len(fourbytes) != 4:
		raise ValueError("given buffer is not exactly four bytes long")
	return ".".join(map(str, map(ord, fourbytes)))

def pack_mac(macstr):
	"""Converts a mac address given in colon delimited notation to a
	six byte string in network byte order.

	>>> pack_mac("30:31:32:33:34:35")
	'012345'
	>>> pack_mac("bad")
	Traceback (most recent call last):
	...
	ValueError: given mac addresses has an invalid number of colons


	@type macstr: str
	@rtype: str
	@raises ValueError: for badly formatted mac addresses
	"""
	if not isinstance(macstr, str):
		raise ValueError("given mac addresses is not a string")
	parts = macstr.split(":")
	if len(parts) != 6:
		raise ValueError("given mac addresses has an invalid number of colons")
	parts = [int(part, 16) for part in parts] # raises ValueError
	parts = map(chr, parts) # raises ValueError
	return "".join(parts) # network byte order

def unpack_mac(sixbytes):
	"""Converts a mac address given in a six byte string in network
	byte order to a string in colon delimited notation.

	>>> unpack_mac("012345")
	'30:31:32:33:34:35'
	>>> unpack_mac("bad")
	Traceback (most recent call last):
	...
	ValueError: given buffer is not exactly six bytes long

	@type sixbytes: str
	@rtype: str
	@raises ValueError: for bad input
	"""
	if not isinstance(sixbytes, str):
		raise ValueError("given buffer is not a string")
	if len(sixbytes) != 6:
		raise ValueError("given buffer is not exactly six bytes long")
	return ":".join(map("%2.2x".__mod__, map(ord, sixbytes)))

__all__.append("Omapi")
class Omapi:
	protocol_version = 100

	def __init__(self, hostname, port, username=None, key=None, debug=False):
		"""
		@type hostname: str
		@type port: int
		@type username: str or None
		@type key: str or None
		@type debug: bool
		@param key: if given, it must be base64 encoded
		@raises binascii.Error: for bad base64 encoding
		@raises socket.error:
		@raises OmapiError:
		"""
		self.hostname = hostname
		self.port = port
		self.authenticators = {0: OmapiNullAuthenticator()}
		self.defauth = 0
		self.debug = debug

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

		@type data: str
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
		buff = OutBuffer()
		buff.add_net32int(self.protocol_version)
		buff.add_net32int(4*6) # header size
		self.send_conn(buff.getvalue())

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
				protocol_version, header_size = result
				if protocol_version != self.protocol_version:
					self.close()
					raise OmapiError("protocol mismatch")
				if header_size != 4*6:
					self.close()
					raise OmapiError("header size mismatch")

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
		if self.debug:
			print "debug recv"
			sys.stdout.write(response.dump())
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
		if self.debug:
			print "debug send"
			sys.stdout.write(message.dump())
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
		msg = OmapiMessage.open("authenticator")
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

	def add_host(self, ip, mac):
		"""
		@type ip: str
		@type mac: str
		@raises ValueError:
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open("host")
		msg.message.append(("create", struct.pack("!I", 1)))
		msg.message.append(("exclusive", struct.pack("!I", 1)))
		msg.obj.append(("hardware-address", pack_mac(mac)))
		msg.obj.append(("hardware-type", struct.pack("!I", 1)))
		msg.obj.append(("ip-address", pack_ip(ip)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiError("add failed")

	def del_host(self, mac):
		"""
		@type mac: str
		@raises ValueError:
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open("host")
		msg.obj.append(("hardware-address", pack_mac(mac)))
		msg.obj.append(("hardware-type", struct.pack("!I", 1)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		if response.handle == 0:
			raise OmapiError("received invalid handle from server")
		response = self.query_server(OmapiMessage.delete(response.handle))
		if response.opcode != OMAPI_OP_STATUS:
			raise OmapiError("delete failed")

	def lookup_ip(self, mac):
		"""
		@type mac: str
		@rtype: str or None
		@raises ValueError:
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open("lease")
		msg.obj.append(("hardware-address", pack_mac(mac)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		try:
			return unpack_ip(dict(response.obj)["ip-address"])
		except KeyError: # ip-address
			raise OmapiErrorNotFound()

	def lookup_mac(self, ip):
		"""
		@type ip: str
		@rtype: str or None
		@raises ValueError:
		@raises OmapiError:
		@raises socket.error:
		"""
		msg = OmapiMessage.open("lease")
		msg.obj.append(("ip-address", pack_ip(ip)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		try:
			return unpack_mac(dict(response.obj)["hardware-address"])
		except KeyError: # hardware-address
			raise OmapiErrorNotFound()

if __name__ == '__main__':
	import doctest
	doctest.testmod()
