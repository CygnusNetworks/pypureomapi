"""Unit tests for the protocol primitives: buffers, messages, parsing, helpers."""

import base64
import binascii
import struct
import types

import pytest

import pypureomapi
from pypureomapi import (
	InBuffer,
	OutBuffer,
	OmapiMessage,
	OmapiStartupMessage,
	OmapiError,
	OmapiSizeLimitError,
	OmapiNullAuthenticator,
	OmapiHMACMD5Authenticator,
	OmapiProtocol,
	repr_opcode,
	pack_ip,
	unpack_ip,
	pack_mac,
	unpack_mac,
	encode_classless_static_routes,
	OMAPI_OP_OPEN,
	OMAPI_OP_UPDATE,
	OMAPI_OP_DELETE,
	OMAPI_OP_STATUS,
)

KEY = base64.b64encode(b"0123456789abcdef")


# --- repr_opcode ------------------------------------------------------------

def test_repr_opcode_known_and_unknown():
	assert repr_opcode(OMAPI_OP_OPEN) == "open"
	assert repr_opcode(OMAPI_OP_DELETE) == "delete"
	assert repr_opcode(99) == "unknown (99)"


# --- OutBuffer --------------------------------------------------------------

def test_outbuffer_int_bounds():
	with pytest.raises(ValueError):
		OutBuffer().add_net32int(-1)
	with pytest.raises(ValueError):
		OutBuffer().add_net32int(1 << 32)
	with pytest.raises(ValueError):
		OutBuffer().add_net16int(-1)
	with pytest.raises(ValueError):
		OutBuffer().add_net16int(1 << 16)


def test_outbuffer_net16string_too_long():
	with pytest.raises(ValueError):
		OutBuffer().add_net16string(b"x" * (1 << 16))


def test_outbuffer_consume_and_len():
	buf = OutBuffer().add(b"spam")
	assert len(buf) == 4
	assert buf.consume(2).getvalue() == b"am"


def test_outbuffer_bindict_list_and_dict_equal():
	as_list = OutBuffer().add_bindict([(b"foo", b"bar")]).getvalue()
	as_dict = OutBuffer().add_bindict({b"foo": b"bar"}).getvalue()
	assert as_list == as_dict == b"\x00\x03foo\x00\x00\x00\x03bar\x00\x00"


# --- InBuffer ---------------------------------------------------------------

def test_inbuffer_size_limit():
	buf = InBuffer()
	with pytest.raises(OmapiSizeLimitError):
		buf.feed(b"x" * (InBuffer.sizelimit + 1))


def test_inbuffer_parse_ints_and_strings():
	assert next(InBuffer(b"\x01\x02").parse_net16int()) == 0x102
	assert next(InBuffer(b"\x01\x00\x00\x02").parse_net32int()) == 0x1000002
	assert next(InBuffer(b"\x00\x03egg").parse_net16string()) == b"egg"
	assert next(InBuffer(b"\x00\x00\x00\x03egg").parse_net32string()) == b"egg"


def test_inbuffer_partial_feed():
	buf = InBuffer()
	parser = buf.parse_net32int()
	assert next(parser) is None      # nothing fed yet
	buf.feed(b"\x00\x00")
	assert next(parser) is None      # still incomplete
	buf.feed(b"\x00\x05")
	assert next(parser) == 5


# --- OmapiMessage -----------------------------------------------------------

def test_message_named_constructors():
	assert OmapiMessage.open(b"host").opcode == OMAPI_OP_OPEN
	assert OmapiMessage.open(b"host").message == [(b"type", b"host")]
	assert OmapiMessage.update(7).opcode == OMAPI_OP_UPDATE
	assert OmapiMessage.update(7).handle == 7
	assert OmapiMessage.delete(9).opcode == OMAPI_OP_DELETE


def test_message_is_response():
	req = OmapiMessage(tid=1234)
	assert OmapiMessage(rid=1234).is_response(req)
	assert not OmapiMessage(rid=1).is_response(req)


def test_message_update_object_replaces():
	msg = OmapiMessage(obj=[(b"name", b"old"), (b"keep", b"x")])
	msg.update_object({b"name": b"new"})
	assert dict(msg.obj) == {b"name": b"new", b"keep": b"x"}


def test_message_dump_contains_fields():
	msg = OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=3, tid=5, rid=6)
	assert "opcode:" in msg.dump()
	assert "handle=3" in msg.dump_oneline()


def test_message_roundtrip_signed():
	auth = OmapiHMACMD5Authenticator(b"user", KEY)
	auth.authid = 5
	msg = OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=9, tid=123, rid=456,
			message=[(b"k", b"v")], obj=[(b"a", b"b")])
	msg.sign(auth)
	parsed = next(InBuffer(msg.as_string()).parse_message())
	assert (parsed.opcode, parsed.handle, parsed.tid, parsed.rid) == (OMAPI_OP_UPDATE, 9, 123, 456)
	assert parsed.message == [(b"k", b"v")]
	assert parsed.obj == [(b"a", b"b")]
	assert parsed.authid == 5
	assert parsed.signature == msg.signature
	assert parsed.verify({5: auth})


def test_generate_tid_randomish():
	assert OmapiMessage(tid=-1).tid != OmapiMessage(tid=-1).tid


# --- OmapiStartupMessage ----------------------------------------------------

def test_startup_header_size_mismatch():
	with pytest.raises(OmapiError):
		OmapiStartupMessage(header_size=999).validate()


def test_startup_dump_and_roundtrip():
	msg = OmapiStartupMessage()
	assert "protocol_version=" in msg.dump_oneline()
	parsed = next(InBuffer(msg.as_string()).parse_startup_message())
	parsed.validate()


# --- authenticators ---------------------------------------------------------

def test_null_authenticator():
	auth = OmapiNullAuthenticator()
	assert auth.auth_object() == {}
	assert auth.sign(b"whatever") == b""
	assert auth.authlen == 0


def test_hmac_authenticator_auth_object_and_sign():
	auth = OmapiHMACMD5Authenticator(b"user", KEY)
	assert auth.auth_object() == {b"name": b"user", b"algorithm": auth.algorithm}
	assert len(auth.sign(b"payload")) == auth.authlen == 16


def test_hmac_authenticator_bad_base64():
	with pytest.raises(binascii.Error):
		OmapiHMACMD5Authenticator(b"user", b"!!!not-base64!!!")


# --- pack/unpack ------------------------------------------------------------

def test_pack_unpack_ip_roundtrip_and_errors():
	assert unpack_ip(pack_ip("10.20.30.40")) == "10.20.30.40"
	with pytest.raises(ValueError):
		pack_ip(1234)  # not a string
	with pytest.raises(ValueError):
		pack_ip("1.2.3")  # wrong number of dots
	with pytest.raises(ValueError):
		pack_ip("256.0.0.1")  # octet out of range
	with pytest.raises(ValueError):
		unpack_ip("notbytes")
	with pytest.raises(ValueError):
		unpack_ip(b"toolong!")


def test_pack_unpack_mac_roundtrip_and_errors():
	assert unpack_mac(pack_mac("aa:bb:cc:dd:ee:ff")) == "aa:bb:cc:dd:ee:ff"
	with pytest.raises(ValueError):
		pack_mac(1234)  # not a string
	with pytest.raises(ValueError):
		pack_mac("aa:bb:cc")  # too few groups
	with pytest.raises(ValueError):
		pack_mac(":".join(["00"] * 17))  # too many groups
	with pytest.raises(ValueError):
		pack_mac("zz:bb:cc:dd:ee:ff")  # invalid hex
	with pytest.raises(ValueError):
		pack_mac(" 0a:bb:cc:dd:ee:ff")  # whitespace in group
	with pytest.raises(ValueError):
		pack_mac("1ff:bb:cc:dd:ee:ff")  # group out of range
	assert pack_mac("0:1:2:3:4:5") == bytes(range(6))  # single hex digit groups
	assert pack_mac(":".join(["ab"] * 16)) == b"\xab" * 16
	with pytest.raises(ValueError):
		unpack_mac("notbytes")
	with pytest.raises(ValueError):
		unpack_mac(b"")
	with pytest.raises(ValueError):
		unpack_mac(b"\x00" * 17)


def test_pack_unpack_mac_eui64():
	# issue #49: 8 byte EUI-64 hardware addresses (e.g. IEEE 802.15.4)
	packed = pack_mac("00:12:4B:00:0B:27:67:4B")
	assert packed == bytes.fromhex("00124b000b27674b")
	assert unpack_mac(packed) == "00:12:4b:00:0b:27:67:4b"


# --- classless static routes (issue #31) ------------------------------------

def test_encode_classless_static_routes_vectors():
	assert encode_classless_static_routes([("10.0.0.0/8", "192.168.1.1")]) == "08:0a:c0:a8:01:01"
	assert encode_classless_static_routes([("0.0.0.0/0", "10.0.0.1")]) == "00:0a:00:00:01"
	assert encode_classless_static_routes([("192.168.1.0/24", "10.0.0.1")]) == "18:c0:a8:01:0a:00:00:01"


def test_encode_classless_static_routes_multiple_concatenate():
	value = encode_classless_static_routes([
		("10.0.0.0/8", "192.168.1.1"),
		("0.0.0.0/0", "10.0.0.1"),
	])
	assert value == "08:0a:c0:a8:01:01:00:0a:00:00:01"


def test_encode_classless_static_routes_errors():
	with pytest.raises(ValueError):
		encode_classless_static_routes([("10.0.0.0", "1.2.3.4")])  # missing /prefix
	with pytest.raises(ValueError):
		encode_classless_static_routes([("10.0.0.0/33", "1.2.3.4")])  # prefix out of range


# --- OmapiProtocol byte pump ------------------------------------------------

def _dummy_transport():
	closed = []
	return types.SimpleNamespace(close=lambda: closed.append(True), closed=closed)


def test_protocol_data_received_startup_then_message():
	proto = OmapiProtocol()
	proto.transport = _dummy_transport()
	received = []
	proto.message_received = received.append
	proto.data_received(OmapiStartupMessage().as_string())
	msg = OmapiMessage(opcode=OMAPI_OP_STATUS, obj=[(b"a", b"b")])
	proto.data_received(msg.as_string())
	assert len(received) == 1
	assert received[0].opcode == OMAPI_OP_STATUS
	assert received[0].obj == [(b"a", b"b")]


def test_protocol_startup_mismatch_closes_transport():
	proto = OmapiProtocol()
	proto.transport = _dummy_transport()
	with pytest.raises(OmapiError):
		proto.data_received(OmapiStartupMessage(protocol_version=42).as_string())
	assert proto.transport.closed == [True]


def test_protocol_message_received_default_is_noop():
	# The base OmapiProtocol.message_received just ignores the message.
	assert OmapiProtocol().message_received(OmapiMessage()) is None


def test_authenticator_base_is_abstract():
	base = pypureomapi.OmapiAuthenticatorBase()
	with pytest.raises(NotImplementedError):
		base.auth_object()
	with pytest.raises(NotImplementedError):
		base.sign(b"x")


def test_lazystr_defers_call():
	calls = []

	def make():
		calls.append(1)
		return "value"

	lazy = pypureomapi.LazyStr(make)
	assert calls == []          # not called on construction
	assert str(lazy) == "value"
	assert calls == [1]
