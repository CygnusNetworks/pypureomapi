"""Unit tests for pypureomapi.

These tests exercise the pure serialization/parsing code paths without a real
DHCP server connection. The add_*/change_group tests are regressions for a bug
where str keys/values (instead of bytes) were appended to a message, which made
serialization fail on Python 3.
"""

import struct

import pytest

import pypureomapi


def test_pack_unpack_ip_roundtrip():
	assert pypureomapi.unpack_ip(pypureomapi.pack_ip("192.168.0.250")) == "192.168.0.250"


def test_pack_mac():
	assert pypureomapi.pack_mac("30:31:32:33:34:35") == b"012345"


def test_unpack_mac():
	assert pypureomapi.unpack_mac(b"012345") == "30:31:32:33:34:35"


def test_pack_ip_invalid():
	with pytest.raises(ValueError):
		pypureomapi.pack_ip("foo")


def test_unpack_ip_invalid_length():
	with pytest.raises(ValueError):
		pypureomapi.unpack_ip(b"alive")


def test_outbuffer_bindict():
	value = pypureomapi.OutBuffer().add_bindict({b"foo": b"bar"}).getvalue()
	assert value == b"\x00\x03foo\x00\x00\x00\x03bar\x00\x00"


def test_outbuffer_size_limit():
	buff = pypureomapi.OutBuffer().add(pypureomapi.OutBuffer.sizelimit * b"x")
	with pytest.raises(pypureomapi.OmapiSizeLimitError):
		buff.add(b"y")


def test_startup_message_roundtrip():
	data = pypureomapi.OmapiStartupMessage().as_string()
	parsed = next(pypureomapi.InBuffer(data).parse_startup_message())
	parsed.validate()  # must not raise


def test_startup_message_protocol_mismatch():
	with pytest.raises(pypureomapi.OmapiError):
		pypureomapi.OmapiStartupMessage(42).validate()


def test_parse_bindict():
	data = b"\x00\x01a\x00\x00\x00\x01b\x00\x00spam"
	assert next(pypureomapi.InBuffer(data).parse_bindict()) == [(b"a", b"b")]


def test_parse_bindict_multiple_entries():
	msg = pypureomapi.OmapiMessage(obj=[(b"a", b"b"), (b"cc", b"dddd")])
	data = msg.as_string()
	parsed = next(pypureomapi.InBuffer(data).parse_message())
	assert parsed.obj == [(b"a", b"b"), (b"cc", b"dddd")]


def test_message_sign_verify():
	auth = pypureomapi.OmapiHMACMD5Authenticator(b"egg", b"spam")
	auth.authid = 5
	msg = pypureomapi.OmapiMessage.open(b"host")
	assert msg.verify({auth.authid: auth}) is False
	msg.sign(auth)
	assert msg.verify({auth.authid: auth}) is True


class _FakeOmapi(pypureomapi.Omapi):
	"""Omapi subclass that records messages and serializes them (to surface
	bytes/str bugs) instead of talking to a server."""

	def __init__(self):  # pylint:disable=super-init-not-called
		self.sent = []

	def query_server(self, message):
		# Force serialization: this is what fails when a str sneaks into obj.
		message.as_string()
		self.sent.append(message)
		return pypureomapi.OmapiMessage(opcode=pypureomapi.OMAPI_OP_UPDATE, handle=1)


def test_add_group_serializes():
	omapi = _FakeOmapi()
	omapi.add_group("mygroup", 'ddns-hostname "foo";')
	sent = dict(omapi.sent[-1].obj)
	assert sent[b"name"] == b"mygroup"
	assert sent[b"statements"] == b'ddns-hostname "foo";'


def test_add_host_with_group_serializes():
	omapi = _FakeOmapi()
	omapi.add_host_with_group("192.168.0.1", "00:11:22:33:44:55", "mygroup")
	sent = dict(omapi.sent[-1].obj)
	assert sent[b"group"] == b"mygroup"
	assert sent[b"ip-address"] == pypureomapi.pack_ip("192.168.0.1")


def test_add_host_supersede_serializes():
	omapi = _FakeOmapi()
	omapi.add_host_supersede("192.168.0.1", "00:11:22:33:44:55", "myhost", hostname="h", router="192.168.0.254")
	sent = dict(omapi.sent[-1].obj)
	assert sent[b"name"] == b"myhost"
	assert b"supersede host-name" in sent[b"statements"]


def test_change_group_serializes():
	omapi = _FakeOmapi()
	omapi.change_group("myhost", "mygroup")
	first, second = omapi.sent
	assert dict(first.obj)[b"name"] == b"myhost"
	assert dict(second.obj)[b"group"] == b"mygroup"


def test_lookup_by_failoverstate_opens_failover_state_type():
	omapi = _FakeOmapi()
	omapi.lookup_by_failoverstate(name="dhcp-failover")
	sent = omapi.sent[-1]
	assert dict(sent.message)[b"type"] == b"failover-state"
	assert dict(sent.obj)[b"name"] == b"dhcp-failover"


def test_lookup_failoverstate_missing_attribute():
	omapi = _FakeOmapi()  # fake response has no obj attributes
	with pytest.raises(pypureomapi.OmapiErrorAttributeNotFound):
		omapi.lookup_failoverstate("dhcp-failover", "partner-state")


def test_lookup_host_by_ip_missing_attribute():
	omapi = _FakeOmapi()
	with pytest.raises(pypureomapi.OmapiErrorAttributeNotFound):
		omapi.lookup_host_by_ip("192.168.0.1")
