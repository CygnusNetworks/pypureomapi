"""End-to-end Omapi client tests driven by an in-process fake OMAPI server."""

import base64
import socket
import struct

import pytest

import pypureomapi
from pypureomapi import (
	OmapiMessage,
	OmapiError,
	OmapiErrorNotFound,
	OmapiErrorAttributeNotFound,
	OMAPI_OP_OPEN,
	OMAPI_OP_UPDATE,
	OMAPI_OP_STATUS,
	OMAPI_OP_DELETE,
	pack_ip,
	pack_mac,
)
from fakeserver import FakeOmapiServer

KEY = base64.b64encode(b"0123456789abcdef")


def _loopback_available():
	try:
		sock = socket.socket()
		sock.bind(("127.0.0.1", 0))
		sock.close()
		return True
	except OSError:  # pragma: no cover - only in restricted build sandboxes
		return False


# Skip the whole end-to-end module where loopback networking is unavailable
# (e.g. some RPM/deb build chroots), rather than failing the build.
pytestmark = pytest.mark.skipif(not _loopback_available(), reason="no loopback networking")


def connect(port, **kwargs):
	try:
		return pypureomapi.Omapi("127.0.0.1", port, timeout=5, **kwargs)
	except OSError as exc:  # pragma: no cover - only in sandboxes without loopback
		pytest.skip(f"loopback networking unavailable: {exc}")


def const(response):
	"""A responder that always returns the same response."""
	return lambda request: response


# --- lease/host lookups -----------------------------------------------------

def test_lookup_ip():
	obj = [(b"ip-address", pack_ip("192.168.0.5"))]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_ip("00:11:22:33:44:55") == "192.168.0.5"
		omapi.close()


def test_lookup_mac():
	obj = [(b"hardware-address", pack_mac("00:11:22:33:44:55"))]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_mac("192.168.0.5") == "00:11:22:33:44:55"
		omapi.close()


def test_lookup_ip_host():
	obj = [(b"ip-address", pack_ip("10.0.0.1"))]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_ip_host("00:11:22:33:44:55") == "10.0.0.1"
		omapi.close()


def test_lookup_host():
	obj = [
		(b"ip-address", pack_ip("10.0.0.2")),
		(b"hardware-address", pack_mac("00:11:22:33:44:66")),
		(b"name", b"myhost"),
	]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		res = omapi.lookup_host("myhost")
		assert res == {"ip": "10.0.0.2", "mac": "00:11:22:33:44:66", "hostname": "myhost"}
		omapi.close()


def test_lookup_host_host():
	obj = [
		(b"ip-address", pack_ip("10.0.0.3")),
		(b"hardware-address", pack_mac("00:11:22:33:44:77")),
		(b"name", b"other"),
	]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		res = omapi.lookup_host_host("00:11:22:33:44:77")
		assert res["name"] == "other" and res["ip"] == "10.0.0.3"
		omapi.close()


def test_lookup_host_by_ip():
	obj = [
		(b"ip-address", pack_ip("10.0.0.9")),
		(b"hardware-address", pack_mac("00:11:22:33:44:99")),
		(b"name", b"byip"),
	]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_host_by_ip("10.0.0.9")["hostname"] == "byip"
		omapi.close()


def test_lookup_hostname():
	obj = [(b"client-hostname", b"client42")]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_hostname("192.168.0.5") == "client42"
		omapi.close()


def test_lookup_by_lease_decodes_attributes():
	obj = [
		(b"ip-address", pack_ip("192.168.10.20")),
		(b"hardware-address", pack_mac("24:79:2a:0a:13:c0")),
		(b"starts", struct.pack(">I", 1549885390)),
		(b"state", struct.pack(">I", 2)),
		(b"client-hostname", b"leasehost"),
	]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		res = omapi.lookup_by_lease(mac="24:79:2a:0a:13:c0")
		assert res["ip-address"] == "192.168.10.20"
		assert res["hardware-address"] == "24:79:2a:0a:13:c0"
		assert res["starts"] == 1549885390
		assert res["state"] == 2
		assert res["client-hostname"] == b"leasehost"  # not decoded in generic lookup
		omapi.close()


def test_lookup_by_lease_raw():
	packed = pack_ip("192.168.10.20")
	obj = [(b"ip-address", packed)]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		res = omapi.lookup_by_lease(ip="192.168.10.20", raw=True)
		assert res[b"ip-address"] == packed
		omapi.close()


def test_lookup_not_found():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_STATUS))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiErrorNotFound):
			omapi.lookup_by_lease(mac="00:11:22:33:44:55")
		omapi.close()


def test_lookup_ip_missing_attribute():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[]))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiErrorAttributeNotFound):
			omapi.lookup_ip("00:11:22:33:44:55")
		omapi.close()


# --- host creation / deletion ----------------------------------------------

def test_add_host_success():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE))) as srv:
		omapi = connect(srv.port)
		omapi.add_host("192.168.0.5", "00:11:22:33:44:55")  # no exception
		omapi.close()


def test_add_host_failure():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_STATUS))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.add_host("192.168.0.5", "00:11:22:33:44:55")
		omapi.close()


def test_add_host_variants():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE))) as srv:
		omapi = connect(srv.port)
		omapi.add_host_without_ip("00:11:22:33:44:55")
		omapi.add_host_supersede_name("192.168.0.6", "00:11:22:33:44:56", "h6")
		omapi.add_host_supersede("192.168.0.7", "00:11:22:33:44:57", "h7", hostname="h7", router="192.168.0.1", domain="example.org")
		omapi.add_group("grp", 'ddns-hostname "x";')
		omapi.add_host_with_group("192.168.0.8", "00:11:22:33:44:58", "grp")
		omapi.close()


def test_del_host_success():
	def responder(request):
		if request.opcode == OMAPI_OP_OPEN:
			return OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=42)
		assert request.opcode == OMAPI_OP_DELETE
		return OmapiMessage(opcode=OMAPI_OP_STATUS)

	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		omapi.del_host("00:11:22:33:44:55")  # no exception
		omapi.close()


def test_del_host_not_found():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_STATUS))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiErrorNotFound):
			omapi.del_host("00:11:22:33:44:55")
		omapi.close()


def test_del_host_invalid_handle():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=0))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.del_host("00:11:22:33:44:55")
		omapi.close()


def test_del_host_delete_failed():
	def responder(request):
		if request.opcode == OMAPI_OP_OPEN:
			return OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=42)
		return OmapiMessage(opcode=OMAPI_OP_UPDATE)  # not STATUS -> failure

	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.del_host("00:11:22:33:44:55")
		omapi.close()


def test_change_group_success():
	def responder(request):
		return OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=7)

	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		omapi.change_group("myhost", "mygroup")  # no exception
		omapi.close()


def test_change_group_open_fails():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_STATUS))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.change_group("myhost", "mygroup")
		omapi.close()


# --- failover-state ---------------------------------------------------------

def test_lookup_failoverstate():
	obj = [(b"partner-state", b"normal")]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_failoverstate("dhcp-failover", "partner-state") == b"normal"
		omapi.close()


# --- authentication ---------------------------------------------------------

def test_hmac_authentication_then_lookup():
	obj = [(b"ip-address", pack_ip("192.168.0.5"))]
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj)), user=b"user", key=KEY) as srv:
		omapi = connect(srv.port, username=b"user", key=KEY)
		# defauth switched away from the null authenticator during __init__.
		assert omapi.protocol.defauth == srv.authid
		assert omapi.lookup_ip("00:11:22:33:44:55") == "192.168.0.5"
		omapi.close()


# --- connection state -------------------------------------------------------

def test_send_after_close_raises():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE))) as srv:
		omapi = connect(srv.port)
		omapi.close()
		with pytest.raises(OmapiError):
			omapi.check_connected()
		with pytest.raises(OmapiError):
			omapi.send_message(OmapiMessage.open(b"host"))


def test_connection_closed_midstream():
	with FakeOmapiServer(const(None)) as srv:  # server hangs up without answering
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.lookup_ip("00:11:22:33:44:55")


def test_fill_inbuffer_after_close_raises():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE))) as srv:
		omapi = connect(srv.port)
		omapi.close()
		with pytest.raises(OmapiError):
			omapi.transport.fill_inbuffer()


# --- lookup attribute-missing branches --------------------------------------

@pytest.mark.parametrize("call", [
	lambda o: o.lookup_ip_host("00:11:22:33:44:55"),
	lambda o: o.lookup_mac("192.168.0.5"),
	lambda o: o.lookup_host("h"),
	lambda o: o.lookup_host_host("00:11:22:33:44:55"),
	lambda o: o.lookup_host_by_ip("10.0.0.1"),
	lambda o: o.lookup_hostname("10.0.0.1"),
])
def test_lookup_missing_attribute_variants(call):
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[]))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiErrorAttributeNotFound):
			call(omapi)
		omapi.close()


def test_lookup_failoverstate_missing_attribute():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[]))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiErrorAttributeNotFound):
			omapi.lookup_failoverstate("dhcp-failover", "partner-state")
		omapi.close()


# --- more creation failure branches -----------------------------------------

def test_lookup_generic_custom_attribute():
	# A kwarg that is not ip/mac/name exercises the generic encode branch.
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[]))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_by_lease(circuit_id="wifi") == {}
		omapi.close()


def test_lookup_keeps_undecodable_integer_as_bytes():
	# A malformed fixed-width field falls back to the raw bytes (struct.error).
	obj = [(b"starts", b"x")]  # not 4 bytes -> cannot unpack
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=obj))) as srv:
		omapi = connect(srv.port)
		assert omapi.lookup_by_lease(mac="00:11:22:33:44:55")["starts"] == b"x"
		omapi.close()


@pytest.mark.parametrize("call", [
	lambda o: o.add_host_supersede_name("192.168.0.6", "00:11:22:33:44:56", "h6"),
	lambda o: o.add_host_without_ip("00:11:22:33:44:56"),
	lambda o: o.add_host_supersede("192.168.0.7", "00:11:22:33:44:57", "h7"),
])
def test_creation_failure_variants(call):
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_STATUS))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			call(omapi)
		omapi.close()


def test_add_host_supersede_with_extra_statements():
	sent = []

	def responder(request):
		sent.append(request)
		return OmapiMessage(opcode=OMAPI_OP_UPDATE)

	routes = pypureomapi.encode_classless_static_routes([("10.0.0.0/8", "192.168.1.1")])
	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		omapi.add_host_supersede("192.168.0.7", "00:11:22:33:44:57", "h7",
				statements=f"supersede classless-static-routes = {routes};")
		omapi.close()
	stmts = dict(sent[-1].obj)[b"statements"]
	assert b"classless-static-routes = 08:0a:c0:a8:01:01;" in stmts


# --- graceful shutdown (issue #8) -------------------------------------------

def test_signal_shutdown_sets_control_state():
	sent = []

	def responder(request):
		sent.append(request)
		return OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=55)

	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		omapi.signal_shutdown()
		omapi.close()
	# first request opens the control object, second sets state = 2
	assert dict(sent[0].message)[b"type"] == b"control"
	assert dict(sent[-1].obj)[b"state"] == struct.pack("!I", 2)


def test_signal_shutdown_open_fails():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_STATUS))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.signal_shutdown()
		omapi.close()


def test_signal_shutdown_invalid_handle():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=0))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.signal_shutdown()
		omapi.close()


def test_signal_shutdown_state_update_rejected():
	state = {"n": 0}

	def responder(request):
		state["n"] += 1
		if state["n"] == 1:
			return OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=55)
		return OmapiMessage(opcode=OMAPI_OP_STATUS)  # state update rejected

	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.signal_shutdown()
		omapi.close()


def test_signal_shutdown_connection_drop_is_success():
	state = {"n": 0}

	def responder(request):
		state["n"] += 1
		if state["n"] == 1:
			return OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=55)
		return None  # server hangs up as it shuts down

	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		omapi.signal_shutdown()  # must not raise


def test_add_group_and_with_group_failures():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_STATUS))) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.add_group("grp", "stmts")
		with pytest.raises(OmapiError):
			omapi.add_host_with_group("192.168.0.8", "00:11:22:33:44:58", "grp")
		omapi.close()


def test_change_group_change_fails():
	def responder(request):
		if request.opcode == OMAPI_OP_OPEN:
			return OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=7)
		return OmapiMessage(opcode=OMAPI_OP_STATUS)  # update rejected

	with FakeOmapiServer(responder) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.change_group("myhost", "mygroup")
		omapi.close()


# --- authentication failure branches ----------------------------------------

def test_initialize_authenticator_non_update():
	bad = OmapiMessage(opcode=OMAPI_OP_STATUS)
	with FakeOmapiServer(const(None), user=b"user", key=KEY, auth_response=bad) as srv:
		with pytest.raises(OmapiError):
			pypureomapi.Omapi("127.0.0.1", srv.port, username=b"user", key=KEY, timeout=5)


def test_initialize_authenticator_zero_authid():
	bad = OmapiMessage(opcode=OMAPI_OP_UPDATE, handle=0)
	with FakeOmapiServer(const(None), user=b"user", key=KEY, auth_response=bad) as srv:
		with pytest.raises(OmapiError):
			pypureomapi.Omapi("127.0.0.1", srv.port, username=b"user", key=KEY, timeout=5)


def test_bad_signature_rejected():
	resp = OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[(b"ip-address", pack_ip("1.2.3.4"))])
	with FakeOmapiServer(const(resp), corrupt_sig=True) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.lookup_ip("00:11:22:33:44:55")


def test_response_not_matching_request():
	resp = OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[(b"ip-address", pack_ip("1.2.3.4"))])
	with FakeOmapiServer(const(resp), bad_rid=True) as srv:
		omapi = connect(srv.port)
		with pytest.raises(OmapiError):
			omapi.lookup_ip("00:11:22:33:44:55")


def test_response_signed_with_wrong_authenticator():
	# After HMAC negotiation, a reply under the null authenticator is a valid
	# signature but the wrong authenticator for this session.
	resp = OmapiMessage(opcode=OMAPI_OP_UPDATE, obj=[(b"ip-address", pack_ip("1.2.3.4"))])
	with FakeOmapiServer(const(resp), user=b"user", key=KEY, unsigned_response=True) as srv:
		omapi = connect(srv.port, username=b"user", key=KEY)
		with pytest.raises(OmapiError):
			omapi.lookup_ip("00:11:22:33:44:55")


def test_transport_write_after_close_raises():
	with FakeOmapiServer(const(OmapiMessage(opcode=OMAPI_OP_UPDATE))) as srv:
		omapi = connect(srv.port)
		omapi.close()
		with pytest.raises(OmapiError):
			omapi.transport.write(b"data")
