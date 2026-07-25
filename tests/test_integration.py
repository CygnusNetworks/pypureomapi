"""End-to-end integration tests against a *real* ISC DHCP server.

These are skipped unless OMAPI_TEST_HOST points at a running dhcpd with OMAPI
enabled. Configure via environment:

    OMAPI_TEST_HOST     dhcpd host (required to enable these tests)
    OMAPI_TEST_PORT     omapi port (default 7911)
    OMAPI_TEST_KEYNAME  omapi key name (optional; omit for unauthenticated)
    OMAPI_TEST_KEY      base64 HMAC-MD5 secret (optional)

The GitHub Actions "integration" job boots a throwaway isc-dhcp-server and sets
these automatically.
"""

import os

import pytest

import pypureomapi

HOST = os.environ.get("OMAPI_TEST_HOST")
PORT = int(os.environ.get("OMAPI_TEST_PORT", "7911"))
KEYNAME = os.environ.get("OMAPI_TEST_KEYNAME") or None
KEY = os.environ.get("OMAPI_TEST_KEY") or None

pytestmark = pytest.mark.skipif(
	not HOST,
	reason="set OMAPI_TEST_HOST to run integration tests against a real ISC DHCP server",
)

TEST_MAC = "00:16:3e:5a:6b:7c"
TEST_IP = "192.0.2.55"


@pytest.fixture
def omapi():
	username = KEYNAME.encode() if KEYNAME else None
	key = KEY.encode() if KEY else None
	conn = pypureomapi.Omapi(HOST, PORT, username, key, timeout=10)
	yield conn
	conn.close()


@pytest.fixture(autouse=True)
def _cleanup(omapi):
	"""Remove the test host before and after each test."""
	def drop():
		try:
			omapi.del_host(TEST_MAC)
		except pypureomapi.OmapiError:
			pass
	drop()
	yield
	drop()


def test_add_lookup_delete_host(omapi):
	omapi.add_host(TEST_IP, TEST_MAC)
	res = omapi.lookup_host_host(TEST_MAC)
	assert res["ip"] == TEST_IP
	assert res["mac"] == TEST_MAC
	omapi.del_host(TEST_MAC)
	with pytest.raises(pypureomapi.OmapiErrorNotFound):
		omapi.del_host(TEST_MAC)


def test_lookup_ip_host(omapi):
	omapi.add_host(TEST_IP, TEST_MAC)
	assert omapi.lookup_ip_host(TEST_MAC) == TEST_IP


def test_add_host_supersede_name(omapi):
	omapi.add_host_supersede_name(TEST_IP, TEST_MAC, "integration-host")
	res = omapi.lookup_host_host(TEST_MAC)
	assert res["name"] == "integration-host"


def test_add_host_without_ip(omapi):
	omapi.add_host_without_ip(TEST_MAC)
	# No name/ip set, so use the generic lookup instead of lookup_host_host.
	res = omapi.lookup_by_host(mac=TEST_MAC)
	assert res["hardware-address"] == TEST_MAC


def test_add_host_supersede_with_static_routes(omapi):
	# Requires the server to define: option ms-classless-static-routes code 249
	# = array of integer 8; (the CI job and the container harness both do).
	routes = pypureomapi.encode_classless_static_routes([("10.0.0.0/8", "192.0.2.1")])
	omapi.add_host_supersede(
		TEST_IP, TEST_MAC, "route-host",
		statements=f"supersede ms-classless-static-routes = {routes};",
	)
	assert omapi.lookup_host_host(TEST_MAC)["ip"] == TEST_IP


def test_delete_missing_host_raises(omapi):
	with pytest.raises(pypureomapi.OmapiErrorNotFound):
		omapi.del_host("00:16:3e:00:00:99")


# NOTE: keep this LAST — it shuts the test server down, so any test defined
# after it would fail to connect.
def test_signal_shutdown_stops_dhcpd(omapi):
	omapi.signal_shutdown()
	# The server must now be gone: a fresh connection should fail.
	with pytest.raises((pypureomapi.OmapiError, OSError)):
		pypureomapi.Omapi(HOST, PORT, KEYNAME.encode() if KEYNAME else None,
				KEY.encode() if KEY else None, timeout=5)
