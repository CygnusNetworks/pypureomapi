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


def test_delete_missing_host_raises(omapi):
	with pytest.raises(pypureomapi.OmapiErrorNotFound):
		omapi.del_host("00:16:3e:00:00:99")
