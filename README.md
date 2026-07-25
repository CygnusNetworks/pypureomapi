[![Codacy Badge](https://api.codacy.com/project/badge/Grade/eeca983d807b472fa8539506de47ffa6)](https://app.codacy.com/gh/CygnusNetworks/pypureomapi?utm_source=github.com&utm_medium=referral&utm_content=CygnusNetworks/pypureomapi&utm_campaign=Badge_Grade_Dashboard)
[![CI](https://github.com/CygnusNetworks/pypureomapi/actions/workflows/ci.yml/badge.svg)](https://github.com/CygnusNetworks/pypureomapi/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/CygnusNetworks/pypureomapi/branch/master/graph/badge.svg)](https://codecov.io/gh/CygnusNetworks/pypureomapi)
[![Latest Version](https://img.shields.io/pypi/v/pypureomapi.svg)](https://pypi.python.org/pypi/pypureomapi)
[![PyPi Status](https://img.shields.io/pypi/status/pypureomapi.svg)](https://pypi.python.org/pypi/pypureomapi) [![PyPi Versions](https://img.shields.io/pypi/pyversions/pypureomapi.svg)](https://pypi.python.org/pypi/pypureomapi)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.md)

pypureomapi
===========

pypureomapi is a Python implementation of the DHCP OMAPI protocol used in the most popular Linux DHCP server from ISC. 
It can be used to query and modify leases and other objects exported by an ISC DHCP server. 
The interaction can be authenticated using HMAC-MD5. Besides basic ready to use operations, custom interaction can be implemented with limited effort. 
It provides error checking and extensibility.

## Installation

pypureomapi requires Python 3.11 or newer and has no runtime dependencies.

From PyPI:

```
pip install pypureomapi
```

Distribution packages are built automatically for every
[GitHub release](https://github.com/CygnusNetworks/pypureomapi/releases) and
attached as assets:

  * `.deb` for Debian 12, Debian 13 and Ubuntu 24.04
  * `.rpm` for Fedora and Enterprise Linux 9 (Rocky/Alma)

On Enterprise Linux 9 the default `python3` (3.9) is too old, so the package is
built against `python3.12` and is named `python3.12-pypureomapi`.

## Server side configugration for ISC DHCP3

To allow a OMAPI access to your ISC DHCP3 DHCP Server you should define the following in your dhcpd.conf config file:

```
key defomapi {
	algorithm hmac-md5;
	secret +bFQtBCta6j2vWkjPkNFtgA==; # FIXME: replace by your own dnssec key (see below)!!!
};

omapi-key defomapi;
omapi-port 7911;
```

Replace the given secret by a key created on your own!

To generate a key use the following command:

```
/usr/sbin/dnssec-keygen -a HMAC-MD5 -b 128 -n USER defomapi
```

which will create two files containing a HMAC MD5 key. Alternatively, it
is possible to generate the key value for the config file directly:

```
dd if=/dev/urandom bs=16 count=1 2>/dev/null | openssl enc -e -base64
```

## Example omapi lookup

This is a short example, of how to use basic lookup functions **lookup_mac** and **lookup_ip** to quickly query a DHCP lease on a ISC DHCP Server.

```python
import pypureomapi

KEYNAME = b"defomapi"
BASE64_ENCODED_KEY = b"+bFQtBCta6j2vWkjPkNFtgA=="  # FIXME: be sure to replace this by your own key!!!

dhcp_server_ip = "127.0.0.1"
port = 7911  # Port of the omapi service

omapi = pypureomapi.Omapi(dhcp_server_ip, port, KEYNAME, BASE64_ENCODED_KEY)
mac = omapi.lookup_mac("192.168.0.250")
print(f"192.168.0.250 is currently assigned to mac {mac}")

ip = omapi.lookup_ip(mac)
print(f"{mac} mac currently has ip {ip} assigned")
```

pypureomapi requires Python 3.11 or newer.

If you need full lease information, you can also query the full lease directly by using **lookup_by_lease**, which gives you the full lease details as output:

```
lease = omapi.lookup_by_lease(mac="24:79:2a:0a:13:c0")
for k, v in lease.items():
	print("%s: %s" % (k, v))
```

Output:
```
state: 2
ip-address: 192.168.10.167
dhcp-client-identifier: b'\x01$y*\x06U\xc0'
subnet: 6126
pool: 6127
hardware-address: 24:79:2a:0a:13:c0
hardware-type: 1
ends: 1549885690
starts: 1549885390
tstp: 1549885840
tsfp: 1549885840
atsfp: 1549885840
cltt: 1549885390
flags: 0
clientip: b'192.168.10.167'
clientmac: b'24:79:2a:0a:13:c0'
clientmac_hostname: b'24792a0a13c0'
vendor-class-identifier: b'Ruckus CPE'
agent.circuit-id: b'\x00\x04\x00\x12\x00-'
agent.remote-id: b'\x00\x06\x00\x12\xf2\x8e!\x00'
agent.subscriber-id: b'wifi-basement'
```

To check if a lease is still valid, you should check ends and state:

```
if lease["ends"] < time.time() or lease["state"] != 2:
    print("Lease is not valid")
```

Most attributes will be decoded directly into the corresponding human readable values. 
Converted attributes are ip-address, hardware-address and all 32 bit and 8 bit integer values. If you need raw values, you can add a raw option to the lookup:

```
lease = omapi.lookup_by_lease(mac="24:79:2a:0a:13:c0", raw=True)
for k, v in res.items():
	print("%s: %s" % (k, v))
```

Output:

```
b'state': b'\x00\x00\x00\x02'
b'ip-address': b'\xc0\xa8\n\xa7'
...
```

The following lookup functions are implemented, allowing directly querying the different types:

  * lookup_ip_host(mac) - lookups up a host object (static defined host) by mac
  * lookup_ip(mac) - lookups a lease object by mac and returns the ip
  * lookup_host(name) - lookups a host object by name and returns the ip, mac and hostname
  * lookup_host_host(mac) - lookups a host object by mac and returns the ip, mac and name
  * lookup_hostname(ip) - lookups a lease object by ip and returns the client-hostname
  
These special functions use:

  * lookup_by_host - generic lookup function for host objects 
  * lookup_by_lease - generic lookup function for lease objects
  
which provide full access to complete lease data. 

## Add and delete host objects

For adding and deleting host objects (static DHCP leases), there are multiple functions:

  * add_host(ip, mac)
  * add_host_supersede_name(ip, mac, name)
  * add_host_without_ip(mac)
  * add_host_supersede(ip, mac, name, hostname=None, router=None, domain=None, statements=None)
  * add_group(groupname, statements)
  * add_host_with_group(ip, mac, groupname))

See http://jpmens.net/2011/07/20/dynamically-add-static-leases-to-dhcpd/ for original idea (which is now merged) and detailed explanation.

### Classless static routes

`add_host_supersede` accepts an optional `statements` argument with additional raw
ISC DHCP statements. Together with the helper `encode_classless_static_routes`
you can push classless static routes (RFC 3442, or the Microsoft option 249
`ms-classless-static-routes`). The helper turns `(destination_cidr, gateway)`
pairs into the colon-hex byte string dhcpd expects:

```python
routes = pypureomapi.encode_classless_static_routes([
    ("10.0.0.0/8", "192.168.1.1"),
    ("0.0.0.0/0", "192.168.1.254"),
])
# routes == "08:0a:c0:a8:01:01:00:c0:a8:01:fe"

omapi.add_host_supersede(
    "192.168.1.50", "00:11:22:33:44:55", "myhost",
    statements=f"supersede ms-classless-static-routes = {routes};",
)
```

The relevant option must be defined in your `dhcpd.conf`, e.g.
`option ms-classless-static-routes code 249 = array of integer 8;`.

## Shutting down the server

`signal_shutdown()` gracefully stops the DHCP server via the OMAPI `control`
object (equivalent to `omshell`'s `new control; open; set state = 2; update`).
Create the connection with a `timeout`, since dhcpd shuts down without sending a
final response:

```python
omapi = pypureomapi.Omapi(dhcp_server_ip, port, KEYNAME, BASE64_ENCODED_KEY, timeout=10)
omapi.signal_shutdown()
```

# Custom Integration

Assuming there already is a connection named `o` (i.e. a `Omapi` instance, see [Example]).
To craft your own communication with the server you need to create an `OmapiMessage`, send it, receive a response and evaluate that response being an `OmapiMessage` as well. So here we go and create our first message.
```python
m1 = OmapiMessage.open(b"host")
```
We are using a named constructor (`OmapiMessage.open`). It fills in the opcode (as `OMAPI_OP_OPEN`), generates a random transaction id, and uses the parameter for the type field. This is the thing you want almost all the time. In this case we are going to open a host object, but we did not specify which host to open. For example we can select a host by its name.
```python
m1.update_object({b"name": b"foo"})
```
The next step is to interact with the DHCP server. The easiest way to do so is using the `query_server` method. It takes an `OmapiMessage`and returns another.
```
r1 = o.query_server(m1)
```
The returned `OmapiMessage` contains the parsed response from the server. Since opening can fail, we need to check the `opcode` attribute. In case of success its value is `OMAPI_OP_UPDATE`. As with files on unix we now have a descriptor called `r1.handle`. So now we are to modify some attribute about this host. Say we want to set its group. To do so we construct a new message and reference the opened host object via its handle.
```python
m2 = OmapiMessage.update(r1.handle)
```
Again `OmapiMessage.update` is a named constructor. It fills in the opcode (as `OMAPI_OP_UPDATE`), generates a random transaction id and fills in the handle. So now we need to add the actual modification to the message and send the message to the server.
```python
m2.update_object({b"group": b"bar"})
r2 = o.query_server(m2)
```
We receive a new message and need to check the returned `opcode` which should be `OMAPI_OP_UPDATE` again. Now we have a complete sequence.

As can be seen, the OMAPI protocol permits flexible interaction and it would be unreasonable to include every possibility as library functions. Instead you are encouraged to subclass the `Omapi` class and define your own methods. If they prove useful in multiple locations, please submit them to the issue tracker.

# Development and packaging

Run the test suite (unit tests plus the doctests embedded in the module):

```
pip install -e .[test]
pytest
```

Building the distribution artifacts:

```
# Python sdist + wheel
python -m build

# Debian package (on Debian/Ubuntu, in a checkout)
dpkg-buildpackage -us -uc -b

# RPM (on Fedora; on EL9 add: -D "python3_pkgversion 3.12")
python -m build --sdist
cp dist/pypureomapi-*.tar.gz ~/rpmbuild/SOURCES/
rpmbuild -ba pypureomapi.spec
```

The version is single-sourced from the git tag on release:
`packaging/set-version.sh <version>` stamps it into `pyproject.toml`, the
module, the RPM spec and `debian/changelog`. Releasing is automated — publishing
a GitHub release triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which uploads the sdist and wheel to PyPI and attaches the `.deb`/`.rpm` packages
to the release.
