pypureomapi
===========

pypureomapi is a Python implementation of the DHCP OMAPI protocol used in the most popular Linux DHCP server from ISC. It can be used to query and modify leases and other objects exported by an ISC DHCP server. The interaction can be authenticated using HMAC-MD5. Besides basic ready to use operations, custom interaction can be implemented with limited effort. It can be used as a drop-in replacement for pyomapic, but provides error checking and extensibility beyond pyomapic.

#Example omapi lookup

```
import pypureomapi

KEYNAME="defomapi"
BASE64_ENCODED_KEY="+bFQtBCta6j2vWkjPkNFtgA=="

lease_ip = "192.168.0.250" # ip of some host with a dhcp lease on your dhcp server
dhcp_server_ip="127.0.0.1"
port = 7911 # Port of the omapi service

try:
    o = pypureomapi.Omapi(dhcp_server_ip,port, KEYNAME, BASE64_ENCODED_KEY)
    mac = o.lookup_mac(lease_ip)
    print "%s is currently assigned to mac %s" % (lease_ip, mac)
except pypureomapi.OmapiErrorNotFound:
    print "%s is currently not assigned" % (lease_ip,)
except pypureomapi.OmapiError, err:
    print "an error occured: %r" % (err,)
```

#Server side configugration for ISC DHCP3

To allow a OMAPI access to your ISC DHCP3 DHCP Server you should define the following in your dhcpd.conf config file:

```
key defomapi {
	algorithm hmac-md5;
	secret +bFQtBCta6j2vWkjPkNFtgA==;
};

omapi-key defomapi;
omapi-port 7911;
```

Replace the given secret by a key created on your own!

To generate a key use the following command:

```
/usr/sbin/dnssec-keygen -a HMAC-MD5 -b 128 -n USER defomapi
```

which will create two files containing a HMAC MD5 key. 

#UseCaseCreateGroup

A group needs at least one statement. See issue #9 for background. See UseCaseSupersedeHostname for example statements.
```
def add_group(omapi, groupname, statements):
    """
    @type omapi: Omapi
    @type groupname: bytes
    @type statements: str
    """
    msg = OmapiMessage.open("group")
    msg.message.append(("create", struct.pack("!I", 1)))
    msg.obj.append(("name", groupname))
    msg.obj.append(("statements", statements))
    response = self.query_server(msg)
    if response.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("add group failed")
```

And with that, to attach a new host to a group:
```
def add_host_with_group(omapi, ip, mac, groupname):
    msg = OmapiMessage.open("host")
    msg.message.append(("create", struct.pack("!I", 1)))
    msg.message.append(("exclusive", struct.pack("!I", 1)))
    msg.obj.append(("hardware-address", pack_mac(mac)))
    msg.obj.append(("hardware-type", struct.pack("!I", 1)))
    msg.obj.append(("ip-address", pack_ip(ip)))
    msg.obj.append(("group", groupname))
    response = omapi.query_server(msg)
    if response.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("add failed")
```

#UseCaseSupersedeHostname

See http://jpmens.net/2011/07/20/dynamically-add-static-leases-to-dhcpd/ for the original idea.

```
def add_host_supersede_name(omapi, ip, mac, name):
    """Add a host with a fixed-address and override its hostname with the given name.
    @type omapi: Omapi
    @type ip: str
    @type mac: str
    @type name: str
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
    msg.obj.append(("name", name))
    msg.obj.append(("statement", "supersede host-name %s;" % name))
    response = omapi.query_server(msg)
    if response.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("add failed")

```

Similarly the router can be superseded. 

#UseCaseGetLease

Original idea from Josh West.

```
def get_lease(omapi, ip):
    """
    @type omapi: Omapi
    @type ip: str
    @rtype: OmapiMessage
    @raises OmapiErrorNotFound:
    @raises socket.error:
    """
    msg = OmapiMessage.open("lease")
    msg.obj.append(("ip-address", pack_ip(ip)))
    response = omapi.query_server(msg)
    if response.opcode != OMAPI_OP_UPDATE:
        raise OmapiErrorNotFound()
    return response
```

#UseCaseChangeGroup

```
def change_group(omapi, name, group):
    """Change the group of a host given the name of the host.
    @type omapi: Omapi
    @type name: str
    @type group: str
    """
    m1 = OmapiMessage.open("host")
    m1.update_object(dict(name=name))
    r1 = omapi.query_server(m1)
    if r1.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("opening host %s failed" % name)
    m2 = OmapiMessage.update(r.handle)
    m2.update_object(dict(group=group))
    r2 = omapi.query_server(m2)
    if r2.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("changing group of host %s to %s failed" % (name, group))
```

#CustomIntegration
#summary Advanced use case

Assuming there already is a connection named `o` (i.e. a `Omapi` instance, see [Example]).
To craft your own communication with the server you need to create an `OmapiMessage`, send it, receive a response and evaluate that response being an `OmapiMessage` as well. So here we go and create our first message.
```
m1 = OmapiMessage.open("host")
```
We are using a named constructor (`OmapiMessage.open`). It fills in the opcode (as `OMAPI_OP_OPEN`), generates a random transaction id, and uses the parameter for the type field. This is the thing you want almost all the time. In this case we are going to open a host object, but we did not specify which host to open. For example we can select a host by its name.
```
m1.update_object(dict(name="foo"))
```
The next step is to interact with the DHCP server. The easiest way to do so is using the `query_server` method. It takes an `OmapiMessage`and returns another.
```
r1 = o.query_server(m1)
```
The returned `OmapiMessage` contains the parsed response from the server. Since opening can fail, we need to check the `opcode` attribute. In case of success its value is `OMAPI_OP_UPDATE`. As with files on unix we now have a descriptor called `r1.handle`. So now we are to modify some attribute about this host. Say we want to set its group. To do so we construct a new message and reference the opened host object via its handle.
```
m2 = OmapiMessage.update(r1.handle)
```
Again `OmapiMessage.update` is a named constructor. It fills in the opcode (as `OMAPI_OP_UPDATE`), generates a random transaction id and fills in the handle. So now we need to add the actual modification to the message and send the message to the server.
```
m2.update_object(dict(group="bar"))
r2 = o.query_server(m2)
```
We receive a new message and need to check the returned `opcode` which should be `OMAPI_OP_UPDATE` again. Now we have a complete sequence.

As can be seen, the OMAPI protocol permits flexible interaction and it would be unreasonable to include every possibility as library functions. Instead you are encouraged to subclass the `Omapi` class and define your own methods. If they prove useful in multiple locations, please submit them to the issue tracker.
