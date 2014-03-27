pypureomapi
===========

pypureomapi is a Python implementation of the DHCP OMAPI protocol used in the most popular Linux DHCP server from ISC. It can be used to query and modify leases and other objects exported by an ISC DHCP server. The interaction can be authenticated using HMAC-MD5. Besides basic ready to use operations, custom interaction can be implemented with limited effort. It can be used as a drop-in replacement for pyomapic, but provides error checking and extensibility beyond pyomapic.

#summary example for using pypureomapi

= Example omapi lookup =

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

= Server side configugration for ISC DHCP3 =

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
