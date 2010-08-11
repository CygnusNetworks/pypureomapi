#!/usr/bin/python

import distutils.core

distutils.core.setup(name='pypureomapi',
	version='0.0.1',
	description="ISC DHCP OMAPI protocol implementation in Python",
	long_description="This module grew out of frustration about pyomapi and later pyomapic. The extension modules mentioned can be used to query the ISC DHCP server for information about leases. pyomapic does this job using swig and the static library provided with ISC DHCP. It leaks and has basically no error checking. Adding error checking later turned out to be a maintenance hell with swig, so a pure python implementation for omapi, pypureomapi was born. It can mostly be used as a drop-in replacement for pyomapic.",
	author='Helmut Grohne',
	author_email='h.grohne@cygnusnetworks.de',
	maintainer='Torge Szczepanek',
	maintainer_email='info@cygnusnetworks.de',
	license='GPL',
	url='http://code.google.com/p/pypureomapi/',
	py_modules=['pypureomapi'],
	classifiers=[
		"Development Status :: 3 - Alpha",
		"Intended Audience :: System Administrators",
		"License :: OSI Approved :: GNU General Public License (GPL)",
		"Programming Language :: Python",
		"Topic :: Internet",
		"Topic :: System :: Networking",
		]
	)

