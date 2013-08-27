#!/usr/bin/python
#
# library for communicating with an isc dhcp server over the omapi protocol
#
# Copyright (C) 2010-2013 Cygnus Networks GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import distutils.core

distutils.core.setup(name='pypureomapi',
	version='0.3',
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
		"Development Status :: 5 - Production/Stable",
		"Intended Audience :: System Administrators",
		"License :: OSI Approved :: GNU General Public License (GPL)",
		"Programming Language :: Python",
		"Topic :: Internet",
		"Topic :: System :: Networking",
		]
	)

