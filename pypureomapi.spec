%define srcname pypureomapi
%define version 1.1
%define release 1

Name:           python-%{srcname}
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        ISC DHCP OMAPI protocol implementation in Python
License:        Apache-2.0
URL:            https://github.com/CygnusNetworks/pypureomapi
Source0:        %{srcname}-%{version}.tar.gz

BuildArch:      noarch

# python3_pkgversion defaults to 3 (Fedora); override to e.g. 3.12 on EL9,
# where the default python3 (3.9) does not satisfy requires-python >= 3.11.
BuildRequires:  python%{python3_pkgversion}-devel
BuildRequires:  pyproject-rpm-macros

%global source_date_epoch_from_changelog 0

%global _description %{expand:
pypureomapi is a pure-Python implementation of the ISC DHCP OMAPI protocol.
It can be used to query and modify leases and other objects exported by an
ISC DHCP server, with HMAC-MD5 authenticated interaction.}

%description %_description

%package -n python%{python3_pkgversion}-%{srcname}
Summary:        %{summary}
%description -n python%{python3_pkgversion}-%{srcname} %_description

%prep
%autosetup -n %{srcname}-%{version}

%generate_buildrequires
%pyproject_buildrequires -x test

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files pypureomapi

%check
%pytest

%files -n python%{python3_pkgversion}-%{srcname} -f %{pyproject_files}
%license LICENSE.md
%doc README.md
