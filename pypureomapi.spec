%define srcname pypureomapi
%define version 1.0
%define release 1
%define sum Cygnus Networks GmbH %{srcname} package

Name:           python-%{srcname}
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        %{sum}
License:        Apache-2.0
Source0:        python-%{srcname}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel python3-setuptools python3-pip
%if 0%{?with_check}
BuildRequires:  python3-pytest
%endif # with_check

%package -n python3-%{srcname}
Summary:        %{sum}
Requires:       python3-setuptools

%description
%{sum}

%description -n python3-%{srcname}
%{sum}

%prep
%setup -q -n python-%{srcname}-%{version}

%build
%py3_build

%install
%py3_install

%if 0%{?with_check}
%check
LANG=en_US.utf8 py.test-%{python3_version} -vv tests
%endif # with_check

%files -n python3-%{srcname}
%license LICENSE.md
%{python3_sitelib}/%{srcname}.py*
%{python3_sitelib}/%{srcname}-%{version}*.egg-info
%{python3_sitelib}/__pycache__/%{srcname}*.py*
