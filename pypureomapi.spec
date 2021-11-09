%if 0%{?rhel} && 0%{?rhel} <= 7
%{!?py2_build: %global py2_build %{__python2} setup.py build}
%{!?py2_install: %global py2_install %{__python2} setup.py install --skip-build --root %{buildroot}}
%endif

%if (0%{?fedora} >= 21 || 0%{?rhel} >= 8)
%global with_python3 1
%else
%global with_python2 1
%endif

%define srcname pypureomapi
%define version 0.8
%define release 2
%define sum Cygnus Networks GmbH %{srcname} package

Name:           python-%{srcname}
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        %{sum}
License:        proprietary
Source0:        python-%{srcname}-%{version}.tar.gz

BuildArch:      noarch


%if 0%{?with_python2}
BuildRequires:  python-setuptools python2-devel

%if 0%{?with_check}
BuildRequires:  pytest
%endif # with_check


%endif # with_python2


%if 0%{?with_python3}
BuildRequires:  python3-setuptools python3-devel
%if 0%{?with_check}
BuildRequires:  python3-pytest
%endif # with_check

%package -n python3-%{srcname}
Summary:        %{sum}
Requires:       python3-setuptools

%endif # with_python3

%description
%{sum}

%if 0%{?with_python3}
%description -n python3-%{srcname}
%{sum}
%endif

%prep
%setup -q -n python-%{srcname}-%{version}

%build

%if 0%{?with_python2}
%py2_build
%endif # with_python2
%if 0%{?with_python3}
%py3_build
%endif # with_python3


%install
%if 0%{?with_python2}
%py2_install
%endif # with_python2
%if 0%{?with_python3}
%py3_install
%endif # with_python3

%if 0%{?with_check}
%check
%if 0%{?with_python2}
LANG=en_US.utf8 py.test-%{python2_version} -vv tests
%endif # with_python2
%if 0%{?with_python3}
LANG=en_US.utf8 py.test-%{python3_version} -vv tests
%endif # with_python3
%endif # with_check

%if 0%{?with_python2}
%files
%{python2_sitelib}/%{srcname}.py*
%{python2_sitelib}/%{srcname}-%{version}-py2.*.egg-info
%endif # with_python2

%if 0%{?with_python3}
%files -n python3-%{srcname}
%{python3_sitelib}/%{srcname}.py*
%{python3_sitelib}/%{srcname}-%{version}-py3.*.egg-info
%{python3_sitelib}/__pycache__/%{srcname}*.py*
%endif # with_python3
