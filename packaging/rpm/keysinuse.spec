%define      debug_package %{nil}

Name:        PACKAGE
Version:     VERSION
Release:     LABEL
Summary:     KeysInUse solution for OpenSSL

Group:       Productivity/Security
License:     Apache
URL:         www.microsoft.com
Source0:     %{name}-%{version}.tgz
BuildRoot:   %{_tmppath}/%{name}-%{version}-%{release}-buildroot

Requires:    openssl >= 1.1.1, openssl < 1.1.2

%description
KeysInUse engine for OpenSSL logs private key usage locally

%define _rpmdir PKG-DIR
%define _build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm

%prep
%setup -q

%build
# Empty section

%install
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/usr/share/doc/keysinuse/ChangeLog
/usr/lib/keysinuse/keysinuseutil
/usr/lib/keysinuse/keysinuse.so

%changelog

%pre
PRE-INSTALL

%post
POST-INSTALL

%preun
PRE-UNINSTALL
