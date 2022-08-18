%define version 0.5

Summary:	Program for secure cleaning of free space.
Name:		e2wipefreespace
Version:	%{version}
Release:	1
URL:		http://rudy.mif.pg.gda.pl/~bogdro/soft/
License:	GPL
Group:		System Utilities
Prefix:		/usr/local
Source:		e2wipefreespace-%{version}.tar.gz
BuildRoot:	/tmp/wipefreespace-build
BuildRequires:	gcc, glibc, glibc-devel, glibc-headers, make, e2fsprogs-devel

#Requires:	e2fsprogs
#Provides:	e2wipefreespace

%description

The e2wipefreespace is a program, wich securely cleans free space on given ext2/3
partitions, making confidential removed data recovery impossible. It also
removes deleted files' names, so that no trace is left.

%prep
rm -rf $RPM_BUILD_ROOT
%setup -q

%build

#./configure --prefix=$RPM_BUILD_ROOT/usr/local #--mandir=$RPM_BUILD_ROOT/usr/local/man
PREFIX=$RPM_BUILD_ROOT/usr/local CFLAGS="-march=i386" make

%install

PREFIX=$RPM_BUILD_ROOT/usr/local CFLAGS="-march=i386" make install

%clean

rm -rf $RPM_BUILD_ROOT

#%uninstall

#/sbin/install-info --delete /usr/local/share/info/e2wipefreespace.info.gz /usr/local/share/info/dir

%files

%defattr(-,root,root)
/usr/local/bin/e2wipefreespace
%doc /usr/local/share/info/e2wipefreespace.info.gz
/usr/local/share/locale/pl/e2wipefreespace.mo

