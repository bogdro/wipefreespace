# Special names here like %{__make} come from /usr/lib/rpm/macros

%define version 0.6

Summary:	Program for secure cleaning of free space.
Name:		wipefreespace
Version:	%{version}
Release:	1
URL:		http://rudy.mif.pg.gda.pl/~bogdro/soft/
License:	GPL
Group:		System Utilities
Packager:	Bogdan Drozdowski <bogdandr@op.pl>
Prefix:		/usr/local
Source:		wipefreespace-%{version}.tar.gz
BuildRoot:	%{_tmppath}/wipefreespace-build
BuildRequires:	gcc, glibc, glibc-devel, glibc-headers, make
#, e2fsprogs-devel

#Requires:	e2fsprogs
Obsoletes:	e2wipefreespace

%description

The wipefreespace is a program which securely cleans free space on given
filesystems, making confidential removed data recovery impossible. It also
removes deleted files' names, so that no trace is left. Supported filesystems
are: ext2/3 and NTFS.

%prep
%{__rm} -rf $RPM_BUILD_ROOT
%setup -q

%build

./configure --prefix=/usr/local
	#--mandir=$RPM_BUILD_ROOT/usr/local/man
#prefix=$RPM_BUILD_ROOT/usr/local
%{__make}

%install

mkdir -p $RPM_BUILD_ROOT/usr/share/info
#prefix=$RPM_BUILD_ROOT/usr/local
%{__make} DESTDIR="$RPM_BUILD_ROOT" install-strip
%{__rm} -f $RPM_BUILD_ROOT/usr/bin/wipefreespace*
%{__rm} -f $RPM_BUILD_ROOT/usr/local/info/wipefreespace.info*
%{__rm} -f $RPM_BUILD_ROOT/usr/local/man/man1/wipefreespace.1*
%{__rm} -f $RPM_BUILD_ROOT/usr/local/share/info/wipefreespace.info*
%{__rm} -f $RPM_BUILD_ROOT/usr/local/share/man/man1/wipefreespace.1*
%{__rm} -f $RPM_BUILD_ROOT/usr/share/locale/pl/LC_MESSAGES/wipefreespace.mo
#%{__mv} -f $RPM_BUILD_ROOT/usr/bin/wipefreespace $RPM_BUILD_ROOT/usr/local/bin/wipefreespace
#%{makeinstall}

%clean

%{__rm} -rf $RPM_BUILD_ROOT

%define _unpackaged_files_terminate_build 0
%files

%defattr(-,root,root)
/usr/local/bin/wipefreespace
%doc /usr/share/info/wipefreespace.info.gz
%doc /usr/share/man/man1/wipefreespace.1.gz
/usr/local/share/locale/pl/LC_MESSAGES/wipefreespace.mo
