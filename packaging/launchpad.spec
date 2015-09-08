Name:       launchpad
Summary:    Launchpad for launching applications
Version:    0.0.20
Release:    1
Group:      Application Framework/Daemons
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  launchpad-process-pool.service
Source102:  launchpad-native.service

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(ail)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(deviced)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(eina)
BuildRequires:  aul-devel

Requires: aul
Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

%define feature_appfw_process_pool 1

%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_process_pool_common 1
%define appfw_feature_hw_rendering 0
%elseif "%{?tizen_profile_name}" == "mobile"
%define appfw_feature_process_pool_common 0
%define appfw_feature_hw_rendering 1
%endif
%define appfw_feature_priority_change 1
%define appfw_feature_native_launchpad 0

%description
Launchpad for launching applications

%package devel
Summary:    Launchpad for launching applications (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Launchpad for launching applications (devel)

%prep
%setup -q

%build
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif
%if 0%{?feature_appfw_process_pool}
_APPFW_FEATURE_PROCESS_POOL=ON
 %if 0%{?appfw_feature_process_pool_common}
 _APPFW_FEATURE_PROCESS_POOL_COMMON=ON
 %else
  %if 0%{?appfw_feature_hw_rendering}
  _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING=ON
  %endif
 %endif
%endif
%if 0%{?appfw_feature_priority_change}
_APPFW_FEATURE_PRIORITY_CHANGE=ON
%endif
%if 0%{?appfw_feature_native_launchpad}
_APPFW_FEATURE_NATIVE_LAUNCHPAD=ON
%endif

cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-D_APPFW_FEATURE_PROCESS_POOL:BOOL=${_APPFW_FEATURE_PROCESS_POOL} \
	-D_APPFW_FEATURE_PROCESS_POOL_COMMON:BOOL=${_APPFW_FEATURE_PROCESS_POOL_COMMON} \
	-D_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING:BOOL=${_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING} \
	-D_APPFW_FEATURE_PRIORITY_CHANGE:BOOL=${_APPFW_FEATURE_PRIORITY_CHANGE} \
	-D_APPFW_FEATURE_NATIVE_LAUNCHPAD:BOOL=${_APPFW_FEATURE_NATIVE_LAUNCHPAD}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%if 0%{?feature_appfw_process_pool} || 0%{?appfw_feature_native_launchpad}
%make_install
%endif

%if 0%{?feature_appfw_process_pool}
mkdir -p %{buildroot}%{_libdir}/systemd/system/graphical.target.wants
install -m0644 %SOURCE101 %{buildroot}%{_libdir}/systemd/system/launchpad-process-pool.service
ln -s ../launchpad-process-pool.service %{buildroot}%{_libdir}/systemd/system/graphical.target.wants/launchpad-process-pool.service
%endif

%if 0%{?appfw_feature_native_launchpad}
mkdir -p %{buildroot}%{_libdir}/systemd/system/graphical.target.wants
install -m0644 %SOURCE102 %{buildroot}%{_libdir}/systemd/system/launchpad-native.service
ln -s ../launchpad-native.service %{buildroot}%{_libdir}/systemd/system/graphical.target.wants/launchpad-native.service
%endif

mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{name}-%{version}/LICENSE  %{buildroot}/usr/share/license/%{name}

%post

%files
%manifest launchpad.manifest
%{_prefix}/share/license/%{name}
%if 0%{?feature_appfw_process_pool}
%{_bindir}/launchpad-process-pool
%{_prefix}/share/aul/launchpad-process-pool-preload-list.txt
%{_libdir}/systemd/system/launchpad-process-pool.service
%{_libdir}/systemd/system/graphical.target.wants/launchpad-process-pool.service
%endif
%if 0%{?appfw_feature_native_launchpad}
%{_bindir}/launchpad-native
%{_prefix}/share/aul/launchpad-native-preload-list.txt
%{_libdir}/systemd/system/launchpad-native.service
%{_libdir}/systemd/system/graphical.target.wants/launchpad-native.service
%endif
