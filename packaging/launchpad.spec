Name:       launchpad
Summary:    Launchpad for launching applications
Version:    0.2.3.14
Release:    1
Group:      Application Framework/Daemons
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source101:  launchpad-process-pool.service

BuildRequires:  cmake
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(libprivilege-control)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(gobject-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(deviced)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(elementary)
BuildRequires:  pkgconfig(eina)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  aul-devel

Requires: aul
Requires(post): /sbin/ldconfig
Requires(post): /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun): /usr/bin/systemctl

%define appfw_feature_process_pool 1
%if "%{?tizen_profile_name}" == "wearable"
%define appfw_feature_process_pool_common 1
%define appfw_feature_sw_rendering 1
%define appfw_feature_hw_rendering 1
%else
%if "%{?tizen_profile_name}" == "mobile"
%define appfw_feature_process_pool_common 1
%define appfw_feature_sw_rendering 1
%define appfw_feature_hw_rendering 1
%else
%if "%{?tizen_profile_name}" == "tv"
%define appfw_feature_process_pool_common 1
%define appfw_feature_sw_rendering 1
%define appfw_feature_hw_rendering 1
%else
%define appfw_feature_process_pool_common 1
%define appfw_feature_sw_rendering 1
%define appfw_feature_hw_rendering 1
%endif
%endif
%endif
%define appfw_feature_priority_change 0

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
%if 0%{?appfw_feature_process_pool}
_APPFW_FEATURE_PROCESS_POOL=ON
 %if 0%{?appfw_feature_process_pool_common}
  _APPFW_FEATURE_PROCESS_POOL_COMMON=ON
 %endif
 %if 0%{?appfw_feature_hw_rendering}
  _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING=ON
 %endif
 %if 0%{?appfw_feature_sw_rendering}
  _APPFW_FEATURE_PROCESS_POOL_SW_RENDERING=ON
 %endif
%endif
%if 0%{?appfw_feature_priority_change}
_APPFW_FEATURE_PRIORITY_CHANGE=ON
%endif

cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	-D_APPFW_FEATURE_PROCESS_POOL:BOOL=${_APPFW_FEATURE_PROCESS_POOL} \
	-D_APPFW_FEATURE_PROCESS_POOL_COMMON:BOOL=${_APPFW_FEATURE_PROCESS_POOL_COMMON} \
	-D_APPFW_FEATURE_PROCESS_POOL_SW_RENDERING:BOOL=${_APPFW_FEATURE_PROCESS_POOL_SW_RENDERING} \
	-D_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING:BOOL=${_APPFW_FEATURE_PROCESS_POOL_HW_RENDERING} \
	-D_APPFW_FEATURE_PRIORITY_CHANGE:BOOL=${_APPFW_FEATURE_PRIORITY_CHANGE}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%if 0%{?appfw_feature_process_pool}
%make_install
%endif

%if 0%{?appfw_feature_process_pool}
mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m0644 %SOURCE101 %{buildroot}%{_libdir}/systemd/system/launchpad-process-pool.service
ln -s ../launchpad-process-pool.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/launchpad-process-pool.service
%endif

mkdir -p %{buildroot}/usr/share/license
cp %{_builddir}/%{name}-%{version}/LICENSE  %{buildroot}/usr/share/license/%{name}

%post

%files
%manifest launchpad.manifest
%{_prefix}/share/license/%{name}
%if 0%{?appfw_feature_process_pool}
%attr(0700,root,root) %{_bindir}/launchpad-process-pool
%attr(0700,root,root) %{_bindir}/launchpad-loader
%{_prefix}/share/aul/preload_list.txt
%{_prefix}/share/aul/launchpad-process-pool-preload-list.txt
%{_libdir}/systemd/system/launchpad-process-pool.service
%{_libdir}/systemd/system/multi-user.target.wants/launchpad-process-pool.service
%endif
