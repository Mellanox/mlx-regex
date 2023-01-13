# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2020-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#

Name:           mlx-regex
Version:        1.2
Release:        1%{?dist}

License:        BSD
URL:            mellanox.com
Source0:        mlx-regex-1.2.tar.gz
Summary:        Userspace regex service for Nvidia Bluefield
BuildRequires:  gcc, cmake, make
BuildRequires:  systemd

%description
Regex database allocation service.

%prep
%setup -q
%build
mkdir -p build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ../
make %{?_smp_mflags}


%install
cd build
make install DESTDIR=%{buildroot}

%files
/usr/bin/mlx-regex
/etc/systemd/system/mlx-regex.service
/usr/sbin/mlx_regex_setup_hugepages.sh

%doc

%changelog

