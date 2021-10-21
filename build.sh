#!/usr/bin/env bash

if ! type -p pkg-config >/dev/null; then
	echo "You need to have pkgconfig installed"
	exit 1
fi

if ! version_release=$(pkg-config --variable VERSION_RELEASE wireshark); then
	echo "You should install the 'wireshark-devel' package or similar"
	exit 1
fi

if [[ -z $version_release ]]; then
	echo "You have a buggy version of wireshark-devel which does not define the VERSION_RELEASE variable"
	if type -p rpm >/dev/null; then
		version_release="VERSION_RELEASE=$(rpm -q wireshark-devel --qf %{VERSION} | cut -d. -f1-2)"
		echo "Trying to work around it by assuming ${version_release}"
	else
		echo "The compiled plugin will most likely refuse to be loaded by wireshark, but buildig it anyway"
	fi
else
	version_release=
fi

set -ex

autoreconf -v -i
./configure
make $version_release
set +x
echo
echo "To install, run the following:"
echo
echo "make ${version_release} install-home"
# make install-home
