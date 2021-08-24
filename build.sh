#!/usr/bin/env bash

if ! type -p pkgconf >/dev/null; then
	echo "You need to have pkgconf installed"
	exit 1
fi

if ! version_release=$(pkgconf --variable VERSION_RELEASE wireshark); then
	echo "You should install the 'wireshark-devel' package or similar"
	exit 1
fi

if [[ -z $version_release ]]; then
	echo "You have a buggy version of wireshark-devel which does not define the VERSION_RELEASE variable"
	if type -p rpm >/dev/null; then
		version_release=$(rpm -q wireshark-devel --qf %{VERSION} | cut -d. -f1-2)
		echo "Trying to work around it by assuming VERSION_RELEASE=${version_release}"
		VERSION_RELEASE=${version_release}
	else
		echo "The compiled plugin will most likely refuse to be loaded by wireshark, but buildig it anyway"
	fi
fi

set -ex

autoreconf -v -i
./configure
if [[ -n $VERSION_RELEASE ]]; then
	make VERSION_RELEASE=$VERSION_RELEASE
else
	make
fi
# make install-home
