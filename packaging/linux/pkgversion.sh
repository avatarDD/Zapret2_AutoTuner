#!/usr/bin/env bash
# The package version of a release version: a prerelease suffix (1.2.0-rc.1) sorts before the release in dpkg and rpm
# only with a tilde (1.2.0~rc.1); rpm does not allow '-' in Version at all.
# usage: packaging/linux/pkgversion.sh <version>
set -euo pipefail
v=${1#v}
printf '%s\n' "${v//-/\~}"
