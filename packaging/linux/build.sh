#!/usr/bin/env bash
# Linux packages from a self-contained publish folder: tar.gz, .deb and .rpm.
# No AppImage in release 1: the Agent runs as root through pkexec, and root cannot read the user's FUSE mount the
# AppImage runs from; copying the Agent somewhere first would let the user swap it before pkexec runs it (docs/PLAN.md, 9).
# usage: packaging/linux/build.sh <rid> <version> <publish-dir> <out-dir>
set -euo pipefail
rid=$1 version=$2 pub=$(realpath "$3") out=$(mkdir -p "$4" && realpath "$4")
here=$(dirname "$(realpath "$0")")
name=zapret-autotuner
case "$rid" in
  linux-x64) deb_arch=amd64 rpm_arch=x86_64 ;;
  linux-arm64) deb_arch=arm64 rpm_arch=aarch64 ;;
  *) echo "unknown rid $rid" >&2; exit 1 ;;
esac
pkg_version=$("$here/pkgversion.sh" "$version")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# portable archive
tar -C "$(dirname "$pub")" --transform "s|^$(basename "$pub")|ZapretAutoTuner-$version|" -czf "$out/ZapretAutoTuner-$version-$rid.tar.gz" "$(basename "$pub")"

# file system layout shared by .deb and .rpm
root="$work/root"
install -d "$root/opt/$name" "$root/usr/bin" "$root/usr/share/applications" "$root/usr/share/icons/hicolor/scalable/apps" "$root/usr/share/polkit-1/actions"
cp -a "$pub/." "$root/opt/$name/"
chmod 755 "$root/opt/$name/ZapretAutoTuner" "$root/opt/$name/ztuner-agent" "$root/opt/$name/zapret2/nfqws2" "$root/opt/$name/geneva/geneva"
ln -s "/opt/$name/ZapretAutoTuner" "$root/usr/bin/$name"
install -m 644 "$here/zapret-autotuner.desktop" "$root/usr/share/applications/"
install -m 644 "$here/../icon.svg" "$root/usr/share/icons/hicolor/scalable/apps/$name.svg"
install -m 644 "$here/org.zapret.autotuner.policy" "$root/usr/share/polkit-1/actions/"
size=$(du -sk "$root" | cut -f1)

# .deb
install -d "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<CONTROL
Package: $name
Version: $pkg_version
Architecture: $deb_arch
Maintainer: Zapret2_AutoTuner contributors
Installed-Size: $size
Depends: nftables | iptables, pkexec | policykit-1, libicu78 | libicu77 | libicu76 | libicu74 | libicu72 | libicu71 | libicu70 | libicu67 | libicu66, libfontconfig1, libfreetype6, libx11-6, libice6, libsm6, libxext6, libxrandr2, libxi6, libxcursor1, zlib1g, libssl3 | libssl3t64 | libssl1.1, ca-certificates
Recommends: libnss3, libnspr4, libatk1.0-0t64 | libatk1.0-0, libatk-bridge2.0-0t64 | libatk-bridge2.0-0, libcups2t64 | libcups2, libdrm2, libxkbcommon0, libxcomposite1, libxdamage1, libxfixes3, libgbm1, libasound2t64 | libasound2, libpango-1.0-0, libcairo2
Section: net
Priority: optional
Homepage: https://github.com/avatarDD/Zapret2_AutoTuner
Description: zapret2 strategy tuning
 Finds working nfqws2 strategies for blocked sites on this PC and exports
 them to zapret2, nfqws2-keenetic and zapret-gui.
CONTROL
dpkg-deb --root-owner-group --build "$root" "$out/${name}_${pkg_version}_${deb_arch}.deb"
rm -rf "$root/DEBIAN"

# .rpm
if command -v rpmbuild >/dev/null; then
  spec="$work/$name.spec"
  cat > "$spec" <<SPEC
Name: $name
Version: $pkg_version
Release: 1
Summary: zapret2 strategy tuning
License: MIT
URL: https://github.com/avatarDD/Zapret2_AutoTuner
Requires: polkit, (nftables or iptables), libicu, fontconfig, freetype, libX11, libICE, libSM, libXext, libXrandr, libXi, libXcursor, zlib, openssl-libs, ca-certificates
AutoReqProv: no
%global __os_install_post %{nil}
%global debug_package %{nil}
%description
Finds working nfqws2 strategies for blocked sites on this PC and exports them to zapret2, nfqws2-keenetic and zapret-gui.
%install
cp -a $root/. %{buildroot}/
%files
/opt/$name
/usr/bin/$name
/usr/share/applications/zapret-autotuner.desktop
/usr/share/icons/hicolor/scalable/apps/$name.svg
/usr/share/polkit-1/actions/org.zapret.autotuner.policy
SPEC
  rpmbuild -bb --target "$rpm_arch" --define "_topdir $work/rpm" --define "_build_id_links none" "$spec"
  find "$work/rpm/RPMS" -name '*.rpm' -exec cp {} "$out/" \;
else
  echo "rpmbuild not found: skipping .rpm" >&2
fi

ls -la "$out"
