#!/usr/bin/env bash
# Linux packages from a self-contained publish folder: tar.gz, .deb, .rpm and AppImage.
# usage: packaging/linux/build.sh <rid> <version> <publish-dir> <out-dir>
set -euo pipefail
rid=$1 version=$2 pub=$(realpath "$3") out=$(mkdir -p "$4" && realpath "$4")
here=$(dirname "$(realpath "$0")")
name=zapret-autotuner
case "$rid" in
  linux-x64) deb_arch=amd64 rpm_arch=x86_64 appimage_arch=x86_64 ;;
  linux-arm64) deb_arch=arm64 rpm_arch=aarch64 appimage_arch=aarch64 ;;
  *) echo "unknown rid $rid" >&2; exit 1 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# portable archive
tar -C "$(dirname "$pub")" --transform "s|^$(basename "$pub")|ZapretAutoTuner-$version|" -czf "$out/ZapretAutoTuner-$version-$rid.tar.gz" "$(basename "$pub")"

# file system layout shared by .deb and .rpm
root="$work/root"
install -d "$root/opt/$name" "$root/usr/bin" "$root/usr/share/applications" "$root/usr/share/icons/hicolor/scalable/apps" "$root/usr/share/polkit-1/actions"
cp -a "$pub/." "$root/opt/$name/"
chmod 755 "$root/opt/$name/ZapretAutoTuner" "$root/opt/$name/ztuner-agent" "$root/opt/$name/zapret2/nfqws2"
ln -s "/opt/$name/ZapretAutoTuner" "$root/usr/bin/$name"
install -m 644 "$here/zapret-autotuner.desktop" "$root/usr/share/applications/"
install -m 644 "$here/../icon.svg" "$root/usr/share/icons/hicolor/scalable/apps/$name.svg"
install -m 644 "$here/org.zapret.autotuner.policy" "$root/usr/share/polkit-1/actions/"
size=$(du -sk "$root" | cut -f1)

# .deb
install -d "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<CONTROL
Package: $name
Version: $version
Architecture: $deb_arch
Maintainer: Zapret2_AutoTuner contributors
Installed-Size: $size
Depends: nftables | iptables, pkexec | policykit-1
Recommends: chromium | chromium-browser | google-chrome-stable
Section: net
Priority: optional
Homepage: https://github.com/avatarDD/Zapret2_AutoTuner
Description: zapret2 strategy tuning
 Finds working nfqws2 strategies for blocked sites on this PC and exports
 them to zapret2, nfqws2-keenetic and zapret-gui.
CONTROL
dpkg-deb --root-owner-group --build "$root" "$out/${name}_${version}_${deb_arch}.deb"
rm -rf "$root/DEBIAN"

# .rpm
if command -v rpmbuild >/dev/null; then
  spec="$work/$name.spec"
  cat > "$spec" <<SPEC
Name: $name
Version: ${version//-/_}
Release: 1
Summary: zapret2 strategy tuning
License: MIT
URL: https://github.com/avatarDD/Zapret2_AutoTuner
Requires: polkit
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

# AppImage (appimagetool is a build tool only; nothing of it ships)
if [ -n "${APPIMAGETOOL:-}" ]; then
  app="$work/AppDir"
  install -d "$app/usr/bin"
  cp -a "$pub/." "$app/usr/bin/"
  install -m 644 "$here/zapret-autotuner.desktop" "$app/"
  install -m 644 "$here/../icon.svg" "$app/$name.svg"
  printf '#!/bin/sh\nexec "$(dirname "$(readlink -f "$0")")/usr/bin/ZapretAutoTuner" "$@"\n' > "$app/AppRun"
  chmod 755 "$app/AppRun"
  ARCH=$appimage_arch "$APPIMAGETOOL" --appimage-extract-and-run --no-appstream "$app" "$out/ZapretAutoTuner-$version-$appimage_arch.AppImage"
fi
ls -la "$out"
