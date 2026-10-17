#!/usr/bin/env python3
"""Fetch the pinned zapret2 release and lay out the engine bundle for one runtime identifier.

    python3 tools/bundle/bundle.py --rid linux-x64 [--out runtimes/linux-x64/zapret2] [--archive file.zip]

Steps (PLAN.md phase 0.3):
  1. download the release asset named in zapret2.lock.json (or use --archive);
  2. verify SHA-256 against the lock file; with an empty pin, against GitHub's asset digest, and print the
     value to pin (fails with --strict);
  3. copy the engine binaries for the RID, the lua files and files/fake into the output directory;
  4. check NFQWS2_COMPAT_VER_REQUIRED of the lua against the lock and that the lua equals third_party/zapret2/lua
     (the catalog is tested against that copy);
  5. write bundle.json with per-file SHA-256 for the runtime integrity check.
Only the Python standard library is used, so it runs on GitHub's Windows and Linux runners as is.
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LOCK = os.path.join(os.path.dirname(__file__), "zapret2.lock.json")


def log(msg):
    print(f"[bundle] {msg}", flush=True)


def fail(msg):
    print(f"[bundle] ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def http_get(url, accept="application/octet-stream"):
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "Zapret2_AutoTuner-bundle"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def release_info(repo, tag):
    try:
        return json.loads(http_get(f"https://api.github.com/repos/{repo}/releases/tags/{tag}", "application/vnd.github+json"))
    except Exception as e:  # noqa: BLE001 - show what exists to make fixing the lock easy
        try:
            rels = json.loads(http_get(f"https://api.github.com/repos/{repo}/releases?per_page=10", "application/vnd.github+json"))
            for r in rels:
                log(f"available release {r['tag_name']}: " + ", ".join(a["name"] for a in r.get("assets", [])))
        except Exception:  # noqa: BLE001
            pass
        fail(f"release {tag} of {repo} not found: {e}")


class Archive:
    """Uniform read access to zip and tar.gz releases with the top-level folder stripped."""

    def __init__(self, data, name):
        self.files = {}
        if name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for i in z.infolist():
                    if not i.is_dir():
                        self.files[i.filename] = z.read(i)
        else:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    if m.isfile():
                        self.files[m.name] = t.extractfile(m).read()
        tops = {p.split("/", 1)[0] for p in self.files}
        if len(tops) == 1 and all("/" in p for p in self.files):
            top = tops.pop() + "/"
            self.files = {p[len(top):]: d for p, d in self.files.items()}

    def get(self, path):
        return self.files.get(path)

    def under(self, prefix):
        prefix = prefix.rstrip("/") + "/"
        return {p[len(prefix):]: d for p, d in self.files.items() if p.startswith(prefix)}

    def dirs_containing(self, filename):
        return sorted({os.path.dirname(p) for p in self.files if os.path.basename(p) == filename})


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rid", required=True)
    ap.add_argument("--out")
    ap.add_argument("--archive", help="use a local release archive instead of downloading")
    ap.add_argument("--strict", action="store_true", help="fail when the lock has no sha256 pin")
    args = ap.parse_args()

    lock = json.load(open(LOCK, encoding="utf-8"))
    rid_spec = lock["rids"].get(args.rid) or fail(f"unknown rid {args.rid}; known: {', '.join(lock['rids'])}")
    out = os.path.abspath(args.out or os.path.join(ROOT, "runtimes", args.rid, "zapret2"))

    if args.archive:
        name = os.path.basename(args.archive)
        data = open(args.archive, "rb").read()
        digest = None
    else:
        rel = release_info(lock["repo"], lock["tag"])
        assets = [a for a in rel.get("assets", []) if re.match(lock["asset_pattern"], a["name"])]
        if not assets:
            fail("no asset matches %s; assets: %s" % (lock["asset_pattern"], ", ".join(a["name"] for a in rel.get("assets", []))))
        asset = assets[0]
        name = asset["name"]
        log(f"downloading {name} from {lock['repo']} {lock['tag']}")
        data = http_get(asset["browser_download_url"])
        digest = (asset.get("digest") or "").removeprefix("sha256:") or None
        sums = [a for a in rel.get("assets", []) if a["name"] == "sha256sum.txt"]
        if sums:
            listed = None
            for line in http_get(sums[0]["browser_download_url"]).decode("utf-8", "replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-1].lstrip("*").split("/")[-1] == name:
                    listed = parts[0].lower()
            if listed and listed != sha256(data):
                fail(f"{name}: sha256 does not match the release's sha256sum.txt ({listed})")
            log(f"{name}: sha256sum.txt of the release " + ("matches" if listed else "has no line for it"))

    actual = sha256(data)
    pinned = lock.get("sha256") or ""
    if pinned:
        if actual != pinned:
            fail(f"{name}: sha256 {actual} does not match the pinned {pinned}")
        log(f"{name}: sha256 matches the pin")
    else:
        if digest and digest != actual:
            fail(f"{name}: sha256 {actual} does not match GitHub's digest {digest}")
        log(f"{name}: sha256 {actual} (GitHub digest: {digest or 'n/a'}) -- pin it in zapret2.lock.json")
        if args.strict:
            fail("no sha256 pin in zapret2.lock.json (--strict)")

    arc = Archive(data, name)
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)
    manifest_files = {}

    def put(rel, blob, executable=False):
        dst = os.path.join(out, *rel.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(blob)
        if executable:
            os.chmod(dst, os.stat(dst).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        manifest_files[rel] = sha256(blob)

    bin_dir = rid_spec["dir"]
    for f in rid_spec["files"]:
        blob = arc.get(f"{bin_dir}/{f}")
        if blob is None:
            fail(f"{bin_dir}/{f} not in the archive; directories with {f}: {arc.dirs_containing(f)}")
        put(f, blob, executable=not f.endswith((".dll", ".sys")))
    for f in rid_spec.get("optional", []):
        blob = arc.get(f"{bin_dir}/{f}")
        if blob is not None:
            put(f, blob, executable=True)

    for rel in lock["common"]:
        blob = arc.get(rel) or fail(f"{rel} not in the archive")
        put(rel, blob)
    for d in lock["common_dirs"]:
        files = arc.under(d)
        if not files:
            fail(f"{d}/ is empty in the archive")
        for sub, blob in sorted(files.items()):
            put(f"{d}/{sub}", blob)

    lib = arc.get("lua/zapret-lib.lua").decode("utf-8", "replace").splitlines()[0]
    m = re.match(r"\s*NFQWS2_COMPAT_VER_REQUIRED\s*=\s*(\d+)", lib)
    compat = int(m.group(1)) if m else fail("zapret-lib.lua has no NFQWS2_COMPAT_VER_REQUIRED on the first line")
    if compat != lock["lua_compat"]:
        fail(f"lua requires compat {compat}, lock expects {lock['lua_compat']}")

    vendored = os.path.join(ROOT, "third_party", "zapret2")
    for rel in lock["common"]:
        vp = os.path.join(vendored, *rel.split("/"))
        if not os.path.exists(vp) or sha256(open(vp, "rb").read().replace(b"\r\n", b"\n")) != sha256(arc.get(rel).replace(b"\r\n", b"\n")):
            fail(f"{rel} differs from third_party/zapret2/{rel}: update the vendored copy and re-check the catalog")

    manifest = {
        "tag": lock["tag"],
        "version": lock["version"],
        "rid": args.rid,
        "lua_compat": compat,
        "source_sha256": actual,
        "files": dict(sorted(manifest_files.items())),
    }
    with open(os.path.join(out, "bundle.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    log(f"bundle for {args.rid} is ready in {out} ({len(manifest_files)} files)")


if __name__ == "__main__":
    main()
