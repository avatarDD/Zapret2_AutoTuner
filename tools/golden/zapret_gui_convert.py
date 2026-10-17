#!/usr/bin/env python3
"""Golden outputs of zapret-gui core/profile_import.convert for the C# port (ZapretGuiConvert).

Usage: python3 tools/golden/zapret_gui_convert.py /path/to/zapret-gui
Reads tests/testdata/zapret-gui-convert/*.txt, writes *.expected.json next to them. The environment is the one of
zapret-gui's tests/test_profile_import.py; ExportTests uses the same.
"""
import json
import os
import sys

gui = os.path.abspath(sys.argv[1])
sys.path.insert(0, gui)
from core import profile_import as pi  # noqa: E402

HAVE = {"/l/lua/zapret-antidpi.lua", "/l/fake/tls_google.bin", "/l/lists/other.txt"}
ENV = {"lua_path": "/l/lua", "bin_path": "/l/fake", "lists_path": "/l/lists", "ipset_path": "/l/ipset",
       "exists": lambda p: p in HAVE, "iface_exists": lambda i: i == "eth3"}

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "testdata", "zapret-gui-convert")
for name in sorted(os.listdir(root)):
    if not name.endswith(".txt"):
        continue
    with open(os.path.join(root, name), encoding="utf-8") as f:
        out = pi.convert(f.read(), ENV)
    with open(os.path.join(root, name[:-4] + ".expected.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
