#!/usr/bin/env python3
# Fix missing SUSFS header includes after applying T-branch + main SUSFS patches
# in reversed order (T-branch first, main patch with || true). The main patch's
# fdinfo.c include hunk fails on the ares tree, so we add it explicitly here.
import os

# Run from kernel source root (working-directory: kernel)
TARGETS = ['fs/notify/fdinfo.c', 'fs/proc/base.c']

for f in TARGETS:
    if not os.path.exists(f):
        print('skip (not found):', f)
        continue
    s = open(f).read()
    if '#include <linux/susfs_def.h>' in s:
        print('already has susfs_def.h include:', f)
        continue
    lines = s.split('\n')
    inserted = False
    for i, l in enumerate(lines):
        if l.startswith('#include <linux/'):
            lines.insert(i + 1, '#include <linux/susfs_def.h>')
            inserted = True
            break
    if not inserted:
        # no linux include found; add after the first line (SPDX/license)
        lines.insert(1, '#include <linux/susfs_def.h>')
    open(f, 'w').write('\n'.join(lines))
    print('added #include <linux/susfs_def.h> to', f)
