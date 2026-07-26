#!/usr/bin/env python3
# Apply ReSukiSU SUSFS (inline-hook path) manual call sites to the ares 4.14 kernel.
# Called from the kernel source root (device_kernel). Adds the 7 ksu_handle_* call
# sites required by kernel/tools/inline_hook_check.mk, guarded by CONFIG_KSU.
# NOTE: we do NOT use ksu_init_rc_hook / ksu_input_hook (those are forbidden in the
#       SUSFS inline path by inline_hook_check.mk). The handlers internally check
#       KSU readiness, so an unconditional call is safe.
import os, sys, re

ROOT = os.getcwd()

# (relative path, unique signature anchor, extern declaration, call site)
HOOKS = [
    ("fs/stat.c", "SYSCALL_DEFINE4(newfstatat,",
     "extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);",
     "ksu_handle_stat(&dfd, &filename, &flag);"),
    ("fs/stat.c", "SYSCALL_DEFINE2(newfstat,",
     "extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);",
     "ksu_handle_newfstat_ret(&fd, &statbuf);"),
    ("fs/stat.c", "SYSCALL_DEFINE2(fstat64,",
     "extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);",
     "ksu_handle_fstat64_ret(&fd, &statbuf);"),
    ("kernel/sys.c", "SYSCALL_DEFINE3(setresuid,",
     "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);",
     "(void)ksu_handle_setresuid(ruid, euid, suid);"),
    ("kernel/reboot.c", "SYSCALL_DEFINE4(reboot,",
     "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);",
     "ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);"),
    ("drivers/input/input.c", "static void input_handle_event(",
     "extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);",
     "ksu_handle_input_handle_event(&type, &code, &value);"),
    ("fs/exec.c", "static int do_execveat_common(",
     "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);",
     "ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);"),
    ("fs/open.c", "SYSCALL_DEFINE3(faccessat,",
     "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags);",
     "ksu_handle_faccessat(&dfd, &filename, &mode, NULL);"),
    ("fs/read_write.c", "SYSCALL_DEFINE3(read,",
     "extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);",
     "ksu_handle_sys_read(fd, &buf, &count);"),
]

GUARD_OPEN = "#ifdef CONFIG_KSU"
GUARD_CLOSE = "#endif"

def inject(path, sig, extern_decl, call):
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        print(f"[!] SKIP (no file): {path}")
        return False
    with open(full, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    # idempotency: if the call symbol already present, skip
    # robustly extract the ksu_handle_* symbol (call may start with a cast like "(void)")
    m = re.search(r"ksu_handle_\w+", call)
    call_sym = m.group(0) if m else call.split("(")[0].strip()
    if not call_sym:
        print(f"[!] could not derive symbol from call: {call!r}")
        return False
    for ln in lines:
        if call_sym in ln:
            print(f"[=] already present, skip: {path} ({call_sym})")
            return True
    # find signature line
    si = None
    for i, ln in enumerate(lines):
        if sig in ln:
            si = i
            break
    if si is None:
        print(f"[!] signature not found in {path}: {sig}")
        return False
    # find the opening brace line after the signature
    bi = None
    for j in range(si, min(si + 12, len(lines))):
        if "{" in lines[j]:
            bi = j
            break
    if bi is None:
        print(f"[!] brace not found after sig in {path}")
        return False
    # build blocks
    extern_block = [GUARD_OPEN, "\t" + extern_decl, GUARD_CLOSE, ""]
    call_block = [GUARD_OPEN, "\t" + call, GUARD_CLOSE]
    # insert call block AFTER brace line
    lines = lines[:bi+1] + call_block + lines[bi+1:]
    # insert extern block BEFORE signature line
    lines = lines[:si] + extern_block + lines[si:]
    with open(full, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] injected: {path}  ({call_sym})")
    return True

def main():
    ok = True
    for path, sig, ext, call in HOOKS:
        if not inject(path, sig, ext, call):
            ok = False
    if not ok:
        print("[X] some hooks failed to inject")
        sys.exit(1)
    print("[OK] all 7 SUSFS call sites injected")

if __name__ == "__main__":
    main()
