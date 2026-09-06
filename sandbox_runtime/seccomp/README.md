# Evolve bwrap seccomp profile

This profile is derived from the maintained Docker/Moby seccomp baseline:

- source: `moby/profiles`
- tag: `seccomp/v0.2.1`
- source file: `seccomp/default.json`

The local delta is intentionally narrow: `pivot_root` is added to the existing
`CAP_SYS_ADMIN`-gated allow rule. No syscall is made unconditionally available and
`seccomp=unconfined` is not used.

The container root needs `CAP_SYS_ADMIN` only so the trusted sandbox daemon can create
the bubblewrap mount namespace used by the Evolve synthetic filesystem. Agent-controlled
children must run with an empty effective/inheritable/ambient capability set, an empty
capability bounding set, and `no_new_privs`.
