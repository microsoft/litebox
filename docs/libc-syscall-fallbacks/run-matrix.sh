#!/usr/bin/env bash
# Build probe.c against glibc and musl, then fail one syscall at a time with ENOSYS
# (strace fault injection) and report which libc wrappers break.
#
#   MUSL_GCC=/path/to/musl-gcc ./run-matrix.sh
set -euo pipefail
cd "$(dirname "$0")"
MUSL_GCC=${MUSL_GCC:-musl-gcc}
SYSCALLS=${SYSCALLS:-"clone3 faccessat2 fchmodat2 statx execveat close_range renameat2 mlock2
  preadv2 pwritev2 getrandom rseq set_robust_list membarrier prlimit64 pipe2 dup3 accept4
  eventfd2 epoll_create1 epoll_pwait signalfd4 inotify_init1 utimensat copy_file_range
  memfd_create fallocate getcpu newfstatat stat lstat fstat mlock"}

gcc -O1 -pthread -o probe-glibc probe.c
"$MUSL_GCC" -O1 -static -idirafter /usr/include -idirafter "/usr/include/$(gcc -print-multiarch)" \
  -o probe-musl probe.c

for libc in glibc musl; do
  ./probe-$libc >base-$libc.txt
  echo "=== $libc: baseline failures: $(grep -c FAIL base-$libc.txt || true)"
  for sc in $SYSCALLS; do
    rc=0
    out=$(timeout 20 strace -f -qq -o /dev/null -e inject="$sc":error=ENOSYS ./probe-$libc 2>&1) || rc=$?
    # Lines that changed, plus tests that never reported (crash or hang).
    changed=$({
      diff base-$libc.txt <(echo "$out") | sed -n 's/^> //p'
      cut -c1-26 base-$libc.txt | sed 's/ *$//' | while IFS= read -r name; do
        grep -qF -- "$name" <<<"$out" || echo "$name NO RESULT"
      done
      if [ $rc -eq 124 ]; then echo "(hung: killed after 20s)"; fi
    } | tr -s " " | awk '!s[$0]++' | paste -sd ";" - || true)
    printf '%-16s %s\n' "$sc" "${changed:-(all wrappers still OK)}"
  done
  for e in 22 38; do
    printf '%-16s %s\n' "futex→$e" \
      "$(SIM_FUTEX_ERRNO=$e timeout 20 ./probe-$libc 2>&1 | grep -v ' OK$' | tr -s ' ' | paste -sd ';' -)"
  done
done
