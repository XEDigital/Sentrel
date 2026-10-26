#!/usr/bin/env bash
# End-to-end system test against a running server with at least one Linux
# agent (run it on the agent host). Needs curl, jq, nft.
#
#   HB_URL=http://127.0.0.1:8080 HB_USER=admin HB_PASSWORD=... scripts/e2e.sh
#
# It creates checks, channels, windows, blocks and jobs prefixed "e2e-" and
# removes them at the end.
set -uo pipefail

URL="${HB_URL:-http://127.0.0.1:8080}"
USER_="${HB_USER:-admin}"
PASS="${HB_PASSWORD:?set HB_PASSWORD}"
JAR=$(mktemp)
PASSED=0
FAILED=0
trap 'rm -f "$JAR"' EXIT

ok()   { PASSED=$((PASSED+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAILED=$((FAILED+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

CSRF=""
api() { # method path [json]
  local m=$1 p=$2 d=${3:-}
  if [ -n "$d" ]; then
    curl -s -b "$JAR" -c "$JAR" -X "$m" -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" "$URL/api/v1$p" -d "$d"
  else
    curl -s -b "$JAR" -c "$JAR" -X "$m" -H "X-CSRF-Token: $CSRF" "$URL/api/v1$p"
  fi
}
expect() { # description jq-filter json
  if echo "$3" | jq -e "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1 :: $(echo "$3" | head -c 300)"; fi
}
wait_for() { # description seconds command...
  local desc=$1 secs=$2; shift 2
  local end=$((SECONDS+secs))
  while [ $SECONDS -lt $end ]; do
    if "$@" >/dev/null 2>&1; then ok "$desc"; return 0; fi
    sleep 3
  done
  bad "$desc (timed out after ${secs}s)"
  return 1
}

step "login"
R=$(curl -s -c "$JAR" -H "Content-Type: application/json" "$URL/api/v1/auth/login" -d "{\"username\":\"$USER_\",\"password\":\"$PASS\"}")
CSRF=$(echo "$R" | jq -r .csrf_token)
expect "session login" '.user.username != null' "$R"

step "agent host"
HOSTS=$(api GET /hosts)
HID=$(echo "$HOSTS" | jq -r --arg hn "$(hostname)" '[.[] | select(.kind=="agent" and .connected and .host_info.hostname==$hn)][0].id')
[ "$HID" != "null" ] && ok "connected agent host #$HID" || { bad "no connected agent"; exit 1; }
H=$(api GET "/hosts/$HID")
expect "host has disks and services" '(.state.disks | length) > 0 and (.state.services | length) > 0' "$H"
expect "inventory received" '.inventory.installed_count > 100' "$H"
expect "metrics flowing" '.summary.cpu != null and .summary.memory != null' "$H"
M=$(api GET "/hosts/$HID/metrics?panel=network&start=900s")
expect "network series" '(.series | length) > 0' "$M"

step "checks (server-side and agent-evaluated)"
mk() { api POST /checks "$1" | jq -r '.id // empty'; }
C_PING=$(mk '{"name":"e2e-ping","type":"ping","target":"127.0.0.1","interval_seconds":10,"failure_threshold":1}')
C_TCP_UP=$(mk '{"name":"e2e-tcp-up","type":"tcp","target":"127.0.0.1:8080","interval_seconds":10,"failure_threshold":1}')
C_TCP_DOWN=$(mk '{"name":"e2e-tcp-down","type":"tcp","target":"127.0.0.1:1","interval_seconds":10,"failure_threshold":1}')
C_HTTP=$(mk '{"name":"e2e-http","type":"http","target":"http://127.0.0.1:8080/healthz","config":{"keyword":"ok"},"interval_seconds":10,"failure_threshold":1}')
C_CERT=$(mk '{"name":"e2e-cert","type":"cert","target":"www.google.com:443","interval_seconds":60}')
C_DNS=$(mk '{"name":"e2e-dns","type":"dns","target":"one.one.one.one","config":{"record_type":"A","expect":"1.1.1.1"},"interval_seconds":60}')
C_SVC=$(mk "{\"name\":\"e2e-svc-sshd\",\"type\":\"service\",\"target\":\"ssh\",\"host_id\":$HID}")
C_PORT=$(mk "{\"name\":\"e2e-port-22\",\"type\":\"port\",\"target\":\"22\",\"host_id\":$HID}")
C_PROC=$(mk "{\"name\":\"e2e-proc\",\"type\":\"process\",\"target\":\"sentrel-agent\",\"host_id\":$HID}")
C_CONT=$(mk "{\"name\":\"e2e-container\",\"type\":\"container\",\"target\":\"hb-test-nginx\",\"host_id\":$HID}")
C_MISSING=$(mk "{\"name\":\"e2e-svc-missing\",\"type\":\"service\",\"target\":\"no-such-service-xyz\",\"host_id\":$HID,\"failure_threshold\":1}")
for c in "$C_PING" "$C_TCP_UP" "$C_TCP_DOWN" "$C_HTTP" "$C_CERT" "$C_DNS"; do api POST "/checks/$c/run" >/dev/null; done
status_is() { [ "$(api GET "/checks/$1" | jq -r .status)" = "$2" ]; }
wait_for "ping 127.0.0.1 up (ICMP via cap_net_raw)" 30 status_is "$C_PING" up
wait_for "tcp :8080 up" 30 status_is "$C_TCP_UP" up
wait_for "tcp :1 down" 30 status_is "$C_TCP_DOWN" down
wait_for "http /healthz keyword up" 30 status_is "$C_HTTP" up
wait_for "certificate check up" 60 status_is "$C_CERT" up
wait_for "dns A record up" 60 status_is "$C_DNS" up
wait_for "service ssh running (agent)" 90 status_is "$C_SVC" up
wait_for "port 22 listening (agent)" 90 status_is "$C_PORT" up
wait_for "process sentrel-agent (agent)" 90 status_is "$C_PROC" up
wait_for "container hb-test-nginx running (agent)" 90 status_is "$C_CONT" up
wait_for "missing service reported down" 90 status_is "$C_MISSING" down
alert_for() { api GET "/alerts?status=active" | jq -e --arg c "$1" '[.[] | select((.check_id|tostring)==$c and .status=="firing")] | length > 0'; }
wait_for "down check fires an alert" 60 alert_for "$C_TCP_DOWN"

step "notifications (webhook, grouping, resolve)"
HOOK_LOG=$(mktemp)
python3 - "$HOOK_LOG" <<'PY' &
import http.server, sys
log = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        with open(log, 'ab') as f: f.write(self.rfile.read(n) + b"\n")
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', 18099), H).serve_forever()
PY
HOOK_PID=$!
sleep 1
CH=$(api POST /notification-channels '{"name":"e2e-hook","type":"webhook","config":{"url":"http://127.0.0.1:18099/hook"},"repeat_minutes":0}' | jq -r .id)
T=$(api POST "/notification-channels/$CH/test")
expect "test notification delivered" '.ok == true' "$T"
api PUT /settings/alerting '{"group_wait_seconds":5,"default_repeat_minutes":240,"flap_window_minutes":30,"flap_threshold":6,"resolve_count":1}' >/dev/null
C_FLIP=$(mk '{"name":"e2e-flip","type":"tcp","target":"127.0.0.1:18098","interval_seconds":10,"failure_threshold":1}')
api POST "/checks/$C_FLIP/run" >/dev/null
hook_has() { grep -q "$1" "$HOOK_LOG"; }
wait_for "firing alert delivered to webhook" 60 hook_has 'e2e-flip is down'
python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',18098));s.listen(5);time.sleep(60)" &
LISTEN_PID=$!
api POST "/checks/$C_FLIP/run" >/dev/null
wait_for "resolved notification delivered" 60 hook_has '"status":"resolved"'
kill $LISTEN_PID 2>/dev/null

step "acknowledgement and maintenance"
AID=$(api GET "/alerts?status=active" | jq -r --arg c "$C_TCP_DOWN" '[.[] | select((.check_id|tostring)==$c)][0].id')
A=$(api POST "/alerts/$AID/ack" '{"comment":"e2e"}')
expect "alert acknowledged" '.acked_by != ""' "$A"
NOW=$(date +%s)
MW=$(api POST /maintenance "{\"name\":\"e2e-window\",\"scope\":\"host\",\"scope_ids\":[$HID],\"starts_at\":$((NOW-60)),\"ends_at\":$((NOW+600)),\"recurrence\":\"none\",\"timezone\":\"UTC\"}")
expect "maintenance window active" '.active_now == true' "$MW"
expect "host shows in maintenance" '.in_maintenance == true' "$(api GET "/hosts/$HID")"
api DELETE "/maintenance/$(echo "$MW" | jq -r .id)" >/dev/null

step "thresholds (host override)"
R=$(api POST /thresholds "{\"scope\":\"host\",\"scope_id\":$HID,\"metric\":\"disk\",\"label_match\":\"/boot*\",\"warn\":99,\"crit\":99.5,\"for_count\":1}")
expect "label override saved" '.id > 0' "$R"
MR=$(api GET "/hosts/$HID/thresholds")
expect "merged view shows host label override" '[.[] | select(.metric.key=="disk") | .label_overrides[]? | select(.origin=="host")] | length == 1' "$MR"
api DELETE "/thresholds/$(echo "$R" | jq -r .id)" >/dev/null

step "remote actions: IP block (nftables) and upgrade dry run"
api PUT "/hosts/$HID" '{"allow_ip_block":true}' >/dev/null
J=$(api POST "/hosts/$HID/block" '{"ip":"203.0.113.77","minutes":5,"reason":"e2e","confirm":true}')
JID=$(echo "$J" | jq -r .id)
job_done() { [ "$(api GET "/jobs/$1" | jq -r .status)" = "$2" ]; }
wait_for "block job succeeded" 60 job_done "$JID" succeeded
nft_has() { sudo nft list set inet sentrel blocklist4 | grep -q "$1"; }
wait_for "IP present in nftables set with timeout" 10 nft_has 203.0.113.77
UJ=$(api POST "/hosts/$HID/unblock" '{"ip":"203.0.113.77"}' | jq -r .id)
wait_for "unblock job succeeded" 60 job_done "$UJ" succeeded
nft_gone() { ! sudo nft list set inet sentrel blocklist4 | grep -q 203.0.113.77; }
wait_for "IP removed from nftables" 10 nft_gone
R=$(api POST "/hosts/$HID/block" '{"ip":"127.0.0.1","minutes":5,"confirm":true}')
expect "loopback cannot be blocked" '.code != null' "$R"
api PUT "/hosts/$HID" '{"allow_ip_block":false}' >/dev/null
DJ=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"upgrade\",\"dry_run\":true}" | jq -r .id)
wait_for "upgrade dry run succeeded" 300 job_done "$DJ" succeeded
expect "dry run captured package manager output" '.output | test("Reading package lists|upgraded|DRY RUN")' "$(api GET "/jobs/$DJ")"
PREV_UPG=$(api GET "/hosts/$HID" | jq -r '.allow_upgrades // .host.allow_upgrades')
api PUT "/hosts/$HID" '{"allow_upgrades":false}' >/dev/null
R=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"upgrade\",\"confirm\":true}")
expect "real upgrade refused without host opt-in" '.code == "forbidden"' "$R"
api PUT "/hosts/$HID" "{\"allow_upgrades\":$PREV_UPG}" >/dev/null

step "kernels (old kernel detection and remove_kernel dry run)"
K=$(api GET "/hosts/$HID/kernels")
expect "kernels endpoint reports the running kernel and installed kernels" '(.running | length) > 0 and (.installed | type) == "array"' "$K"
expect "the running and newest kernels are never removable" '([.installed[] | select((.running or .newest) and .removable)] | length) == 0' "$K"
FK=$(api GET /vulnerabilities/kernels)
expect "fleet kernels endpoint answers with a list" 'type == "array"' "$FK"
RUNABI=$(echo "$K" | jq -r '[.installed[] | select(.running)][0].abi // empty')
if [ -n "$RUNABI" ]; then
  R=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"remove_kernel\",\"params\":{\"abi\":\"$RUNABI\"},\"dry_run\":true}")
  expect "removing the running kernel is refused" '.code != null' "$R"
fi
R=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"remove_kernel\",\"params\":{\"abi\":\"1.0; id\"},\"dry_run\":true}")
expect "a malformed kernel ABI is refused" '.code != null' "$R"
OLDK=$(echo "$K" | jq -r '[.installed[] | select(.removable)][0].abi // empty')
if [ -n "$OLDK" ]; then
  KJ=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"remove_kernel\",\"params\":{\"abi\":\"$OLDK\"},\"dry_run\":true}" | jq -r .id)
  wait_for "remove_kernel dry run succeeded" 120 job_done "$KJ" succeeded
  KR=$(api GET "/jobs/$KJ")
  expect "dry run lists only the packages of kernel $OLDK" "(.result_json | fromjson | .packages | length) > 0 and ([.result_json | fromjson | .packages[] | select(contains(\"$OLDK\") | not)] | length) == 0" "$KR"
else
  ok "no old kernel installed on this host; dry run skipped"
fi

step "notification muting, beats, disk analysis and cleanup"
R=$(api PUT "/hosts/$HID/notify" '{"metric":"bruteforce","notify":false}')
expect "failed-login notifications can be muted" '.notify == false' "$R"
expect "security view reports muted" '.notify_failed_logins == false' "$(api GET "/hosts/$HID/security")"
api PUT "/hosts/$HID/notify" '{"metric":"bruteforce","notify":true}' >/dev/null
expect "host beats cover 30 days" ".\"$HID\" | length == 30" "$(api GET '/hosts/beats?days=30')"
expect "check beats endpoint answers" 'type == "object"' "$(api GET '/checks/beats?limit=10')"
DU=$(api POST "/hosts/$HID/disk-usage" '{"mount":"/"}' | jq -r .job_id)
wait_for "disk analysis finished" 300 job_done "$DU" succeeded
expect "disk report lists directories" '.status == "done" and (.entries | length) > 0 and .used_bytes > 0' "$(api GET "/hosts/$HID/disk-usage?mount=/")"
R=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"disk_cleanup\",\"params\":{\"tasks\":\"journal,tmp\"},\"dry_run\":true}")
expect "cleanup refused without host opt-in" '.code == "forbidden"' "$R"
R=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"disk_cleanup\",\"params\":{\"tasks\":\"journal;rm\"},\"dry_run\":true}")
expect "cleanup rejects unknown tasks" '.code != null' "$R"
api PUT "/hosts/$HID" '{"allow_cleanup":true}' >/dev/null
CJ=$(api POST /jobs "{\"host_id\":$HID,\"type\":\"disk_cleanup\",\"params\":{\"tasks\":\"pkg_cache,journal,tmp,logs\"},\"dry_run\":true}" | jq -r .id)
wait_for "cleanup dry run succeeded" 300 job_done "$CJ" succeeded
expect "cleanup dry run reports reclaimable bytes" '.output | test("freed_bytes=[0-9]+")' "$(api GET "/jobs/$CJ")"
api PUT "/hosts/$HID" '{"allow_cleanup":false}' >/dev/null

step "status page, metrics endpoint, backup, audit"
SP=$(api POST /status-pages "{\"slug\":\"e2e-status\",\"title\":\"E2E\",\"public\":true,\"items\":[{\"type\":\"check\",\"id\":$C_HTTP,\"label\":\"API\"}]}")
PUB=$(curl -s "$URL/api/v1/public/status/e2e-status")
expect "public status page works without login" '.items[0].label == "API" and .overall != null' "$PUB"
api DELETE "/status-pages/$(echo "$SP" | jq -r .id)" >/dev/null
curl -s -b "$JAR" "$URL/metrics" | grep -q '^sentrel_cpu_usage_percent{' && ok "/metrics exposes host series" || bad "/metrics missing host series"
curl -s -b "$JAR" -o /tmp/e2e-backup.tgz "$URL/api/v1/server/backup"
LIST=$(tar tzf /tmp/e2e-backup.tgz) # not piped into grep -q: SIGPIPE + pipefail
grep -qx 'sentrel.db' <<<"$LIST" && grep -qx 'pki/ca.key' <<<"$LIST" && ok "backup contains database and PKI" || bad "backup incomplete"
rm -f /tmp/e2e-backup.tgz
AUD=$(api GET "/audit?q=job.created&limit=5")
expect "jobs are audited" 'length > 0' "$AUD"

step "agent install hub (packages) and removed push install"
II=$(api GET /agents/install-info)
expect "install-info lists server url, tls mode and version" '.server_url != null and .tls_mode != null and (.version | length) > 0' "$II"
expect "install-info spki only in selfsigned mode" '(.tls_mode == "selfsigned") == ((.spki_sha256 | length) > 0)' "$II"
NPK=$(echo "$II" | jq '.packages | length')
if [ "$NPK" -gt 0 ]; then
  ok "install-info lists $NPK packages"
  while IFS=$'\t' read -r PF PSZ PSHA PURL; do
    PTMP=$(mktemp)
    curl -s -o "$PTMP" -D "$PTMP.h" "$URL/download/agent/pkg/$PF"
    GOT_SZ=$(stat -c %s "$PTMP"); GOT_SHA=$(sha256sum "$PTMP" | cut -d' ' -f1)
    [ "$GOT_SZ" = "$PSZ" ] && [ "$GOT_SHA" = "$PSHA" ] && grep -qi '^content-disposition: attachment' "$PTMP.h" \
      && ok "package $PF: size and sha256 match the manifest" || bad "package $PF: size $GOT_SZ/$PSZ sha256 $GOT_SHA/$PSHA"
    rm -f "$PTMP" "$PTMP.h"
  done < <(echo "$II" | jq -r '.packages[] | [.file, .size, .sha256, .url] | @tsv')
  expect "install-info covers deb, rpm and msi" '([.packages[].format] | unique) as $f | ($f | index("deb")) != null and ($f | index("rpm")) != null and ($f | index("msi")) != null' "$II"
else
  ok "no packages embedded in this build (nfpm/wixl missing); skipped downloads"
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$URL/download/agent/pkg/not-in-the-manifest.deb")
[ "$CODE" = 404 ] && ok "unknown package file is 404" || bad "unknown package file returned $CODE"
for pp in "GET /push" "POST /push/ssh" "POST /push/winrm" "POST /push/ssh/fingerprint"; do
  set -- $pp
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -X "$1" -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" "$URL/api/v1$2" -d '{}')
  [ "$CODE" = 404 ] && ok "$1 $2 is gone (404)" || bad "$1 $2 returned $CODE"
done

step "port-scan detection (kernel rules, docker nmap scan from the bridge network)"
SEC=$(api GET "/hosts/$HID/security")
expect "port-scan status reported by the agent" '.portscan_status.known == true' "$SEC"
if echo "$SEC" | jq -e '.portscan_status.supported == true and .portscan_status.active == true' >/dev/null; then
  ok "port-scan detection is active on this host"
  nft_chain() { sudo nft list chain inet sentrel scan | grep -q "update @scanners4"; }
  wait_for "detection chain installed" 30 nft_chain
  if sudo nft list chain inet sentrel scan | grep -qiE '(drop|reject)'; then bad "detection chain must not drop traffic"; else ok "detection chain never drops traffic"; fi
  expect "scan notification toggle works" '.notify == false' "$(api PUT "/hosts/$HID/notify" '{"metric":"portscan","notify":false}')"
  api PUT "/hosts/$HID/notify" '{"metric":"portscan","notify":true}' >/dev/null
  if command -v docker >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    BRIP=$(ip -4 -o addr show docker0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    if [ -n "$BRIP" ]; then
      HAD_IMG=$(sudo docker image ls -q alpine | head -1)
      # Forget earlier scanners so the agent sees this scan as new (it polls every 30 s).
      sudo nft flush set inet sentrel scanners4 2>/dev/null; sleep 35
      T0=$(date +%s)
      SCANOUT=$(sudo docker run --rm alpine sh -c "apk add -q nmap >/dev/null 2>&1 && nmap -Pn -n -p 1-200 --max-retries 0 $BRIP" 2>&1 | tail -3)
      ok "nmap scan of $BRIP from a container finished"
      scan_seen() { api GET "/hosts/$HID/security" | jq -e --argjson t0 "$T0" '[.portscans[] | select(.last_seen >= $t0 - 5)] | length > 0' >/dev/null; }
      wait_for "port scan reported by the agent" 150 scan_seen
      SEC=$(api GET "/hosts/$HID/security")
      expect "scanner is a docker bridge address" "[.portscans[] | select(.last_seen >= $T0 - 5)][0].ip | (startswith(\"172.\") or startswith(\"10.\") or startswith(\"192.168.\"))" "$SEC"
      scan_alert() { api GET /alerts | jq -e '[.. | objects | select(.metric? == "portscan")] | length > 0' >/dev/null; }
      wait_for "port-scan alert raised" 30 scan_alert
      [ -z "$HAD_IMG" ] && sudo docker rmi alpine >/dev/null 2>&1
    else
      ok "no docker0 bridge; container scan skipped"
    fi
  else
    ok "docker not available; container scan skipped"
  fi
else
  ok "port-scan detection unsupported here ($(echo "$SEC" | jq -r .portscan_status.reason)); scan skipped"
fi

step "cleanup"
for c in $C_PING $C_TCP_UP $C_TCP_DOWN $C_HTTP $C_CERT $C_DNS $C_SVC $C_PORT $C_PROC $C_CONT $C_MISSING $C_FLIP; do api DELETE "/checks/$c" >/dev/null; done
api DELETE "/notification-channels/$CH" >/dev/null
kill $HOOK_PID 2>/dev/null
rm -f "$HOOK_LOG"
ok "removed e2e objects"

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
