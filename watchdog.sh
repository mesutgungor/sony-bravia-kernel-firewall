#!/bin/zsh
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
# Automatic Watchdog to keep BraviaKernelDaemon (Kernel eBPF + Web Dashboard) alive after cold TV power cycles

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
ADB="$SDK/platform-tools/adb"

# 1. Check if local ADB port-forwarded Web Dashboard is already responding with ebpfEnabled=true
if curl -s --max-time 2 "http://127.0.0.1:8899/api/state" | grep -q '"ebpfEnabled":true'; then
  exit 0
fi

# 2. If TV is connected over ADB, ensure BraviaKernelDaemon and BraviaTunVpnService are running
if "$ADB" get-state >/dev/null 2>&1; then
  "$ADB" shell "
    if ! pgrep -f '[B]raviaKernelDaemon' >/dev/null 2>&1; then
      CLASSPATH=/data/local/tmp/bravia_fw/bravia_daemon.dex nohup app_process /system/bin BraviaKernelDaemon >/data/local/tmp/bravia_fw/daemon.log 2>&1 </dev/null &
    fi
    am startservice -a com.bravia.firewall.START_VPN com.bravia.firewall/.BraviaTunVpnService >/dev/null 2>&1 || true
  " >/dev/null 2>&1
  "$ADB" forward tcp:8899 tcp:8899 >/dev/null 2>&1 || true
fi
