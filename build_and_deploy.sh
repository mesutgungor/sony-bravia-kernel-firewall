#!/bin/zsh
set -e

# Locate JDK (Java 17+)
if [ -z "$JAVA_HOME" ]; then
  if [ -d "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" ]; then
    export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
  elif [ -d "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home" ]; then
    export JAVA_HOME="/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"
  fi
fi
[ -n "$JAVA_HOME" ] && export PATH="$JAVA_HOME/bin:$PATH"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
BT_VERSION=$(ls -1 "$SDK/build-tools" | sort -V | tail -n 1)
BT="$SDK/build-tools/$BT_VERSION"
PLATFORM="$SDK/platforms/android-34/android.jar"
ADB="$SDK/platform-tools/adb"

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD/apk_classes" "$BUILD/daemon_classes" "$BUILD/gen"

echo "[1/6] Compiling Android TV /dev/tun Firewall APK (com.bravia.firewall)..."
"$BT/aapt2" compile --dir "$ROOT/apk/res" -o "$BUILD/res.zip"
"$BT/aapt2" link -o "$BUILD/unaligned.apk" \
  -I "$PLATFORM" \
  --manifest "$ROOT/apk/AndroidManifest.xml" \
  --java "$BUILD/gen" \
  "$BUILD/res.zip"

javac -source 11 -target 11 -classpath "$PLATFORM" \
  -d "$BUILD/apk_classes" \
  "$BUILD/gen/com/bravia/firewall/R.java" \
  "$ROOT/apk/src/com/bravia/firewall/BraviaTunVpnService.java" \
  "$ROOT/apk/src/com/bravia/firewall/BootReceiver.java" \
  "$ROOT/apk/src/com/bravia/firewall/MainActivity.java"

"$BT/d8" --lib "$PLATFORM" --output "$BUILD" "$BUILD/apk_classes/com/bravia/firewall/"*.class

cd "$BUILD"
zip -q -u unaligned.apk classes.dex
"$BT/zipalign" -f 4 unaligned.apk aligned.apk

if [ ! -f "$BUILD/debug.keystore" ]; then
  keytool -genkeypair -v -keystore "$BUILD/debug.keystore" -storepass android -alias androiddebugkey \
    -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
fi

"$BT/apksigner" sign --ks "$BUILD/debug.keystore" --ks-pass pass:android --key-pass pass:android \
  --out "$BUILD/bravia-firewall.apk" aligned.apk

echo "[2/6] Compiling Privileged Kernel eBPF & Socket Daemon (BraviaKernelDaemon)..."
javac -source 17 -target 17 -classpath "$PLATFORM" \
  -d "$BUILD/daemon_classes" \
  "$ROOT/daemon/src/DashboardHtml.java" \
  "$ROOT/daemon/src/BraviaKernelDaemon.java"

"$BT/d8" --lib "$PLATFORM" --output "$BUILD/daemon_classes" "$BUILD/daemon_classes/"*.class
mv "$BUILD/daemon_classes/classes.dex" "$BUILD/bravia_daemon.dex"

echo "[3/6] Installing com.bravia.firewall APK & configuring Always-On Persistence on TV..."
"$ADB" install -r "$BUILD/bravia-firewall.apk"
"$ADB" shell "
cmd appops set com.bravia.firewall ACTIVATE_VPN allow
cmd appops set com.bravia.firewall ACTIVATE_PLATFORM_VPN allow
cmd appops set com.bravia.firewall RUN_IN_BACKGROUND allow
cmd appops set com.bravia.firewall RUN_ANY_IN_BACKGROUND allow
dumpsys deviceidle whitelist +com.bravia.firewall >/dev/null 2>&1 || true
settings put secure always_on_vpn_app com.bravia.firewall
settings put secure always_on_vpn_lockdown 0
"

echo "[4/6] Extracting live UID/Package table & pushing BraviaKernelDaemon to TV..."
"$ADB" shell "pm list packages -U -f" | python3 -c '
import sys, re

uid_map = {}
for line in sys.stdin:
    line = line.strip()
    m = re.match(r"^package:(.+)=([^\s=]+)\s+uid:(\d+)$", line)
    if m:
        path, pkg, uid = m.group(1), m.group(2), int(m.group(3))
        is_sys = "1" if (path.startswith("/system/") or path.startswith("/vendor/") or path.startswith("/product/") or path.startswith("/apex/")) else "0"
        uid_map.setdefault(uid, []).append((pkg, is_sys))

print("0\troot (Linux Kernel/Netd)\t1\t1")
print("1051\tdnsproxyd (Android DNS Proxy)\t1\t1")
for uid in sorted(uid_map.keys()):
    items = uid_map[uid]
    pkgs = ",".join(x[0] for x in items)
    if len(pkgs) > 120:
        pkgs = ",".join(x[0] for x in items[:3]) + f" (+{len(items)-3} more)"
    is_sys = items[0][1]
    print(f"{uid}\t{pkgs}\t{is_sys}\t1")
' > "$BUILD/packages.tsv"

"$ADB" shell "mkdir -p /data/local/tmp/bravia_fw"
"$ADB" push "$BUILD/packages.tsv" /data/local/tmp/bravia_fw/packages.tsv
"$ADB" push "$BUILD/bravia_daemon.dex" /data/local/tmp/bravia_fw/bravia_daemon.dex

echo "[5/6] Starting BraviaKernelDaemon (uid=2000) & /dev/tun VPN Service on TV..."
"$ADB" shell "pkill -f '[B]raviaKernelDaemon' 2>/dev/null || true"
"$ADB" shell "CLASSPATH=/data/local/tmp/bravia_fw/bravia_daemon.dex nohup app_process /system/bin BraviaKernelDaemon >/data/local/tmp/bravia_fw/daemon.log 2>&1 </dev/null &"
sleep 2
"$ADB" shell "am start -n com.bravia.firewall/.MainActivity --ez auto_start true"
sleep 2

echo "[6/6] Forwarding local port 8899 -> TV:8899..."
"$ADB" forward tcp:8899 tcp:8899

echo "Deployment complete! Open http://localhost:8899 in your browser."
