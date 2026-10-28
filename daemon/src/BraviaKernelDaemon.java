import android.os.IBinder;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class BraviaKernelDaemon {
    private static final int FIREWALL_CHAIN_STANDBY = 2; // Denylist eBPF chain in BpfNetMaps
    private static final int FIREWALL_RULE_DEFAULT = 0;  // ALLOW in STANDBY chain
    private static final int FIREWALL_RULE_DENY = 2;     // DENY in STANDBY chain

    private static final int UDP_IPC_PORT = 8898;
    private static final int HTTP_PORT = 8899;
    private static final String BASE_DIR = "/data/local/tmp/bravia_fw";
    private static final String PACKAGES_FILE = BASE_DIR + "/packages.tsv";
    private static final String RULES_FILE = BASE_DIR + "/rules.conf";

    // Kernel eBPF Binder handle (IConnectivityManager) + Persistent Policy (INetworkPolicyManager)
    private static Object connectivityManager;
    private static Method setChainEnabledMethod;
    private static Method getChainEnabledMethod;
    private static Method setUidRuleMethod;
    private static Method getUidRuleMethod;
    private static Object netPolicyManager;
    private static Method addUidPolicyMethod;
    private static Method removeUidPolicyMethod;
    private static volatile boolean ebpfEnabled = false;
    private static volatile String tunStatus = "STARTING";

    // Package metadata
    static class AppInfo {
        final int uid;
        final String pkg;
        final boolean system;
        final boolean hasInternet;
        final boolean protectedUid;
        final AtomicInteger eventsCount = new AtomicInteger(0);
        volatile int activeSockets = 0;

        AppInfo(int uid, String pkg, boolean system, boolean hasInternet, boolean protectedUid) {
            this.uid = uid;
            this.pkg = pkg;
            this.system = system;
            this.hasInternet = hasInternet;
            this.protectedUid = protectedUid;
        }
    }

    static class EgressEvent {
        final long id;
        final String time;
        final String verdict;
        final int uid;
        final String pkg;
        final String proto;
        final String domain;
        final String dstIp;
        final int dstPort;

        EgressEvent(long id, String time, String verdict, int uid, String pkg, String proto, String domain, String dstIp, int dstPort) {
            this.id = id;
            this.time = time;
            this.verdict = verdict;
            this.uid = uid;
            this.pkg = pkg;
            this.proto = proto;
            this.domain = domain;
            this.dstIp = dstIp;
            this.dstPort = dstPort;
        }
    }

    static class AlertItem {
        final long id;
        final String time;
        final String type;
        final boolean blocked;
        final int uid;
        final String pkg;
        final String proto;
        final String domain;
        final String dstIp;
        final int dstPort;

        AlertItem(long id, String time, String type, boolean blocked, int uid, String pkg, String proto, String domain, String dstIp, int dstPort) {
            this.id = id;
            this.time = time;
            this.type = type;
            this.blocked = blocked;
            this.uid = uid;
            this.pkg = pkg;
            this.proto = proto;
            this.domain = domain;
            this.dstIp = dstIp;
            this.dstPort = dstPort;
        }
    }

    static class DnsEntry {
        final String time;
        final String domain;
        final String ips;
        final boolean blocked;

        DnsEntry(String time, String domain, String ips, boolean blocked) {
            this.time = time;
            this.domain = domain;
            this.ips = ips;
            this.blocked = blocked;
        }
    }

    static class KernelSocket {
        final int uid;
        final String pkg;
        final String proto;
        final String localIp;
        final int localPort;
        final String remoteIp;
        final int remotePort;
        final String state;
        final String domain;

        KernelSocket(int uid, String pkg, String proto, String localIp, int localPort, String remoteIp, int remotePort, String state, String domain) {
            this.uid = uid;
            this.pkg = pkg;
            this.proto = proto;
            this.localIp = localIp;
            this.localPort = localPort;
            this.remoteIp = remoteIp;
            this.remotePort = remotePort;
            this.state = state;
            this.domain = domain;
        }
    }

    private static final Map<Integer, AppInfo> appsByUid = new ConcurrentHashMap<>();
    private static final Set<Integer> blockedUids = ConcurrentHashMap.newKeySet();
    private static final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private static final Set<String> blockedIps = ConcurrentHashMap.newKeySet();

    private static final Map<String, String> ipToDomain = new ConcurrentHashMap<>();
    private static final List<EgressEvent> recentEvents = new CopyOnWriteArrayList<>();
    private static final List<AlertItem> activeAlerts = new CopyOnWriteArrayList<>();
    private static final List<DnsEntry> dnsLog = new CopyOnWriteArrayList<>();
    private static volatile List<KernelSocket> currentSockets = new ArrayList<>();

    private static final Map<String, Long> seenFlows = new ConcurrentHashMap<>();
    private static final Set<String> alertedAppTargets = ConcurrentHashMap.newKeySet();
    private static final AtomicLong eventSeq = new AtomicLong(1);
    private static final AtomicLong totalEventsCount = new AtomicLong(0);
    private static final AtomicLong totalBlockedCount = new AtomicLong(0);
    private static volatile int firewallAppUid = -1;

    public static void main(String[] args) throws Exception {
        System.out.println("==========================================================");
        System.out.println("Sony Bravia Hybrid Kernel Egress Application Firewall");
        System.out.println("Starting BraviaKernelDaemon (uid=" + android.os.Process.myUid() + ")...");
        System.out.println("==========================================================");

        loadPackages();
        initKernelEbpfBridge();
        loadOrInitRules();
        syncAllEbpfRulesToKernel();

        Thread udpThread = new Thread(BraviaKernelDaemon::runUdpIpcServer, "UdpIpcServer");
        udpThread.setDaemon(true);
        udpThread.start();

        Thread procScannerThread = new Thread(BraviaKernelDaemon::runProcNetScanner, "ProcNetScanner");
        procScannerThread.setDaemon(true);
        procScannerThread.start();

        runHttpServer();
    }

    private static void loadPackages() {
        // Detect com.bravia.firewall UID if installed
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "pm list packages -U com.bravia.firewall"});
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line = br.readLine();
                if (line != null && line.contains("uid:")) {
                    firewallAppUid = Integer.parseInt(line.substring(line.indexOf("uid:") + 4).trim());
                    appsByUid.put(firewallAppUid, new AppInfo(firewallAppUid, "com.bravia.firewall (Firewall TUN Service)", false, true, true));
                }
            }
        } catch (Exception ignored) {}

        File f = new File(PACKAGES_FILE);
        if (!f.exists()) return;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split("\t");
                if (parts.length >= 4) {
                    int uid = Integer.parseInt(parts[0].trim());
                    String pkg = parts[1].trim();
                    boolean sys = "1".equals(parts[2].trim());
                    boolean net = "1".equals(parts[3].trim());
                    boolean prot = uid < 10000 || uid == firewallAppUid || pkg.contains("com.bravia.firewall");
                    appsByUid.put(uid, new AppInfo(uid, pkg, sys, net, prot));
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading packages.tsv: " + e);
        }
    }

    private static void initKernelEbpfBridge() {
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method getService = sm.getMethod("getService", String.class);
            IBinder cb = (IBinder) getService.invoke(null, "connectivity");
            connectivityManager = Class.forName("android.net.IConnectivityManager$Stub")
                    .getMethod("asInterface", IBinder.class)
                    .invoke(null, cb);

            Class<?> cmClass = connectivityManager.getClass();
            setChainEnabledMethod = cmClass.getMethod("setFirewallChainEnabled", int.class, boolean.class);
            getChainEnabledMethod = cmClass.getMethod("getFirewallChainEnabled", int.class);
            setUidRuleMethod = cmClass.getMethod("setUidFirewallRule", int.class, int.class, int.class);
            getUidRuleMethod = cmClass.getMethod("getUidFirewallRule", int.class, int.class);

            setChainEnabledMethod.invoke(connectivityManager, FIREWALL_CHAIN_STANDBY, true);
            ebpfEnabled = (Boolean) getChainEnabledMethod.invoke(connectivityManager, FIREWALL_CHAIN_STANDBY);
            System.out.println("[eBPF] Kernel BpfNetMaps STANDBY Chain (2) enabled = " + ebpfEnabled);

            IBinder npb = (IBinder) getService.invoke(null, "netpolicy");
            if (npb != null) {
                netPolicyManager = Class.forName("android.net.INetworkPolicyManager$Stub")
                        .getMethod("asInterface", IBinder.class)
                        .invoke(null, npb);
                addUidPolicyMethod = netPolicyManager.getClass().getMethod("addUidPolicy", int.class, int.class);
                removeUidPolicyMethod = netPolicyManager.getClass().getMethod("removeUidPolicy", int.class, int.class);
            }
        } catch (Throwable t) {
            System.err.println("[eBPF] Failed to initialize IConnectivityManager bridge: " + t);
        }
    }

    private static void loadOrInitRules() {
        File rf = new File(RULES_FILE);
        if (!rf.exists()) {
            // Recommended Default Policy: Default Allow + Pre-block known telemetry, voice/mic, ACR, and ad services
            int[] defaultBlockedUids = new int[]{
                10062, // com.google.android.tv.remote.service (BLE Remote Mic Service)
                10084, // com.google.android.katniss (Google Assistant / Hotword)
                10148, // com.sony.dtv.voicesearch (Sony Voice Search)
                10144, // com.sony.dtv.seeds.iot (Sony SEEDS IoT Telemetry)
                10166, // com.sony.dtv.seeds.auth (Sony SEEDS Auth Telemetry)
                10063, // tv.samba.ssm (Samba TV ACR Tracking)
                10262, // tv.samba.ssm.ui (Samba TV UI)
                10290, // com.android.adservices.api (Android AdServices)
                10291, // com.android.sdksandbox (Advertising SDK Sandbox)
                10154, // com.google.android.feedback (Google Feedback Telemetry)
                10053  // com.sony.dtv.customersupport (Sony Customer Support Telemetry)
            };
            for (int u : defaultBlockedUids) {
                blockedUids.add(u);
            }

            String[] defaultBlockedDomains = new String[]{
                "*.samba.tv",
                "*.flingo.tv",
                "*.sambaa.com",
                "*.doubleclick.net",
                "*.googleadservices.com",
                "*.googlesyndication.com",
                "*.app-measurement.com",
                "*.google-analytics.com",
                "ssm1.internet.sony.tv",
                "ssm2.internet.sony.tv",
                "ssm3.internet.sony.tv",
                "*.ndmdhs.com",
                "*.idd.sony.net",
                "reg.biv.sony.tv"
            };
            Collections.addAll(blockedDomains, defaultBlockedDomains);
            saveRules();
            return;
        }

        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(rf), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("UID|")) {
                    int u = Integer.parseInt(line.substring(4));
                    if (u >= 10000 && u != firewallAppUid) blockedUids.add(u);
                } else if (line.startsWith("DOMAIN|")) {
                    blockedDomains.add(line.substring(7).toLowerCase());
                } else if (line.startsWith("IP|")) {
                    blockedIps.add(line.substring(3));
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading rules.conf: " + e);
        }
    }

    private static synchronized void saveRules() {
        try {
            File dir = new File(BASE_DIR);
            if (!dir.exists()) dir.mkdirs();
            StringBuilder sb = new StringBuilder();
            for (int u : blockedUids) sb.append("UID|").append(u).append("\n");
            for (String d : blockedDomains) sb.append("DOMAIN|").append(d).append("\n");
            for (String ip : blockedIps) sb.append("IP|").append(ip).append("\n");
            try (FileOutputStream fos = new FileOutputStream(RULES_FILE)) {
                fos.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            System.err.println("Error saving rules.conf: " + e);
        }
    }

    private static void syncAllEbpfRulesToKernel() {
        if (connectivityManager == null) return;
        try {
            setChainEnabledMethod.invoke(connectivityManager, FIREWALL_CHAIN_STANDBY, true);
            ebpfEnabled = (Boolean) getChainEnabledMethod.invoke(connectivityManager, FIREWALL_CHAIN_STANDBY);
            for (int uid : blockedUids) {
                applyKernelEbpfUidRule(uid, true);
            }
            System.out.println("[eBPF] Synced " + blockedUids.size() + " blocked UIDs into Kernel BpfNetMaps.");
        } catch (Throwable t) {
            System.err.println("[eBPF] Error syncing rules: " + t);
        }
    }

    private static synchronized boolean applyKernelEbpfUidRule(int uid, boolean block) {
        if (uid < 10000 || uid == firewallAppUid) {
            System.out.println("[eBPF] Refusing to block protected core UID " + uid);
            return false;
        }
        try {
            if (connectivityManager != null && setUidRuleMethod != null) {
                int rule = block ? FIREWALL_RULE_DENY : FIREWALL_RULE_DEFAULT;
                setUidRuleMethod.invoke(connectivityManager, FIREWALL_CHAIN_STANDBY, uid, rule);
            }
            if (netPolicyManager != null) {
                try {
                    if (block && addUidPolicyMethod != null) {
                        addUidPolicyMethod.invoke(netPolicyManager, uid, 1); // POLICY_REJECT_METERED_BACKGROUND persisted to /data/system/netpolicy.xml
                    } else if (!block && removeUidPolicyMethod != null) {
                        removeUidPolicyMethod.invoke(netPolicyManager, uid, 1);
                    }
                } catch (Throwable ignored) {}
            }
            if (block) {
                blockedUids.add(uid);
            } else {
                blockedUids.remove(uid);
            }
            saveRules();
            return true;
        } catch (Throwable t) {
            System.err.println("[eBPF] Failed to set rule for uid " + uid + ": " + t);
            return false;
        }
    }

    private static void triggerVpnReload() {
        try {
            Runtime.getRuntime().exec(new String[]{
                "sh", "-c", "am startservice -a com.bravia.firewall.RELOAD_VPN com.bravia.firewall/.BraviaTunVpnService >/dev/null 2>&1 &"
            });
        } catch (Exception ignored) {}
    }

    private static void runUdpIpcServer() {
        try (DatagramSocket sock = new DatagramSocket(UDP_IPC_PORT, InetAddress.getByName("127.0.0.1"))) {
            byte[] buf = new byte[8192];
            while (true) {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                sock.receive(dp);
                String msg = new String(buf, 0, dp.getLength(), StandardCharsets.UTF_8).trim();
                handleTunIpcMessage(msg);
            }
        } catch (Throwable t) {
            System.err.println("UDP IPC server error: " + t);
        }
    }

    private static void handleTunIpcMessage(String msg) {
        try {
            String[] parts = msg.split("\\|");
            if (parts.length == 0) return;
            String type = parts[0];

            if ("TUN_STATUS".equals(type) && parts.length >= 2) {
                tunStatus = parts[1];
            } else if ("DNS_ALLOW".equals(type) && parts.length >= 4) {
                tunStatus = "ACTIVE (tun0)";
                int uid = parseIntSafe(parts[1], -1);
                String domain = parts[2].toLowerCase();
                String ipsCsv = parts[3];
                if (!"-".equals(ipsCsv)) {
                    for (String ip : ipsCsv.split(",")) {
                        ip = ip.trim();
                        if (!ip.isEmpty()) {
                            ipToDomain.put(ip, domain);
                        }
                    }
                }
                addDnsLogEntry(domain, ipsCsv, false);
            } else if ("DNS_BLOCK".equals(type) && parts.length >= 4) {
                int uid = parseIntSafe(parts[1], -1);
                String domain = parts[2].toLowerCase();
                String trapIp = parts[3];
                ipToDomain.put(trapIp, domain);
                addDnsLogEntry(domain, trapIp + " (Sinkhole)", true);
                totalBlockedCount.incrementAndGet();
                recordEgressEvent("BLOCKED (TUN DNS)", uid > 0 ? uid : 1051, "UDP/DNS", domain, trapIp, 53, true);
            } else if ("TUN_BLOCK".equals(type) && parts.length >= 7) {
                int uid = parseIntSafe(parts[1], -1);
                String proto = parts[2];
                String dstIp = parts[3];
                int dstPort = parseIntSafe(parts[4], 0);
                String domain = parts[5];
                String sni = parts[6];
                if ((domain == null || "-".equals(domain)) && sni != null && !"-".equals(sni)) {
                    domain = sni;
                } else if (sni != null && !"-".equals(sni) && !sni.equalsIgnoreCase(domain)) {
                    domain = domain + " [SNI: " + sni + "]";
                }
                if ("-".equals(domain)) {
                    domain = ipToDomain.getOrDefault(dstIp, "-");
                }
                totalBlockedCount.incrementAndGet();
                String verdict = sni != null && !"-".equals(sni) ? "BLOCKED (TUN SNI)" : "BLOCKED (TUN Packet)";
                recordEgressEvent(verdict, uid, proto, domain, dstIp, dstPort, true);
            }
        } catch (Throwable ignored) {}
    }

    private static void addDnsLogEntry(String domain, String ips, boolean blocked) {
        dnsLog.add(0, new DnsEntry(nowTime(), domain, ips, blocked));
        while (dnsLog.size() > 150) {
            dnsLog.remove(dnsLog.size() - 1);
        }
    }

    private static void recordEgressEvent(String verdict, int uid, String proto, String domain, String dstIp, int dstPort, boolean isBlocked) {
        String pkg = getPkgName(uid);
        long id = eventSeq.getAndIncrement();
        String t = nowTime();
        EgressEvent ev = new EgressEvent(id, t, verdict, uid, pkg, proto, domain, dstIp, dstPort);
        recentEvents.add(0, ev);
        while (recentEvents.size() > 250) {
            recentEvents.remove(recentEvents.size() - 1);
        }
        totalEventsCount.incrementAndGet();

        AppInfo ai = appsByUid.get(uid);
        if (ai != null) {
            ai.eventsCount.incrementAndGet();
        }

        String targetKey = uid + "|" + (!"-".equals(domain) ? domain : dstIp);
        if (isBlocked || alertedAppTargets.add(targetKey)) {
            String alertType = isBlocked ? verdict : "NEW EGRESS";
            activeAlerts.add(0, new AlertItem(id, t, alertType, isBlocked, uid, pkg, proto, domain, dstIp, dstPort));
            while (activeAlerts.size() > 30) {
                activeAlerts.remove(activeAlerts.size() - 1);
            }
        }
    }

    private static void runProcNetScanner() {
        int cycle = 0;
        while (true) {
            try {
                if (++cycle % 10 == 0 && connectivityManager != null && getChainEnabledMethod != null) {
                    boolean chainActive = (Boolean) getChainEnabledMethod.invoke(connectivityManager, FIREWALL_CHAIN_STANDBY);
                    if (!chainActive) {
                        System.out.println("[eBPF Watchdog] Re-enabling STANDBY Chain (2) after standby/wake transition...");
                        syncAllEbpfRulesToKernel();
                    }
                }
                List<KernelSocket> list = new ArrayList<>();
                Map<Integer, Integer> countsByUid = new HashMap<>();
                long now = System.currentTimeMillis();

                scanProcFile("/proc/net/tcp", "TCP", false, list, countsByUid, now);
                scanProcFile("/proc/net/tcp6", "TCP6", true, list, countsByUid, now);
                scanProcFile("/proc/net/udp", "UDP", false, list, countsByUid, now);
                scanProcFile("/proc/net/udp6", "UDP6", true, list, countsByUid, now);

                if (new File("/sys/class/net/tun0").exists()) {
                    tunStatus = "ACTIVE (tun0)";
                }

                for (AppInfo ai : appsByUid.values()) {
                    ai.activeSockets = countsByUid.getOrDefault(ai.uid, 0);
                }
                currentSockets = list;

                // Clean up old flow dedup entries (> 45s)
                seenFlows.entrySet().removeIf(e -> (now - e.getValue()) > 45000L);

                Thread.sleep(300);
            } catch (Throwable t) {
                try { Thread.sleep(1000); } catch (InterruptedException ignored) {}
            }
        }
    }

    private static void scanProcFile(
            String path, String proto, boolean ipv6,
            List<KernelSocket> outList, Map<Integer, Integer> countsByUid, long now) {
        File f = new File(path);
        if (!f.exists()) return;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.US_ASCII))) {
            String line = br.readLine(); // skip header
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] cols = line.split("\\s+");
                if (cols.length < 8) continue;

                String[] localParts = cols[1].split(":");
                String[] remParts = cols[2].split(":");
                if (localParts.length != 2 || remParts.length != 2) continue;

                String localIp = parseProcHexIp(localParts[0], ipv6);
                int localPort = Integer.parseInt(localParts[1], 16);
                String remIp = parseProcHexIp(remParts[0], ipv6);
                int remPort = Integer.parseInt(remParts[1], 16);
                int stateCode = Integer.parseInt(cols[3], 16);
                int uid = parseIntSafe(cols[7], -1);

                // Skip listening/unconnected or loopback/LAN-management sockets, or orphaned TIME_WAIT sockets (uid=0)
                if (remPort == 0 || isIgnoredAddress(remIp) || localPort == HTTP_PORT || localPort == UDP_IPC_PORT) {
                    continue;
                }
                if (uid == 2000 && remIp.startsWith("192.168.")) {
                    continue;
                }
                if (uid == 0 && (stateCode == 6 || stateCode == 5 || stateCode == 7)) {
                    continue;
                }

                String state = tcpStateName(stateCode, proto);
                String pkg = getPkgName(uid);
                String domain = ipToDomain.getOrDefault(remIp, "-");

                outList.add(new KernelSocket(uid, pkg, proto, localIp, localPort, remIp, remPort, state, domain));
                countsByUid.put(uid, countsByUid.getOrDefault(uid, 0) + 1);

                String flowKey = uid + "|" + proto + "|" + remIp + ":" + remPort;
                Long prev = seenFlows.put(flowKey, now);
                if (prev == null) {
                    boolean isUidBlocked = blockedUids.contains(uid);
                    boolean isIpBlocked = blockedIps.contains(remIp);
                    boolean isTrapIp = remIp.startsWith("10.254.");
                    boolean blocked = isUidBlocked || isIpBlocked || isTrapIp;
                    String verdict = isTrapIp ? "BLOCKED (TUN Sinkhole)"
                            : isUidBlocked ? "BLOCKED (Kernel eBPF)"
                            : isIpBlocked ? "BLOCKED (TUN IP)"
                            : "ALLOWED";
                    if (blocked) {
                        totalBlockedCount.incrementAndGet();
                    }
                    recordEgressEvent(verdict, uid, proto, domain, remIp, remPort, blocked);
                }
            }
        } catch (Exception ignored) {}
    }

    private static boolean isIgnoredAddress(String ip) {
        if (ip == null || ip.isEmpty()) return true;
        if ("0.0.0.0".equals(ip) || "::".equals(ip) || "127.0.0.1".equals(ip) || "::1".equals(ip)) return true;
        if (ip.startsWith("127.") || ip.startsWith("fe80:") || ip.startsWith("ff0") || ip.startsWith("224.") || ip.startsWith("239.")) return true;
        if ("10.215.173.1".equals(ip) || "10.215.173.2".equals(ip)) return true;
        return false;
    }

    private static String parseProcHexIp(String hex, boolean ipv6) {
        try {
            if (!ipv6 && hex.length() == 8) {
                int b0 = Integer.parseInt(hex.substring(6, 8), 16);
                int b1 = Integer.parseInt(hex.substring(4, 6), 16);
                int b2 = Integer.parseInt(hex.substring(2, 4), 16);
                int b3 = Integer.parseInt(hex.substring(0, 2), 16);
                return b0 + "." + b1 + "." + b2 + "." + b3;
            } else if (ipv6 && hex.length() == 32) {
                // Check IPv4-mapped IPv6: 0000000000000000FFFF0000XXXXXXXX
                if (hex.regionMatches(true, 0, "0000000000000000FFFF0000", 0, 24)) {
                    String v4Hex = hex.substring(24, 32);
                    return parseProcHexIp(v4Hex, false);
                }
                if ("00000000000000000000000000000000".equals(hex)) {
                    return "::";
                }
                byte[] bytes = new byte[16];
                for (int word = 0; word < 4; word++) {
                    String w = hex.substring(word * 8, word * 8 + 8);
                    bytes[word * 4] = (byte) Integer.parseInt(w.substring(6, 8), 16);
                    bytes[word * 4 + 1] = (byte) Integer.parseInt(w.substring(4, 6), 16);
                    bytes[word * 4 + 2] = (byte) Integer.parseInt(w.substring(2, 4), 16);
                    bytes[word * 4 + 3] = (byte) Integer.parseInt(w.substring(0, 2), 16);
                }
                return InetAddress.getByAddress(bytes).getHostAddress();
            }
        } catch (Exception ignored) {}
        return hex;
    }

    private static String tcpStateName(int st, String proto) {
        if (proto.startsWith("UDP")) return st == 1 ? "ESTAB" : "ACTIVE";
        switch (st) {
            case 1: return "ESTABLISHED";
            case 2: return "SYN_SENT";
            case 3: return "SYN_RECV";
            case 4: return "FIN_WAIT1";
            case 5: return "FIN_WAIT2";
            case 6: return "TIME_WAIT";
            case 7: return "CLOSE";
            case 8: return "CLOSE_WAIT";
            case 9: return "LAST_ACK";
            case 10: return "LISTEN";
            case 11: return "CLOSING";
            default: return "STATE_" + st;
        }
    }

    private static String getPkgName(int uid) {
        if (uid < 0) return "unknown";
        AppInfo ai = appsByUid.get(uid);
        if (ai != null) return ai.pkg;
        return "uid:" + uid;
    }

    // Embedded HTTP Server for Real-Time Web Dashboard & API
    private static void runHttpServer() throws Exception {
        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress("0.0.0.0", HTTP_PORT));
        System.out.println("[HTTP] Web Dashboard listening on http://0.0.0.0:" + HTTP_PORT);

        while (true) {
            final Socket client = server.accept();
            Thread t = new Thread(() -> handleHttpClient(client));
            t.setDaemon(true);
            t.start();
        }
    }

    private static void handleHttpClient(Socket client) {
        try (Socket s = client;
             InputStream in = s.getInputStream();
             OutputStream out = s.getOutputStream()) {
            s.setSoTimeout(5000);
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String reqLine = br.readLine();
            if (reqLine == null || reqLine.isEmpty()) return;

            String[] reqParts = reqLine.split(" ");
            if (reqParts.length < 2) return;
            String method = reqParts[0];
            String path = reqParts[1];

            int contentLength = 0;
            String hdr;
            while ((hdr = br.readLine()) != null && !hdr.isEmpty()) {
                if (hdr.toLowerCase().startsWith("content-length:")) {
                    contentLength = parseIntSafe(hdr.substring(15).trim(), 0);
                }
            }

            String body = "";
            if (contentLength > 0 && contentLength < 65536) {
                char[] cbuf = new char[contentLength];
                int read = 0;
                while (read < contentLength) {
                    int n = br.read(cbuf, read, contentLength - read);
                    if (n < 0) break;
                    read += n;
                }
                body = new String(cbuf, 0, read);
            }

            if ("GET".equals(method) && ("/".equals(path) || path.startsWith("/index.html"))) {
                sendHttpResponse(out, 200, "text/html; charset=utf-8", DashboardHtml.HTML);
            } else if ("GET".equals(method) && path.startsWith("/api/state")) {
                sendHttpResponse(out, 200, "application/json; charset=utf-8", buildStateJson());
            } else if ("GET".equals(method) && path.startsWith("/api/tun-rules")) {
                sendHttpResponse(out, 200, "text/plain; charset=utf-8", buildTunRulesText());
            } else if ("POST".equals(method) && path.startsWith("/api/action")) {
                handleApiAction(body);
                sendHttpResponse(out, 200, "application/json; charset=utf-8", "{\"ok\":true}");
            } else {
                sendHttpResponse(out, 404, "text/plain; charset=utf-8", "Not Found");
            }
        } catch (Throwable ignored) {}
    }

    private static void handleApiAction(String formBody) {
        Map<String, String> params = new HashMap<>();
        for (String pair : formBody.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                try {
                    String k = URLDecoder.decode(pair.substring(0, eq), "UTF-8");
                    String v = URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
                    params.put(k, v);
                } catch (Exception ignored) {}
            }
        }
        String action = params.getOrDefault("action", "");
        if ("block_uid".equals(action)) {
            int uid = parseIntSafe(params.get("uid"), -1);
            if (uid >= 10000) applyKernelEbpfUidRule(uid, true);
        } else if ("allow_uid".equals(action)) {
            int uid = parseIntSafe(params.get("uid"), -1);
            if (uid >= 10000) applyKernelEbpfUidRule(uid, false);
        } else if ("block_domain".equals(action)) {
            String d = params.getOrDefault("domain", "").trim().toLowerCase();
            if (!d.isEmpty() && !"-".equals(d)) {
                if (d.contains(" ")) d = d.split(" ")[0];
                blockedDomains.add(d);
                saveRules();
            }
        } else if ("allow_domain".equals(action)) {
            String d = params.getOrDefault("domain", "").trim().toLowerCase();
            blockedDomains.remove(d);
            saveRules();
        } else if ("block_ip".equals(action)) {
            String ip = params.getOrDefault("ip", "").trim();
            if (!ip.isEmpty() && !ip.startsWith("192.168.") && !ip.startsWith("127.") && !ip.startsWith("10.254.")) {
                blockedIps.add(ip);
                saveRules();
                triggerVpnReload();
            }
        } else if ("allow_ip".equals(action)) {
            String ip = params.getOrDefault("ip", "").trim();
            blockedIps.remove(ip);
            saveRules();
            triggerVpnReload();
        } else if ("dismiss_alert".equals(action)) {
            long id = Long.parseLong(params.getOrDefault("id", "-1"));
            activeAlerts.removeIf(a -> a.id == id);
        } else if ("clear_alerts".equals(action)) {
            activeAlerts.clear();
        }
    }

    private static String buildTunRulesText() {
        StringBuilder sb = new StringBuilder();
        for (String d : blockedDomains) sb.append("DOMAIN|").append(d).append("\n");
        for (String ip : blockedIps) sb.append("IP|").append(ip).append("\n");
        for (int u : blockedUids) sb.append("UID|").append(u).append("\n");
        return sb.toString();
    }

    private static String buildStateJson() {
        StringBuilder sb = new StringBuilder(32768);
        sb.append("{");
        sb.append("\"ebpfEnabled\":").append(ebpfEnabled).append(",");
        sb.append("\"tunStatus\":\"").append(jsonEsc(tunStatus)).append("\",");
        sb.append("\"totalEvents\":").append(totalEventsCount.get()).append(",");
        sb.append("\"totalBlocked\":").append(totalBlockedCount.get()).append(",");

        // blockedUids
        sb.append("\"blockedUids\":[");
        boolean first = true;
        for (int u : blockedUids) {
            if (!first) sb.append(",");
            first = false;
            sb.append(u);
        }
        sb.append("],");

        // blockedDomains
        sb.append("\"blockedDomains\":[");
        first = true;
        List<String> doms = new ArrayList<>(blockedDomains);
        Collections.sort(doms);
        for (String d : doms) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(jsonEsc(d)).append("\"");
        }
        sb.append("],");

        // blockedIps
        sb.append("\"blockedIps\":[");
        first = true;
        List<String> ips = new ArrayList<>(blockedIps);
        Collections.sort(ips);
        for (String ip : ips) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(jsonEsc(ip)).append("\"");
        }
        sb.append("],");

        // alerts
        sb.append("\"alerts\":[");
        first = true;
        for (AlertItem a : activeAlerts) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"id\":").append(a.id)
              .append(",\"time\":\"").append(jsonEsc(a.time)).append("\"")
              .append(",\"type\":\"").append(jsonEsc(a.type)).append("\"")
              .append(",\"blocked\":").append(a.blocked)
              .append(",\"uid\":").append(a.uid)
              .append(",\"pkg\":\"").append(jsonEsc(a.pkg)).append("\"")
              .append(",\"proto\":\"").append(jsonEsc(a.proto)).append("\"")
              .append(",\"domain\":\"").append(jsonEsc(a.domain)).append("\"")
              .append(",\"dstIp\":\"").append(jsonEsc(a.dstIp)).append("\"")
              .append(",\"dstPort\":").append(a.dstPort).append("}");
        }
        sb.append("],");

        // events
        sb.append("\"events\":[");
        first = true;
        int count = 0;
        for (EgressEvent e : recentEvents) {
            if (count++ >= 120) break;
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"id\":").append(e.id)
              .append(",\"time\":\"").append(jsonEsc(e.time)).append("\"")
              .append(",\"verdict\":\"").append(jsonEsc(e.verdict)).append("\"")
              .append(",\"uid\":").append(e.uid)
              .append(",\"pkg\":\"").append(jsonEsc(e.pkg)).append("\"")
              .append(",\"proto\":\"").append(jsonEsc(e.proto)).append("\"")
              .append(",\"domain\":\"").append(jsonEsc(e.domain)).append("\"")
              .append(",\"dstIp\":\"").append(jsonEsc(e.dstIp)).append("\"")
              .append(",\"dstPort\":").append(e.dstPort).append("}");
        }
        sb.append("],");

        // activeSockets
        sb.append("\"activeSockets\":[");
        first = true;
        for (KernelSocket k : currentSockets) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"uid\":").append(k.uid)
              .append(",\"pkg\":\"").append(jsonEsc(k.pkg)).append("\"")
              .append(",\"proto\":\"").append(jsonEsc(k.proto)).append("\"")
              .append(",\"localIp\":\"").append(jsonEsc(k.localIp)).append("\"")
              .append(",\"localPort\":").append(k.localPort)
              .append(",\"remoteIp\":\"").append(jsonEsc(k.remoteIp)).append("\"")
              .append(",\"remotePort\":").append(k.remotePort)
              .append(",\"state\":\"").append(jsonEsc(k.state)).append("\"")
              .append(",\"domain\":\"").append(jsonEsc(k.domain)).append("\"}");
        }
        sb.append("],");

        // dnsLog
        sb.append("\"dnsLog\":[");
        first = true;
        int dCount = 0;
        for (DnsEntry d : dnsLog) {
            if (dCount++ >= 80) break;
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"time\":\"").append(jsonEsc(d.time)).append("\"")
              .append(",\"domain\":\"").append(jsonEsc(d.domain)).append("\"")
              .append(",\"ips\":\"").append(jsonEsc(d.ips)).append("\"")
              .append(",\"blocked\":").append(d.blocked).append("}");
        }
        sb.append("],");

        // apps (sorted: blocked first, then active sockets, then UID)
        List<AppInfo> appList = new ArrayList<>(appsByUid.values());
        appList.sort((a, b) -> {
            boolean ba = blockedUids.contains(a.uid);
            boolean bb = blockedUids.contains(b.uid);
            if (ba != bb) return ba ? -1 : 1;
            if (a.activeSockets != b.activeSockets) return Integer.compare(b.activeSockets, a.activeSockets);
            if (a.eventsCount.get() != b.eventsCount.get()) return Integer.compare(b.eventsCount.get(), a.eventsCount.get());
            return Integer.compare(a.uid, b.uid);
        });

        sb.append("\"apps\":[");
        first = true;
        for (AppInfo a : appList) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"uid\":").append(a.uid)
              .append(",\"pkg\":\"").append(jsonEsc(a.pkg)).append("\"")
              .append(",\"system\":").append(a.system)
              .append(",\"protectedUid\":").append(a.protectedUid)
              .append(",\"blocked\":").append(blockedUids.contains(a.uid))
              .append(",\"activeSockets\":").append(a.activeSockets)
              .append(",\"eventsCount\":").append(a.eventsCount.get()).append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private static void sendHttpResponse(OutputStream out, int code, String contentType, String body) throws Exception {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String statusText = code == 200 ? "OK" : "Not Found";
        String header = "HTTP/1.1 " + code + " " + statusText + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + bodyBytes.length + "\r\n"
                + "Cache-Control: no-store\r\n"
                + "Access-Control-Allow-Origin: *\r\n"
                + "Connection: close\r\n\r\n";
        out.write(header.getBytes(StandardCharsets.UTF_8));
        out.write(bodyBytes);
        out.flush();
    }

    private static String nowTime() {
        return new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date());
    }

    private static int parseIntSafe(String s, int def) {
        if (s == null) return def;
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "");
    }
}
