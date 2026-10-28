package com.bravia.firewall;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class BraviaTunVpnService extends VpnService {
    private static final String TAG = "BraviaTunFirewall";
    private static final String CHANNEL_ID = "bravia_fw_channel";
    private static final int DAEMON_UDP_PORT = 8898;
    private static final int DAEMON_HTTP_PORT = 8899;

    private ParcelFileDescriptor tunInterface;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread tunReadThread;
    private Thread configSyncThread;
    private ExecutorService dnsExecutor;
    private FileOutputStream tunOut;
    private DatagramSocket ipcSocket;

    // Live synced rules from BraviaKernelDaemon
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<Integer> blockedUids = ConcurrentHashMap.newKeySet();
    // Per-UID domain blocks: "uid:domain"
    private final Set<String> blockedUidDomains = ConcurrentHashMap.newKeySet();

    // Trap IP mapping: 10.254.X.Y <-> domain
    private final Map<String, Integer> domainToTrapIp = new ConcurrentHashMap<>();
    private final Map<Integer, String> trapIpToDomain = new ConcurrentHashMap<>();
    private final AtomicInteger trapCounter = new AtomicInteger(1);

    // Track SYN-ACKed connections so we don't duplicate reports if no payload arrives
    private final Map<String, Long> pendingSniHandshakes = new ConcurrentHashMap<>();

    @Override
    public void onCreate() {
        super.onCreate();
        loadDefaultRules();
        try {
            ipcSocket = new DatagramSocket();
            protect(ipcSocket);
        } catch (Exception e) {
            Log.e(TAG, "Failed to create IPC socket", e);
        }
    }

    private void loadDefaultRules() {
        // Default pre-blocked telemetry, ACR, and ad domains
        String[] defaults = new String[]{
            "samba.tv", "flingo.tv", "sambaa.com",
            "doubleclick.net", "googleadservices.com", "googlesyndication.com",
            "app-measurement.com", "google-analytics.com",
            "ssm1.internet.sony.tv", "ssm2.internet.sony.tv", "ssm3.internet.sony.tv",
            "ndmdhs.com", "idd.sony.net", "reg.biv.sony.tv"
        };
        Collections.addAll(blockedDomains, defaults);
        int[] defaultUids = new int[]{
            10062, 10084, 10148, 10144, 10166, 10063, 10262, 10290, 10291, 10154, 10053
        };
        for (int u : defaultUids) blockedUids.add(u);
        loadPersistedTunRules();
    }

    private java.io.File getPersistentRulesFile() {
        Context ctx = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N ? createDeviceProtectedStorageContext() : this;
        return new java.io.File(ctx.getFilesDir(), "tun_rules.conf");
    }

    private void loadPersistedTunRules() {
        try {
            java.io.File f = getPersistentRulesFile();
            if (!f.exists()) return;
            Set<String> newDomains = ConcurrentHashMap.newKeySet();
            Set<String> newIps = ConcurrentHashMap.newKeySet();
            Set<Integer> newUids = ConcurrentHashMap.newKeySet();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("DOMAIN|")) newDomains.add(line.substring(7).toLowerCase());
                    else if (line.startsWith("IP|")) newIps.add(line.substring(3));
                    else if (line.startsWith("UID|")) newUids.add(Integer.parseInt(line.substring(4)));
                }
            }
            if (!newDomains.isEmpty() || !newUids.isEmpty()) {
                blockedDomains.clear();
                blockedDomains.addAll(newDomains);
                blockedIps.clear();
                blockedIps.addAll(newIps);
                blockedUids.clear();
                blockedUids.addAll(newUids);
            }
        } catch (Exception ignored) {}
    }

    private void savePersistedTunRules(String rawContent) {
        try {
            java.io.File f = getPersistentRulesFile();
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(rawContent.getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {}
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : "com.bravia.firewall.START_VPN";
        if ("com.bravia.firewall.STOP_VPN".equals(action)) {
            stopFirewall();
            stopSelf();
            return START_NOT_STICKY;
        } else if ("com.bravia.firewall.RELOAD_VPN".equals(action)) {
            syncRulesFromDaemon();
            restartTunInterface();
            return START_STICKY;
        }

        startForegroundNotification();
        if (!running.get()) {
            startFirewall();
        }
        return START_STICKY;
    }

    private void startForegroundNotification() {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
                NotificationChannel ch = new NotificationChannel(
                        CHANNEL_ID, "Bravia Kernel Egress Firewall", NotificationManager.IMPORTANCE_LOW);
                nm.createNotificationChannel(ch);
                Notification notif = new Notification.Builder(this, CHANNEL_ID)
                        .setContentTitle("Bravia Kernel Egress Firewall Active")
                        .setContentText("Monitoring & filtering egress DNS/SNI/IP via /dev/tun + eBPF")
                        .setSmallIcon(android.R.drawable.ic_lock_lock)
                        .build();
                startForeground(1001, notif);
            }
        } catch (Throwable t) {
            Log.w(TAG, "Foreground notification warning: " + t.getMessage());
        }
    }

    private synchronized void startFirewall() {
        running.set(true);
        dnsExecutor = Executors.newFixedThreadPool(8);
        syncRulesFromDaemon();
        establishTun();

        configSyncThread = new Thread(() -> {
            while (running.get()) {
                try {
                    Thread.sleep(2000);
                    boolean routesChanged = syncRulesFromDaemon();
                    if (routesChanged && running.get()) {
                        Log.i(TAG, "Blocked IP routes changed, reloading /dev/tun");
                        restartTunInterface();
                    }
                } catch (InterruptedException ie) {
                    break;
                } catch (Throwable t) {
                    // ignore transient sync error
                }
            }
        }, "TunConfigSync");
        configSyncThread.setDaemon(true);
        configSyncThread.start();
    }

    private synchronized void restartTunInterface() {
        closeTun();
        if (running.get()) {
            establishTun();
        }
    }

    private synchronized void establishTun() {
        try {
            Builder builder = new Builder();
            builder.setSession("BraviaEgressFirewall");
            builder.setMtu(1500);
            builder.addAddress("10.215.173.1", 30);
            builder.addDnsServer("10.215.173.2");
            // Intercept all system DNS queries to virtual DNS 10.215.173.2
            builder.addRoute("10.215.173.2", 32);
            // Intercept virtual trap subnet 10.254.0.0/16 for blocked domains & TLS SNI extraction
            builder.addRoute("10.254.0.0", 16);

            // Add /32 routes for any explicitly blocked IPv4 addresses
            for (String ip : blockedIps) {
                if (ip != null && ip.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$") && !ip.startsWith("192.168.") && !ip.startsWith("127.")) {
                    try {
                        builder.addRoute(ip, 32);
                    } catch (Exception e) {
                        Log.w(TAG, "Invalid route IP: " + ip);
                    }
                }
            }

            // Never route our own firewall package into tun0 so upstream DNS queries bypass tun0
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (Exception ignored) {}

            builder.setBlocking(true);
            tunInterface = builder.establish();
            if (tunInterface == null) {
                Log.e(TAG, "VpnService.Builder.establish() returned null! Ensure ACTIVATE_VPN appop is allowed.");
                sendDaemonEvent("TUN_STATUS|STOPPED|establish_null");
                return;
            }

            tunOut = new FileOutputStream(tunInterface.getFileDescriptor());
            sendDaemonEvent("TUN_STATUS|ACTIVE|fd=" + tunInterface.getFd());
            Log.i(TAG, "/dev/tun interface established successfully");

            final ParcelFileDescriptor pfd = tunInterface;
            tunReadThread = new Thread(() -> runTunLoop(pfd), "TunPacketLoop");
            tunReadThread.start();
        } catch (Throwable t) {
            Log.e(TAG, "Failed to establish /dev/tun", t);
            sendDaemonEvent("TUN_STATUS|ERROR|" + t.getMessage());
        }
    }

    private void runTunLoop(ParcelFileDescriptor pfd) {
        FileInputStream in = new FileInputStream(pfd.getFileDescriptor());
        byte[] buf = new byte[32767];
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);

        while (running.get() && pfd == tunInterface) {
            try {
                int len = in.read(buf);
                if (len <= 0) {
                    if (len < 0) break;
                    continue;
                }
                int version = (buf[0] >> 4) & 0x0F;
                if (version != 4 || len < 20) {
                    continue;
                }
                int ihl = (buf[0] & 0x0F) * 4;
                if (len < ihl) continue;

                int proto = buf[9] & 0xFF;
                int srcIpInt = readIntBE(buf, 12);
                int dstIpInt = readIntBE(buf, 16);
                String srcIp = ipToString(srcIpInt);
                String dstIp = ipToString(dstIpInt);

                if (proto == 17 && len >= ihl + 8) { // UDP
                    int srcPort = readShortBE(buf, ihl);
                    int dstPort = readShortBE(buf, ihl + 2);
                    int udpLen = readShortBE(buf, ihl + 4);
                    int payloadOffset = ihl + 8;
                    int payloadLen = Math.min(len - payloadOffset, udpLen - 8);
                    if (payloadLen <= 0) continue;

                    int uid = resolveOwnerUid(cm, OsConstants.IPPROTO_UDP, srcIp, srcPort, dstIp, dstPort);

                    if (dstPort == 53) {
                        byte[] packetCopy = new byte[len];
                        System.arraycopy(buf, 0, packetCopy, 0, len);
                        handleDnsPacket(packetCopy, ihl, srcIpInt, dstIpInt, srcPort, dstPort, payloadOffset, payloadLen, uid);
                    } else {
                        // UDP packet to a trapped domain IP (10.254.x.y) or blocked IP
                        String domain = trapIpToDomain.getOrDefault(dstIpInt, "-");
                        sendDaemonEvent("TUN_BLOCK|" + uid + "|UDP|" + dstIp + "|" + dstPort + "|" + domain + "|-");
                    }
                } else if (proto == 6 && len >= ihl + 20) { // TCP
                    int srcPort = readShortBE(buf, ihl);
                    int dstPort = readShortBE(buf, ihl + 2);
                    long seqNum = readIntBE(buf, ihl + 4) & 0xFFFFFFFFL;
                    long ackNum = readIntBE(buf, ihl + 8) & 0xFFFFFFFFL;
                    int dataOffset = ((buf[ihl + 12] >> 4) & 0x0F) * 4;
                    int tcpFlags = buf[ihl + 13] & 0xFF;
                    int payloadOffset = ihl + dataOffset;
                    int payloadLen = len - payloadOffset;

                    int uid = resolveOwnerUid(cm, OsConstants.IPPROTO_TCP, srcIp, srcPort, dstIp, dstPort);
                    String domain = trapIpToDomain.getOrDefault(dstIpInt, "-");
                    String flowKey = srcIp + ":" + srcPort + "->" + dstIp + ":" + dstPort;

                    boolean isSyn = (tcpFlags & 0x02) != 0 && (tcpFlags & 0x10) == 0;
                    boolean isRst = (tcpFlags & 0x04) != 0;
                    boolean isFin = (tcpFlags & 0x01) != 0;

                    if (isRst) {
                        pendingSniHandshakes.remove(flowKey);
                        continue;
                    }

                    if (isSyn) {
                        if ("10.215.173.2".equals(dstIp) && dstPort == 853) {
                            // Silently reject opportunistic DoT probes to virtual DNS so netd uses UDP/53
                            writeTcpControlPacket(dstIpInt, srcIpInt, dstPort, srcPort, 0L, (seqNum + 1) & 0xFFFFFFFFL, 0x14 /* RST,ACK */);
                            continue;
                        }
                        if (dstPort == 443 || dstPort == 80) {
                            // Complete 3-way handshake locally on tun0 so client sends TLS ClientHello / HTTP Host
                            pendingSniHandshakes.put(flowKey, System.currentTimeMillis());
                            writeTcpControlPacket(dstIpInt, srcIpInt, dstPort, srcPort, 0x42524156L, (seqNum + 1) & 0xFFFFFFFFL, 0x12 /* SYN,ACK */);
                        } else {
                            // Reject immediately with RST,ACK
                            writeTcpControlPacket(dstIpInt, srcIpInt, dstPort, srcPort, 0L, (seqNum + 1) & 0xFFFFFFFFL, 0x14 /* RST,ACK */);
                            sendDaemonEvent("TUN_BLOCK|" + uid + "|TCP|" + dstIp + "|" + dstPort + "|" + domain + "|-");
                        }
                    } else if (payloadLen > 0) {
                        // Extract TLS ClientHello SNI or HTTP Host header, then kill connection with RST,ACK!
                        pendingSniHandshakes.remove(flowKey);
                        String sni = extractTlsSni(buf, payloadOffset, payloadLen);
                        if (sni == null) {
                            sni = extractHttpHost(buf, payloadOffset, payloadLen);
                        }
                        if (sni != null && !sni.isEmpty() && "-".equals(domain)) {
                            domain = sni;
                        }
                        writeTcpControlPacket(dstIpInt, srcIpInt, dstPort, srcPort, ackNum, (seqNum + payloadLen) & 0xFFFFFFFFL, 0x14 /* RST,ACK */);
                        sendDaemonEvent("TUN_BLOCK|" + uid + "|TCP|" + dstIp + "|" + dstPort + "|" + domain + "|" + (sni != null ? sni : "-"));
                    } else if (isFin) {
                        writeTcpControlPacket(dstIpInt, srcIpInt, dstPort, srcPort, ackNum, (seqNum + 1) & 0xFFFFFFFFL, 0x14 /* RST,ACK */);
                    }
                }
            } catch (Throwable t) {
                if (!running.get()) break;
            }
        }
    }

    private void handleDnsPacket(
            byte[] pkt, int ihl, int srcIpInt, int dstIpInt, int srcPort, int dstPort,
            int payloadOffset, int payloadLen, int uid) {
        if (payloadLen < 12) return;
        String qname = parseDnsQname(pkt, payloadOffset, payloadLen);
        int qtype = parseDnsQtype(pkt, payloadOffset, payloadLen);
        if (qname == null || qname.isEmpty()) return;
        String domain = qname.toLowerCase();

        if (isDomainBlocked(domain, uid)) {
            int trapIp = getOrCreateTrapIp(domain);
            byte[] dnsResp;
            if (qtype == 1) { // A record -> return 10.254.X.Y trap IP (TTL 5s)
                dnsResp = buildDnsAResponse(pkt, payloadOffset, payloadLen, trapIp, 5);
            } else {
                // For AAAA (28) or HTTPS (65), return empty NOERROR so client uses IPv4 trap IP
                dnsResp = buildDnsEmptyNoError(pkt, payloadOffset, payloadLen);
            }
            if (dnsResp != null) {
                writeUdpPacket(dstIpInt, srcIpInt, dstPort, srcPort, dnsResp);
            }
            sendDaemonEvent("DNS_BLOCK|" + uid + "|" + domain + "|" + ipToString(trapIp) + "|qtype=" + qtype);
            return;
        }

        // Forward allowed DNS query asynchronously via protected DatagramSocket
        final byte[] dnsQuery = new byte[payloadLen];
        System.arraycopy(pkt, payloadOffset, dnsQuery, 0, payloadLen);
        dnsExecutor.submit(() -> {
            DatagramSocket sock = null;
            try {
                sock = new DatagramSocket();
                protect(sock);
                sock.setSoTimeout(2500);
                // Query upstream DNS resolvers (8.8.8.8 with fallback to 1.1.1.1)
                byte[] respBytes = queryUpstreamDns(sock, dnsQuery, "8.8.8.8");
                if (respBytes == null) {
                    respBytes = queryUpstreamDns(sock, dnsQuery, "1.1.1.1");
                }
                if (respBytes != null) {
                    String resolvedIps = parseDnsAnswerIps(respBytes, respBytes.length);
                    sendDaemonEvent("DNS_ALLOW|" + uid + "|" + domain + "|" + (resolvedIps.isEmpty() ? "-" : resolvedIps));
                    writeUdpPacket(dstIpInt, srcIpInt, dstPort, srcPort, respBytes);
                }
            } catch (Throwable t) {
                // ignore upstream timeout
            } finally {
                if (sock != null) sock.close();
            }
        });
    }

    private byte[] queryUpstreamDns(DatagramSocket sock, byte[] query, String dnsHost) {
        try {
            InetAddress addr = InetAddress.getByName(dnsHost);
            DatagramPacket dp = new DatagramPacket(query, query.length, addr, 53);
            sock.send(dp);
            byte[] rbuf = new byte[4096];
            DatagramPacket rp = new DatagramPacket(rbuf, rbuf.length);
            sock.receive(rp);
            byte[] out = new byte[rp.getLength()];
            System.arraycopy(rbuf, 0, out, 0, rp.getLength());
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isDomainBlocked(String domain, int uid) {
        if (uid > 0 && blockedUids.contains(uid)) {
            return true;
        }
        if (blockedDomains.contains(domain)) {
            return true;
        }
        if (uid > 0 && blockedUidDomains.contains(uid + ":" + domain)) {
            return true;
        }
        // Check parent domain / wildcard matches
        for (String rule : blockedDomains) {
            if (rule.startsWith("*.")) {
                String suffix = rule.substring(2);
                if (domain.equals(suffix) || domain.endsWith("." + suffix)) {
                    return true;
                }
            } else if (domain.endsWith("." + rule)) {
                return true;
            }
        }
        return false;
    }

    private int getOrCreateTrapIp(String domain) {
        Integer existing = domainToTrapIp.get(domain);
        if (existing != null) return existing;
        int idx = (trapCounter.getAndIncrement() & 0x7FFF);
        if (idx == 0) idx = 1;
        // 10.254.X.Y
        int trapIp = (10 << 24) | (254 << 16) | (idx & 0xFFFF);
        domainToTrapIp.put(domain, trapIp);
        trapIpToDomain.put(trapIp, domain);
        return trapIp;
    }

    private int resolveOwnerUid(ConnectivityManager cm, int proto, String srcIp, int srcPort, String dstIp, int dstPort) {
        if (cm == null) return -1;
        try {
            InetSocketAddress local = new InetSocketAddress(InetAddress.getByName(srcIp), srcPort);
            InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName(dstIp), dstPort);
            return cm.getConnectionOwnerUid(proto, local, remote);
        } catch (Throwable t) {
            return -1;
        }
    }

    private synchronized void writeTunPacket(byte[] packet) {
        if (tunOut == null) return;
        try {
            tunOut.write(packet);
        } catch (Exception ignored) {}
    }

    private void writeUdpPacket(int srcIp, int dstIp, int srcPort, int dstPort, byte[] payload) {
        int totalLen = 20 + 8 + payload.length;
        byte[] pkt = new byte[totalLen];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[1] = 0x00;
        writeShortBE(pkt, 2, totalLen);
        writeShortBE(pkt, 4, 0);
        writeShortBE(pkt, 6, 0x4000); // DF
        pkt[8] = 64; // TTL
        pkt[9] = 17; // UDP
        writeIntBE(pkt, 12, srcIp);
        writeIntBE(pkt, 16, dstIp);
        writeShortBE(pkt, 10, computeIpChecksum(pkt, 0, 20));

        // UDP header
        writeShortBE(pkt, 20, srcPort);
        writeShortBE(pkt, 22, dstPort);
        writeShortBE(pkt, 24, 8 + payload.length);
        writeShortBE(pkt, 26, 0); // UDP checksum optional in IPv4
        System.arraycopy(payload, 0, pkt, 28, payload.length);
        writeTunPacket(pkt);
    }

    private void writeTcpControlPacket(int srcIp, int dstIp, int srcPort, int dstPort, long seq, long ack, int flags) {
        int totalLen = 40;
        byte[] pkt = new byte[totalLen];
        pkt[0] = 0x45;
        pkt[1] = 0x00;
        writeShortBE(pkt, 2, totalLen);
        writeShortBE(pkt, 4, 0);
        writeShortBE(pkt, 6, 0x4000);
        pkt[8] = 64;
        pkt[9] = 6; // TCP
        writeIntBE(pkt, 12, srcIp);
        writeIntBE(pkt, 16, dstIp);
        writeShortBE(pkt, 10, computeIpChecksum(pkt, 0, 20));

        // TCP header
        writeShortBE(pkt, 20, srcPort);
        writeShortBE(pkt, 22, dstPort);
        writeIntBE(pkt, 24, (int) seq);
        writeIntBE(pkt, 28, (int) ack);
        pkt[32] = 0x50; // data offset 5 (20 bytes)
        pkt[33] = (byte) flags;
        writeShortBE(pkt, 34, 65535); // window
        writeShortBE(pkt, 36, 0); // checksum placeholder
        writeShortBE(pkt, 38, 0); // urgent
        writeShortBE(pkt, 36, computeTcpChecksum(pkt, srcIp, dstIp, 20, 20));
        writeTunPacket(pkt);
    }

    // Parse DNS QNAME
    private static String parseDnsQname(byte[] buf, int offset, int len) {
        int pos = offset + 12;
        int end = offset + len;
        StringBuilder sb = new StringBuilder();
        while (pos < end) {
            int labelLen = buf[pos++] & 0xFF;
            if (labelLen == 0) break;
            if ((labelLen & 0xC0) == 0xC0 || pos + labelLen > end) return null;
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(buf, pos, labelLen, StandardCharsets.US_ASCII));
            pos += labelLen;
        }
        return sb.toString();
    }

    private static int parseDnsQtype(byte[] buf, int offset, int len) {
        int pos = offset + 12;
        int end = offset + len;
        while (pos < end) {
            int labelLen = buf[pos++] & 0xFF;
            if (labelLen == 0) break;
            pos += labelLen;
        }
        if (pos + 4 <= end) {
            return readShortBE(buf, pos);
        }
        return 1;
    }

    private static byte[] buildDnsAResponse(byte[] query, int offset, int len, int ipv4, int ttlSeconds) {
        int pos = offset + 12;
        int end = offset + len;
        while (pos < end && (query[pos] & 0xFF) != 0) {
            pos += 1 + (query[pos] & 0xFF);
        }
        pos += 5; // null byte + QTYPE(2) + QCLASS(2)
        if (pos > end) return null;
        int questionSectionLen = pos - offset;

        byte[] resp = new byte[questionSectionLen + 16];
        System.arraycopy(query, offset, resp, 0, questionSectionLen);
        // Flags: QR=1, AA=0, RD=1, RA=1, RCODE=0 -> 0x8180
        resp[2] = (byte) 0x81;
        resp[3] = (byte) 0x80;
        // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
        writeShortBE(resp, 4, 1);
        writeShortBE(resp, 6, 1);
        writeShortBE(resp, 8, 0);
        writeShortBE(resp, 10, 0);

        int a = questionSectionLen;
        writeShortBE(resp, a, 0xC00C); // pointer to QNAME at offset 12
        writeShortBE(resp, a + 2, 1);  // TYPE A
        writeShortBE(resp, a + 4, 1);  // CLASS IN
        writeIntBE(resp, a + 6, ttlSeconds);
        writeShortBE(resp, a + 10, 4); // RDLENGTH 4
        writeIntBE(resp, a + 12, ipv4);
        return resp;
    }

    private static byte[] buildDnsEmptyNoError(byte[] query, int offset, int len) {
        int pos = offset + 12;
        int end = offset + len;
        while (pos < end && (query[pos] & 0xFF) != 0) {
            pos += 1 + (query[pos] & 0xFF);
        }
        pos += 5;
        if (pos > end) return null;
        int questionSectionLen = pos - offset;
        byte[] resp = new byte[questionSectionLen];
        System.arraycopy(query, offset, resp, 0, questionSectionLen);
        resp[2] = (byte) 0x81;
        resp[3] = (byte) 0x80;
        writeShortBE(resp, 4, 1);
        writeShortBE(resp, 6, 0);
        writeShortBE(resp, 8, 0);
        writeShortBE(resp, 10, 0);
        return resp;
    }

    private static String parseDnsAnswerIps(byte[] dns, int len) {
        try {
            if (len < 12) return "";
            int qdCount = readShortBE(dns, 4);
            int anCount = readShortBE(dns, 6);
            int pos = 12;
            for (int i = 0; i < qdCount && pos < len; i++) {
                pos = skipDnsName(dns, pos, len);
                pos += 4;
            }
            List<String> ips = new ArrayList<>();
            for (int i = 0; i < anCount && pos < len; i++) {
                pos = skipDnsName(dns, pos, len);
                if (pos + 10 > len) break;
                int type = readShortBE(dns, pos);
                int rdLen = readShortBE(dns, pos + 8);
                pos += 10;
                if (pos + rdLen > len) break;
                if (type == 1 && rdLen == 4) { // IPv4 A
                    ips.add(ipToString(readIntBE(dns, pos)));
                } else if (type == 28 && rdLen == 16) { // IPv6 AAAA
                    byte[] v6 = new byte[16];
                    System.arraycopy(dns, pos, v6, 0, 16);
                    InetAddress addr = InetAddress.getByAddress(v6);
                    ips.add(addr.getHostAddress());
                }
                pos += rdLen;
            }
            return String.join(",", ips);
        } catch (Exception e) {
            return "";
        }
    }

    private static int skipDnsName(byte[] dns, int pos, int len) {
        while (pos < len) {
            int b = dns[pos] & 0xFF;
            if (b == 0) {
                return pos + 1;
            } else if ((b & 0xC0) == 0xC0) {
                return pos + 2;
            } else {
                pos += 1 + b;
            }
        }
        return len;
    }

    // Extract TLS ClientHello SNI (extension 0x0000)
    private static String extractTlsSni(byte[] buf, int offset, int len) {
        try {
            int end = offset + len;
            if (len < 43) return null;
            // TLS Record Header: ContentType=22 (Handshake)
            if ((buf[offset] & 0xFF) != 22) return null;
            // Handshake Type=1 (ClientHello)
            if ((buf[offset + 5] & 0xFF) != 1) return null;

            int pos = offset + 5 + 4 + 2 + 32; // Skip Record(5) + Handshake(4) + Version(2) + Random(32)
            if (pos >= end) return null;
            int sessionIdLen = buf[pos] & 0xFF;
            pos += 1 + sessionIdLen;
            if (pos + 2 > end) return null;
            int cipherSuitesLen = readShortBE(buf, pos);
            pos += 2 + cipherSuitesLen;
            if (pos + 1 > end) return null;
            int compMethodsLen = buf[pos] & 0xFF;
            pos += 1 + compMethodsLen;
            if (pos + 2 > end) return null;
            int extensionsLen = readShortBE(buf, pos);
            pos += 2;
            int extEnd = Math.min(end, pos + extensionsLen);
            while (pos + 4 <= extEnd) {
                int extType = readShortBE(buf, pos);
                int extLen = readShortBE(buf, pos + 2);
                pos += 4;
                if (pos + extLen > extEnd) break;
                if (extType == 0x0000 && extLen >= 5) { // server_name
                    int nameType = buf[pos + 2] & 0xFF;
                    int nameLen = readShortBE(buf, pos + 3);
                    if (nameType == 0 && pos + 5 + nameLen <= extEnd) {
                        return new String(buf, pos + 5, nameLen, StandardCharsets.US_ASCII);
                    }
                }
                pos += extLen;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String extractHttpHost(byte[] buf, int offset, int len) {
        try {
            int checkLen = Math.min(len, 512);
            String s = new String(buf, offset, checkLen, StandardCharsets.US_ASCII);
            for (String line : s.split("\r\n")) {
                if (line.regionMatches(true, 0, "Host:", 0, 5)) {
                    return line.substring(5).trim();
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private boolean syncRulesFromDaemon() {
        boolean ipsChanged = false;
        try {
            URL url = new URL("http://127.0.0.1:" + DAEMON_HTTP_PORT + "/api/tun-rules");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(1000);
            conn.setReadTimeout(1000);
            if (conn.getResponseCode() == 200) {
                Set<String> newDomains = ConcurrentHashMap.newKeySet();
                Set<String> newIps = ConcurrentHashMap.newKeySet();
                Set<Integer> newUids = ConcurrentHashMap.newKeySet();
                Set<String> newUidDomains = ConcurrentHashMap.newKeySet();

                StringBuilder rawBuilder = new StringBuilder();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        rawBuilder.append(line).append("\n");
                        if (line.startsWith("DOMAIN|")) {
                            newDomains.add(line.substring(7).toLowerCase());
                        } else if (line.startsWith("IP|")) {
                            newIps.add(line.substring(3));
                        } else if (line.startsWith("UID|")) {
                            try {
                                newUids.add(Integer.parseInt(line.substring(4)));
                            } catch (NumberFormatException ignored) {}
                        } else if (line.startsWith("UID_DOMAIN|")) {
                            newUidDomains.add(line.substring(11).toLowerCase());
                        }
                    }
                }
                savePersistedTunRules(rawBuilder.toString());
                blockedDomains.clear();
                blockedDomains.addAll(newDomains);
                blockedUids.clear();
                blockedUids.addAll(newUids);
                blockedUidDomains.clear();
                blockedUidDomains.addAll(newUidDomains);

                if (!blockedIps.equals(newIps)) {
                    ipsChanged = true;
                    blockedIps.clear();
                    blockedIps.addAll(newIps);
                }
            }
        } catch (Exception ignored) {}
        return ipsChanged;
    }

    private void sendDaemonEvent(String msg) {
        if (ipcSocket == null) return;
        try {
            byte[] data = msg.getBytes(StandardCharsets.UTF_8);
            DatagramPacket dp = new DatagramPacket(data, data.length, InetAddress.getByName("127.0.0.1"), DAEMON_UDP_PORT);
            ipcSocket.send(dp);
        } catch (Exception ignored) {}
    }

    private synchronized void closeTun() {
        try {
            if (tunOut != null) {
                tunOut.close();
                tunOut = null;
            }
        } catch (Exception ignored) {}
        try {
            if (tunInterface != null) {
                tunInterface.close();
                tunInterface = null;
            }
        } catch (Exception ignored) {}
    }

    private synchronized void stopFirewall() {
        running.set(false);
        closeTun();
        if (dnsExecutor != null) {
            dnsExecutor.shutdownNow();
        }
        sendDaemonEvent("TUN_STATUS|STOPPED|manual");
    }

    @Override
    public void onDestroy() {
        stopFirewall();
        if (ipcSocket != null) ipcSocket.close();
        super.onDestroy();
    }

    private static int readShortBE(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static int readIntBE(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24)
                | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8)
                | (b[off + 3] & 0xFF);
    }

    private static void writeShortBE(byte[] b, int off, int val) {
        b[off] = (byte) ((val >> 8) & 0xFF);
        b[off + 1] = (byte) (val & 0xFF);
    }

    private static void writeIntBE(byte[] b, int off, int val) {
        b[off] = (byte) ((val >> 24) & 0xFF);
        b[off + 1] = (byte) ((val >> 16) & 0xFF);
        b[off + 2] = (byte) ((val >> 8) & 0xFF);
        b[off + 3] = (byte) (val & 0xFF);
    }

    private static String ipToString(int ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    private static int computeIpChecksum(byte[] buf, int off, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            if (i == 10) continue;
            sum += readShortBE(buf, off + i);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum & 0xFFFF);
    }

    private static int computeTcpChecksum(byte[] buf, int srcIp, int dstIp, int tcpOff, int tcpLen) {
        long sum = 0;
        sum += ((srcIp >> 16) & 0xFFFF) + (srcIp & 0xFFFF);
        sum += ((dstIp >> 16) & 0xFFFF) + (dstIp & 0xFFFF);
        sum += 6; // TCP proto
        sum += tcpLen;
        for (int i = 0; i < tcpLen; i += 2) {
            if (i == 16) continue;
            if (i + 1 < tcpLen) {
                sum += readShortBE(buf, tcpOff + i);
            } else {
                sum += (buf[tcpOff + i] & 0xFF) << 8;
            }
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum & 0xFFFF);
    }
}
