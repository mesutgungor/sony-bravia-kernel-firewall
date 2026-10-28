package com.bravia.firewall;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;

public class MainActivity extends Activity {
    private static final int REQ_VPN = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        boolean autoStart = getIntent() != null && getIntent().getBooleanExtra("auto_start", false);

        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);
        } else {
            launchTunService();
            if (autoStart) {
                finish();
                return;
            }
        }

        String lanIp = detectLanIpv4();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0B0F19"));
        root.setGravity(Gravity.CENTER);
        root.setPadding(80, 80, 80, 80);

        TextView title = new TextView(this);
        title.setText("Bravia Hybrid Kernel Egress Firewall");
        title.setTextColor(Color.parseColor("#38BDF8"));
        title.setTextSize(28f);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("\n• Kernel eBPF (BpfNetMaps STANDBY Chain 2): ACTIVE\n"
                + "• Kernel /dev/tun DNS/SNI/IP Packet Filter: ACTIVE\n\n"
                + "Real-Time Web Dashboard:\n"
                + "  http://" + lanIp + ":8899\n"
                + "  http://localhost:8899 (via ADB forward)");
        sub.setTextColor(Color.parseColor("#E2E8F0"));
        sub.setTextSize(18f);
        root.addView(sub);

        setContentView(root);
    }

    private String detectLanIpv4() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces != null && ifaces.hasMoreElements()) {
                NetworkInterface nif = ifaces.nextElement();
                if (!nif.isUp() || nif.isLoopback() || nif.getName().startsWith("tun")) continue;
                Enumeration<InetAddress> addrs = nif.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "<TV_LAN_IP>";
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            launchTunService();
        }
    }

    private void launchTunService() {
        Intent svc = new Intent(this, BraviaTunVpnService.class);
        svc.setAction("com.bravia.firewall.START_VPN");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svc);
        } else {
            startService(svc);
        }
    }
}
