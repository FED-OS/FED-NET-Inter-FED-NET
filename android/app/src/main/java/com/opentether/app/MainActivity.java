package com.opentether.app;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.PowerManager;
import android.widget.TextView;

import java.io.*;
import java.net.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("OpenTether\nUSB SOCKS5 proxy active on port 1080.\nConnect the Windows OpenTether client.");
        tv.setTextSize(18);
        tv.setPadding(40, 40, 40, 40);
        setContentView(tv);

        Intent intent = new Intent(this, TetherService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
    }

    public static class TetherService extends Service {
        private ServerSocket serverSocket;
        private final ExecutorService acceptPool = Executors.newSingleThreadExecutor();
        private final ExecutorService handshakePool = Executors.newFixedThreadPool(8);
        private final ExecutorService relayPool = Executors.newFixedThreadPool(32);
        private volatile boolean isRunning = true;
        private PowerManager.WakeLock wakeLock;

        private void readFully(InputStream in, byte[] buffer) throws IOException {
            int totalRead = 0;
            while (totalRead < buffer.length) {
                int read = in.read(buffer, totalRead, buffer.length - totalRead);
                if (read == -1) throw new EOFException("Unexpected end of stream");
                totalRead += read;
            }
        }

        private void sendSocksFailure(OutputStream out, int replyCode) throws IOException {
            out.write(new byte[]{
                0x05, (byte) replyCode, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            });
            out.flush();
        }

        @Override
        public void onCreate() {
            super.onCreate();
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OpenTether::WakeLock");
            wakeLock.acquire();

            createNotificationChannel();
            Notification notification = new Notification.Builder(this, "tether_channel")
                    .setContentTitle("OpenTether Active")
                    .setContentText("USB SOCKS5 proxy running")
                    .setSmallIcon(android.R.drawable.ic_menu_share)
                    .build();

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(1, notification);
            }

            startSocksServer();
        }

        private void createNotificationChannel() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationChannel channel = new NotificationChannel(
                        "tether_channel", "Tether Service", NotificationManager.IMPORTANCE_LOW);
                NotificationManager manager = getSystemService(NotificationManager.class);
                if (manager != null) manager.createNotificationChannel(channel);
            }
        }

        private void startSocksServer() {
            acceptPool.execute(() -> {
                try {
                    serverSocket = new ServerSocket(
                        1080,
                        50,
                        InetAddress.getByName("127.0.0.1")
                    );
                    serverSocket.setSoTimeout(3000);
                    while (isRunning) {
                        try {
                            Socket clientSocket = serverSocket.accept();
                            if (!isRunning) {
                                closeQuietly(clientSocket);
                                break;
                            }
                            handshakePool.execute(() -> handleSocksClient(clientSocket));
                        } catch (SocketTimeoutException e) {
                            // re-check loop
                        }
                    }
                } catch (BindException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }

        private void handleSocksClient(Socket client) {
            Socket targetSocket = null;
            OutputStream out = null;
            boolean methodAccepted = false;
            boolean connectResponseSent = false;

            try {
                client.setSoTimeout(30_000);
                InputStream in = client.getInputStream();
                out = client.getOutputStream();

                // ---- SOCKS5 method negotiation ----
                int version = in.read();
                if (version != 5) { closeQuietly(client); return; }

                int numMethods = in.read();
                if (numMethods < 1) { closeQuietly(client); return; }

                byte[] methods = new byte[numMethods];
                readFully(in, methods);

                boolean supportsNoAuth = false;
                for (byte m : methods) {
                    if ((m & 0xFF) == 0x00) { supportsNoAuth = true; break; }
                }

                if (!supportsNoAuth) {
                    out.write(new byte[]{0x05, (byte) 0xFF});
                    out.flush();
                    closeQuietly(client);
                    return;
                }
                out.write(new byte[]{0x05, 0x00});
                out.flush();
                methodAccepted = true;

                // ---- SOCKS5 CONNECT request ----
                int ver = in.read();
                int cmd = in.read();
                int rsv = in.read();
                int atyp = in.read();

                if (ver < 0 || cmd < 0 || rsv < 0 || atyp < 0) {
                    closeQuietly(client);
                    return;
                }
                if (ver != 0x05 || rsv != 0x00) {
                    closeQuietly(client);
                    return;
                }
                if (cmd != 1) {
                    sendSocksFailure(out, 0x07);
                    closeQuietly(client);
                    return;
                }

                String targetHost;
                if (atyp == 1) {
                    byte[] ip = new byte[4];
                    readFully(in, ip);
                    targetHost = InetAddress.getByAddress(ip).getHostAddress();
                } else if (atyp == 3) {
                    int len = in.read();
                    byte[] domain = new byte[len];
                    readFully(in, domain);
                    targetHost = new String(domain);
                } else {
                    sendSocksFailure(out, 0x08);
                    closeQuietly(client);
                    return;
                }

                byte[] portBytes = new byte[2];
                readFully(in, portBytes);
                int targetPort = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);

                // ---- Outbound connection ----
                targetSocket = new Socket();
                targetSocket.connect(new InetSocketAddress(targetHost, targetPort), 10_000);

                // ---- Success ----
                out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
                out.flush();
                connectResponseSent = true;

                // Clear timeouts for the long-lived relay
                client.setSoTimeout(0);
                targetSocket.setSoTimeout(0);

                Socket target = targetSocket;
                relayPool.execute(() -> relayStream(client, target));
                relayPool.execute(() -> relayStream(target, client));

            } catch (ConnectException e) {
                if (out != null && methodAccepted && !connectResponseSent) {
                    try { sendSocksFailure(out, 0x05); } catch (IOException ignored) {}
                }
                closeQuietly(client);
                closeQuietly(targetSocket);
            } catch (SocketTimeoutException e) {
                if (out != null && methodAccepted && !connectResponseSent) {
                    try { sendSocksFailure(out, 0x06); } catch (IOException ignored) {}
                }
                closeQuietly(client);
                closeQuietly(targetSocket);
            } catch (IOException e) {
                if (out != null && methodAccepted && !connectResponseSent) {
                    try { sendSocksFailure(out, 0x01); } catch (IOException ignored) {}
                }
                closeQuietly(client);
                closeQuietly(targetSocket);
            }
        }

        private void relayStream(Socket source, Socket destination) {
            try (InputStream in = source.getInputStream();
                 OutputStream out = destination.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = in.read(buffer)) != -1) {
                    out.write(buffer, 0, count);
                    out.flush();
                }
            } catch (IOException ignored) {
            } finally {
                closeQuietly(source);
                closeQuietly(destination);
            }
        }

        private void closeQuietly(Socket socket) {
            if (socket != null) {
                try { socket.close(); } catch (IOException ignored) {}
            }
        }

        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            return START_NOT_STICKY;
        }

        @Override
        public IBinder onBind(Intent intent) { return null; }

        @Override
        public void onDestroy() {
            isRunning = false;
            try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
            acceptPool.shutdownNow();
            handshakePool.shutdownNow();
            relayPool.shutdownNow();
            if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
            super.onDestroy();
        }
    }
}
