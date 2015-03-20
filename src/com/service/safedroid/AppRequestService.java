/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.service.safedroid;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.Enumeration;

import com.server.safedroid.ProxyServer;
import com.server.safedroid.ServerAuthenticatorNone;

import android.R;
import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
public class AppRequestService extends VpnService implements Runnable {

	VpnService.Builder builder = new VpnService.Builder();
	ParcelFileDescriptor mInterface;
	Thread mThread;
	private int mSocksProxyPort = 9999;
	private String mServerAddress = "127.0.0.1";
	private int mServerPort = 8087;
	private boolean keepAlive = true;

	public int onStartCommand(Intent intent, int flags, int startId) {
		if (mThread != null) {
			mThread.interrupt();
		}
		startSocksBypass();
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		mThread = new Thread(this);
		mThread.start();
		

		return START_STICKY;

	}

	public synchronized void run() {
		mInterface = builder.setSession("trialDroidVPNService")
				.addAddress("192.168.0.1", 24).addDnsServer("8.8.8.8")
				.addRoute("0.0.0.0", 0).establish();
		// b. Packets to be sent are queued in this input stream.
		FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
		// b. Packets received need to be written to this output stream.
		FileOutputStream out = new FileOutputStream(
				mInterface.getFileDescriptor());
		// c. The UDP channel can be used to pass/get ip package to/from
		// server
		DatagramChannel tunnel = null;
		try {
			tunnel = DatagramChannel.open();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		try {
			tunnel.connect(new InetSocketAddress(mServerAddress, mServerPort));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		protect(tunnel.socket());

		ByteBuffer packet = ByteBuffer.allocate(32767);

		@SuppressWarnings("unused")
		boolean idle = true;
		int length;
		int timer = 0;

		while (true) {
			try {
				length = in.read(packet.array());
				if (length > 0) {
					packet.limit(length);
					tunnel.write(packet);
					packet.clear();
					idle = false;

					if (timer < 1) {
						timer = 1;
					}
				}

				length = tunnel.read(packet);
				if (length > 0) {
					out.write(packet.array(), 0, length);
					packet.clear();
					idle = false;

					// If we were sending, switch to receiving.
					if (timer > 0) {
						timer = 0;
					}
				}

				if (idle) {
					try {
						Thread.sleep(100);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					// Increase the timer. This is inaccurate but good enough,
					// since everything is operated in non-blocking mode.
					timer += (timer > 0) ? 100 : -100;

					// We are receiving for a long time but not sending.
					if (timer < -15000) {
						// Switch to sending.
						timer = 1;
					}

					// We are sending for a long time but not receiving.
					if (timer > 20000) {
						// throw new IllegalStateException("Timed out");
						// Log.d(TAG,"receiving timed out? timer=" + timer);
					}
				}

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

	}

	public void startSocksBypass() {
		Thread thread = new Thread() {
			public void run() {
				try {
					final ProxyServer server = new ProxyServer(
							new ServerAuthenticatorNone(null, null));
					server.setVpnService(AppRequestService.this);

					server.start(mSocksProxyPort, 5, InetAddress.getLocalHost());
				} catch (UnknownHostException e) { // TODO Auto-generated catch
													// block
					e.printStackTrace();
				}

			}
		};

		thread.start();
	}

	@Override
	public void onDestroy() {
		if (mThread != null) {
			mThread.interrupt();
		}
		super.onDestroy();
	}

	/*
	 * private Thread vpnThread; private ParcelFileDescriptor vpnInterface;
	 * 
	 * VpnService.Builder builder = new VpnService.Builder(); private static
	 * String TAG = "AppRequestService"; private Handler mHandler; private
	 * PendingIntent vpnConfigureIntent; private ParcelFileDescriptor
	 * mInterface;
	 * 
	 * private int mSocksProxyPort = 9999; private String mServerAddress =
	 * "127.0.0.73"; private int mServerPort = 8087; private boolean keepAlive =
	 * true;
	 * 
	 * @Override public int onStartCommand(Intent intent, int flags, int
	 * startId) {
	 * 
	 * 
	 * if (vpnThread != null) { vpnThread.interrupt(); }
	 * 
	 * vpnThread = new Thread(this);
	 * 
	 * vpnThread.start();
	 * 
	 * // startSocksBypass();
	 * 
	 * return START_STICKY; }
	 * 
	 * 
	 * 
	 * 
	 * 
	 * @Override public synchronized void run() { InetSocketAddress server = new
	 * InetSocketAddress(mServerAddress, mServerPort); DatagramChannel mTunnel =
	 * null; boolean isConnected = false; try { mTunnel =
	 * DatagramChannel.open(); } catch (IOException e) { // TODO Auto-generated
	 * catch block e.printStackTrace(); } DatagramSocket pSocket =
	 * mTunnel.socket();
	 * 
	 * if (!protect(pSocket)) { throw new
	 * IllegalStateException("Cannot protect the tunnel"); }
	 * 
	 * try { mTunnel.connect(server); mTunnel.configureBlocking(false); } catch
	 * (IOException e) { // TODO Auto-generated catch block e.printStackTrace();
	 * }
	 * 
	 * vpnInterface = builder.setSession("SafeDroidService")
	 * .addAddress("192.168.0.1", 24).addDnsServer("8.8.8.8")
	 * .addRoute("0.0.0.0", 0).establish();
	 * 
	 * isConnected = true;
	 * 
	 * protect(mTunnel.socket());
	 * 
	 * FileInputStream in = new FileInputStream(
	 * vpnInterface.getFileDescriptor());
	 * 
	 * FileOutputStream out = new FileOutputStream(
	 * vpnInterface.getFileDescriptor());
	 * 
	 * ByteBuffer packet = ByteBuffer.allocate(32767);
	 * 
	 * int timer = 0; while (true) { try { boolean idle = true; int length =
	 * in.read(packet.array()); Log.i("SafeDroid", "" + in.available() + " l:" +
	 * length); if (length > 0) { packet.limit(length); mTunnel.write(packet);
	 * packet.clear();
	 * 
	 * idle = false;
	 * 
	 * if (timer < 1) { timer = 1; } }
	 * 
	 * length = mTunnel.read(packet); if (length > 0) {
	 * out.write(packet.array(), 0, length); packet.clear();
	 * 
	 * idle = false;
	 * 
	 * if (timer > 0) { timer = 0; } }
	 * 
	 * if (idle) { Thread.sleep(100);
	 * 
	 * // Increase the timer. This is inaccurate but good // enough, // since
	 * everything is operated in non-blocking // mode. timer += (timer > 0) ?
	 * 100 : -100;
	 * 
	 * // We are receiving for a long time but not sending. if (timer < -15000)
	 * { // Switch to sending. timer = 1; }
	 * 
	 * // We are sending for a long time but not receiving. if (timer > 20000) {
	 * // throw new IllegalStateException("Timed out"); //
	 * Log.d(TAG,"receiving timed out? timer=" + // timer); } }
	 * 
	 * } catch (Exception e) {
	 * 
	 * }
	 * 
	 * }
	 * 
	 * }
	 */

}
