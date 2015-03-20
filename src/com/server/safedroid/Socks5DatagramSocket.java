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
package com.server.safedroid;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class Socks5DatagramSocket extends  DatagramSocket{
	
	InetAddress relayIP;
	int relayPort;
	Socks5Proxy proxy;
	private boolean server_mode = false;
	UDPEncapsulation encapsulation;

	/*private Logger log = LoggerFactory.getLogger(Socks5DatagramSocket.class);

	 * Construct Datagram socket for communication over SOCKS5 proxy server.
	 * This constructor uses default proxy, the one set with
	 * Proxy.setDefaultProxy() method. If default proxy is not set or it is set
	 * to version4 proxy, which does not support datagram forwarding, throws
	 * SocksException.
	 */
	public Socks5DatagramSocket() throws SocksException, IOException {
		this(SocksProxyBase.defaultProxy, 0, null);
	}

	/**
	 * Construct Datagram socket for communication over SOCKS5 proxy server. And
	 * binds it to the specified local port. This constructor uses default
	 * proxy, the one set with Proxy.setDefaultProxy() method. If default proxy
	 * is not set or it is set to version4 proxy, which does not support
	 * datagram forwarding, throws SocksException.
	 */
	public Socks5DatagramSocket(int port) throws SocksException, IOException {
		this(SocksProxyBase.defaultProxy, port, null);
	}

	/**
	 * Construct Datagram socket for communication over SOCKS5 proxy server. And
	 * binds it to the specified local port and address. This constructor uses
	 * default proxy, the one set with Proxy.setDefaultProxy() method. If
	 * default proxy is not set or it is set to version4 proxy, which does not
	 * support datagram forwarding, throws SocksException.
	 */
	public Socks5DatagramSocket(int port, InetAddress ip)
			throws SocksException, IOException {
		this(SocksProxyBase.defaultProxy, port, ip);
	}

	/**
	 * Constructs datagram socket for communication over specified proxy. And
	 * binds it to the given local address and port. Address of null and port of
	 * 0, signify any availabale port/address. Might throw SocksException, if:
	 * <ol>
	 * <li>Given version of proxy does not support UDP_ASSOCIATE.
	 * <li>Proxy can't be reached.
	 * <li>Authorization fails.
	 * <li>Proxy does not want to perform udp forwarding, for any reason.
	 * </ol>
	 * Might throw IOException if binding datagram socket to given address/port
	 * fails. See java.net.DatagramSocket for more details.
	 */
	public Socks5DatagramSocket(SocksProxyBase p, int port, InetAddress ip)
			throws SocksException, IOException {

		super(port, ip);

		if (p == null) {
			throw new SocksException(SocksProxyBase.SOCKS_NO_PROXY);
		}

		if (!(p instanceof Socks5Proxy)) {
			final String s = "Datagram Socket needs Proxy version 5";
			throw new SocksException(-1, s);
		}

		if (p.chainProxy != null) {
			final String s = "Datagram Sockets do not support proxy chaining.";
			throw new SocksException(SocksProxyBase.SOCKS_JUST_ERROR, s);
		}

		proxy = (Socks5Proxy) p.copy();

		final ProxyMessage msg = proxy.udpAssociate(super.getLocalAddress(),
				super.getLocalPort());

		relayIP = msg.ip;
		if (relayIP.getHostAddress().equals("0.0.0.0")) {
			// FIXME: What happens here?
			relayIP = proxy.proxyIP;
		}
		relayPort = msg.port;

		encapsulation = proxy.udp_encapsulation;

		//log.debug("Datagram Socket:{}:{}", getLocalAddress(), getLocalPort());
		//log.debug("Socks5Datagram: {}:{}", relayIP, relayPort);
	}

	/**
	 * Used by UDPRelayServer.
	 */
	Socks5DatagramSocket(boolean server_mode, UDPEncapsulation encapsulation,
			InetAddress relayIP, int relayPort) throws IOException {
		super();
		this.server_mode = server_mode;
		this.relayIP = relayIP;
		this.relayPort = relayPort;
		this.encapsulation = encapsulation;
		this.proxy = null;
	}

	/**
	 * Sends the Datagram either through the proxy or directly depending on
	 * current proxy settings and destination address. <BR>
	 * 
	 * <B> NOTE: </B> DatagramPacket size should be at least 10 bytes less than
	 * the systems limit.
	 * 
	 * <P>
	 * See documentation on java.net.DatagramSocket for full details on how to
	 * use this method.
	 * 
	 * @param dp
	 *            Datagram to send.
	 * @throws IOException
	 *             If error happens with I/O.
	 */
	public void send(DatagramPacket dp) throws IOException {
		// If the host should be accessed directly, send it as is.
		if (!server_mode && proxy.isDirect(dp.getAddress())) {
			super.send(dp);
		//	log.debug("Sending datagram packet directly:");
			return;
		}

		final byte[] head = formHeader(dp.getAddress(), dp.getPort());
		byte[] buf = new byte[head.length + dp.getLength()];
		final byte[] data = dp.getData();

		// Merge head and data
		System.arraycopy(head, 0, buf, 0, head.length);
		// System.arraycopy(data,dp.getOffset(),buf,head.length,dp.getLength());
		System.arraycopy(data, 0, buf, head.length, dp.getLength());

		if (encapsulation != null) {
			buf = encapsulation.udpEncapsulate(buf, true);
		}

		super.send(new DatagramPacket(buf, buf.length, relayIP, relayPort));
	}

	/**
	 * This method allows to send datagram packets with address type DOMAINNAME.
	 * SOCKS5 allows to specify host as names rather than ip addresses.Using
	 * this method one can send udp datagrams through the proxy, without having
	 * to know the ip address of the destination host.
	 * <p>
	 * If proxy specified for that socket has an option resolveAddrLocally set
	 * to true host will be resolved, and the datagram will be send with address
	 * type IPV4, if resolve fails, UnknownHostException is thrown.
	 * 
	 * @param dp
	 *            Datagram to send, it should contain valid port and data
	 * @param host
	 *            Host name to which datagram should be send.
	 * @throws IOException
	 *             If error happens with I/O, or the host can't be resolved when
	 *             proxy settings say that hosts should be resolved locally.
	 * @see Socks5Proxy#resolveAddrLocally(boolean)
	 */
	public void send(DatagramPacket dp, String host) throws IOException {
		if (proxy.isDirect(host)) {
			dp.setAddress(InetAddress.getByName(host));
			super.send(dp);
			return;
		}

		if ((proxy).resolveAddrLocally) {
			dp.setAddress(InetAddress.getByName(host));
		}

		final byte[] head = formHeader(host, dp.getPort());
		byte[] buf = new byte[head.length + dp.getLength()];
		final byte[] data = dp.getData();
		// Merge head and data
		System.arraycopy(head, 0, buf, 0, head.length);
		// System.arraycopy(data,dp.getOffset(),buf,head.length,dp.getLength());
		System.arraycopy(data, 0, buf, head.length, dp.getLength());

		if (encapsulation != null) {
			buf = encapsulation.udpEncapsulate(buf, true);
		}

		super.send(new DatagramPacket(buf, buf.length, relayIP, relayPort));
	}

	/**
	 * Receives udp packet. If packet have arrived from the proxy relay server,
	 * it is processed and address and port of the packet are set to the address
	 * and port of sending host.<BR>
	 * If the packet arrived from anywhere else it is not changed.<br>
	 * <B> NOTE: </B> DatagramPacket size should be at least 10 bytes bigger
	 * than the largest packet you expect (this is for IPV4 addresses). For
	 * hostnames and IPV6 it is even more.
	 * 
	 * @param dp
	 *            Datagram in which all relevent information will be copied.
	 */
	public void receive(DatagramPacket dp) throws IOException {
		super.receive(dp);

		if (server_mode) {
			// Drop all datagrams not from relayIP/relayPort
			final int init_length = dp.getLength();
			final int initTimeout = getSoTimeout();
			final long startTime = System.currentTimeMillis();

			while (!relayIP.equals(dp.getAddress())
					|| (relayPort != dp.getPort())) {

				// Restore datagram size
				dp.setLength(init_length);

				// If there is a non-infinit timeout on this socket
				// Make sure that it happens no matter how often unexpected
				// packets arrive.
				if (initTimeout != 0) {
					final long passed = System.currentTimeMillis() - startTime;
					final int newTimeout = initTimeout - (int) passed;

					if (newTimeout <= 0) {
						throw new InterruptedIOException(
								"In Socks5DatagramSocket->receive()");
					}
					setSoTimeout(newTimeout);
				}

				super.receive(dp);
			}

			// Restore timeout settings
			if (initTimeout != 0) {
				setSoTimeout(initTimeout);
			}

		} else if (!relayIP.equals(dp.getAddress())
				|| (relayPort != dp.getPort())) {
			return; // Recieved direct packet
			// If the datagram is not from the relay server, return it it as is.
		}

		byte[] data;
		data = dp.getData();

		if (encapsulation != null) {
			data = encapsulation.udpEncapsulate(data, false);
		}

		// FIXME: What is this?
		final int offset = 0; // Java 1.1
		// int offset = dp.getOffset(); //Java 1.2

		final ByteArrayInputStream bIn = new ByteArrayInputStream(data, offset,
				dp.getLength());

		final ProxyMessage msg = new Socks5Message(bIn);
		dp.setPort(msg.port);
		dp.setAddress(msg.getInetAddress());

		// what wasn't read by the Message is the data
		final int data_length = bIn.available();
		// Shift data to the left
		System.arraycopy(data, offset + dp.getLength() - data_length, data,
				offset, data_length);

		dp.setLength(data_length);
	}

	/**
	 * Returns port assigned by the proxy, to which datagrams are relayed. It is
	 * not the same port to which other party should send datagrams.
	 * 
	 * @return Port assigned by socks server to which datagrams are send for
	 *         association.
	 */
	public int getLocalPort() {
		if (server_mode) {
			return super.getLocalPort();
		}
		return relayPort;
	}

	/**
	 * Address assigned by the proxy, to which datagrams are send for relay. It
	 * is not necesseraly the same address, to which other party should send
	 * datagrams.
	 * 
	 * @return Address to which datagrams are send for association.
	 */
	public InetAddress getLocalAddress() {
		if (server_mode) {
			return super.getLocalAddress();
		}
		return relayIP;
	}

	/**
	 * Closes datagram socket, and proxy connection.
	 */
	public void close() {
		if (!server_mode) {
			proxy.endSession();
		}
		super.close();
	}

	/**
	 * This method checks wether proxy still runs udp forwarding service for
	 * this socket.
	 * <p>
	 * This methods checks wether the primary connection to proxy server is
	 * active. If it is, chances are that proxy continues to forward datagrams
	 * being send from this socket. If it was closed, most likely datagrams are
	 * no longer being forwarded by the server.
	 * <p>
	 * Proxy might decide to stop forwarding datagrams, in which case it should
	 * close primary connection. This method allows to check, wether this have
	 * been done.
	 * <p>
	 * You can specify timeout for which we should be checking EOF condition on
	 * the primary connection. Timeout is in milliseconds. Specifying 0 as
	 * timeout implies infinity, in which case method will block, until
	 * connection to proxy is closed or an error happens, and then return false.
	 * <p>
	 * One possible scenario is to call isProxyactive(0) in separate thread, and
	 * once it returned notify other threads about this event.
	 * 
	 * @param timeout
	 *            For how long this method should block, before returning.
	 * @return true if connection to proxy is active, false if eof or error
	 *         condition have been encountered on the connection.
	 */
	public boolean isProxyAlive(int timeout) {
		if (server_mode) {
			return false;
		}
		if (proxy != null) {
			try {
				proxy.proxySocket.setSoTimeout(timeout);

				final int eof = proxy.in.read();
				if (eof < 0) {
					return false; // EOF encountered.
				} else {
					//log.warn("This really should not happen");
					return true; // This really should not happen
				}

			} catch (final InterruptedIOException iioe) {
				return true; // read timed out.
			} catch (final IOException ioe) {
				return false;
			}
		}
		return false;
	}

	// PRIVATE METHODS
	// ////////////////

	private byte[] formHeader(InetAddress ip, int port) {
		final Socks5Message request = new Socks5Message(0, ip, port);
		request.data[0] = 0;
		return request.data;
	}

	private byte[] formHeader(String host, int port) {
		final Socks5Message request = new Socks5Message(0, host, port);
		request.data[0] = 0;
		return request.data;
	}

}
