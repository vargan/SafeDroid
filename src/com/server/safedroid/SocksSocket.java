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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

public class SocksSocket extends Socket {
	
	protected SocksProxyBase proxy;
	protected String localHost, remoteHost;
	protected InetAddress localIP, remoteIP;
	protected int localPort, remotePort;

	private Socket directSock = null;
	//private Logger log = LoggerFactory.getLogger(SocksSocket.class);

	/**
	 * Tryies to connect to given host and port using default proxy. If no
	 * default proxy speciefied it throws SocksException with error code
	 * SOCKS_NO_PROXY.
	 * 
	 * @param host
	 *            Machine to connect to.
	 * @param port
	 *            Port to which to connect.
	 * @see SocksSocket#SocksSocket(SocksProxyBase,String,int)
	 * @see Socks5Proxy#resolveAddrLocally
	 */
	public SocksSocket(String host, int port) throws SocksException,
			UnknownHostException {
		this(SocksProxyBase.defaultProxy, host, port);
	}

	/**
	 * Connects to host port using given proxy server.
	 * 
	 * @param p
	 *            Proxy to use.
	 * @param host
	 *            Machine to connect to.
	 * @param port
	 *            Port to which to connect.
	 * @throws UnknownHostException
	 *             If one of the following happens:
	 *             <ol>
	 * 
	 *             <li>Proxy settings say that address should be resolved
	 *             locally, but this fails.
	 *             <li>Proxy settings say that the host should be contacted
	 *             directly but host name can't be resolved.
	 *             </ol>
	 * @throws SocksException
	 *             If one of the following happens:
	 *             <ul>
	 *             <li>Proxy is is null.
	 *             <li>Proxy settings say that the host should be contacted
	 *             directly but this fails.
	 *             <li>Socks Server can't be contacted.
	 *             <li>Authentication fails.
	 *             <li>Connection is not allowed by the SOCKS proxy.
	 *             <li>SOCKS proxy can't establish the connection.
	 *             <li>Any IO error occured.
	 *             <li>Any protocol error occured.
	 *             </ul>
	 * @throws IOexception
	 *             if anything is wrong with I/O.
	 * @see Socks5Proxy#resolveAddrLocally
	 */
	public SocksSocket(SocksProxyBase p, String host, int port)
			throws SocksException, UnknownHostException {

		if (p == null) {
			throw new SocksException(SocksProxyBase.SOCKS_NO_PROXY);
		}
		// proxy=p;
		proxy = p.copy();
		remoteHost = host;
		remotePort = port;
		if (proxy.isDirect(host)) {
			remoteIP = InetAddress.getByName(host);
			doDirect();
		} else {
			processReply(proxy.connect(host, port));
		}
	}

	/**
	 * Tryies to connect to given ip and port using default proxy. If no default
	 * proxy speciefied it throws SocksException with error code SOCKS_NO_PROXY.
	 * 
	 * @param ip
	 *            Machine to connect to.
	 * @param port
	 *            Port to which to connect.
	 * @see SocksSocket#SocksSocket(SocksProxyBase,String,int)
	 */
	public SocksSocket(InetAddress ip, int port) throws SocksException {
		this(SocksProxyBase.defaultProxy, ip, port);
	}

	/**
	 * Connects to given ip and port using given Proxy server.
	 * 
	 * @param p
	 *            Proxy to use.
	 * @param ip
	 *            Machine to connect to.
	 * @param port
	 *            Port to which to connect.
	 */
	public SocksSocket(SocksProxyBase p, InetAddress ip, int port)
			throws SocksException {
		if (p == null) {
			throw new SocksException(SocksProxyBase.SOCKS_NO_PROXY);
		}
		this.proxy = p.copy();
		this.remoteIP = ip;
		this.remotePort = port;
		this.remoteHost = ip.getHostName();
		if (proxy.isDirect(remoteIP)) {
			doDirect();
		} else {
			processReply(proxy.connect(ip, port));
		}
	}

	/**
	 * These 2 constructors are used by the SocksServerSocket. This socket
	 * simply overrides remoteHost, remotePort
	 */
	protected SocksSocket(String host, int port, SocksProxyBase proxy) {
		this.remotePort = port;
		this.proxy = proxy;
		this.localIP = proxy.proxySocket.getLocalAddress();
		this.localPort = proxy.proxySocket.getLocalPort();
		this.remoteHost = host;
	}

	protected SocksSocket(InetAddress ip, int port, SocksProxyBase proxy) {
		remoteIP = ip;
		remotePort = port;
		this.proxy = proxy;
		this.localIP = proxy.proxySocket.getLocalAddress();
		this.localPort = proxy.proxySocket.getLocalPort();
		remoteHost = remoteIP.getHostName();
	}

	/**
	 * Same as Socket
	 */
	public void close() throws IOException {
		if (proxy != null) {
			proxy.endSession();
		}
		proxy = null;
	}

	/**
	 * Same as Socket
	 */
	public InputStream getInputStream() {
		return proxy.in;
	}

	/**
	 * Same as Socket
	 */
	public OutputStream getOutputStream() {
		return proxy.out;
	}

	/**
	 * Same as Socket
	 */
	public int getPort() {
		return remotePort;
	}

	/**
	 * Returns remote host name, it is usefull in cases when addresses are
	 * resolved by proxy, and we can't create InetAddress object.
	 * 
	 * @return The name of the host this socket is connected to.
	 */
	public String getHost() {
		return remoteHost;
	}

	/**
	 * Get remote host as InetAddress object, might return null if addresses are
	 * resolved by proxy, and it is not possible to resolve it locally
	 * 
	 * @return Ip address of the host this socket is connected to, or null if
	 *         address was returned by the proxy as DOMAINNAME and can't be
	 *         resolved locally.
	 */
	public InetAddress getInetAddress() {
		if (remoteIP == null) {
			try {
				remoteIP = InetAddress.getByName(remoteHost);
			} catch (final UnknownHostException e) {
				return null;
			}
		}
		return remoteIP;
	}

	/**
	 * Get the port assigned by the proxy for the socket, not the port on locall
	 * machine as in Socket.
	 * 
	 * @return Port of the socket used on the proxy server.
	 */
	public int getLocalPort() {
		return localPort;
	}

	/**
	 * Get address assigned by proxy to make a remote connection, it might be
	 * different from the host specified for the proxy. Can return null if socks
	 * server returned this address as hostname and it can't be resolved
	 * locally, use getLocalHost() then.
	 * 
	 * @return Address proxy is using to make a connection.
	 */
	public InetAddress getLocalAddress() {
		if (localIP == null) {
			try {
				localIP = InetAddress.getByName(localHost);
			} catch (final UnknownHostException e) {
				return null;
			}
		}
		return localIP;
	}

	/**
	 * Get name of the host, proxy has assigned to make a remote connection for
	 * this socket. This method is usefull when proxy have returned address as
	 * hostname, and we can't resolve it on this machine.
	 * 
	 * @return The name of the host proxy is using to make a connection.
	 */
	public String getLocalHost() {
		return localHost;
	}

	/**
	 * Same as socket.
	 */
	public void setSoLinger(boolean on, int val) throws SocketException {
		proxy.proxySocket.setSoLinger(on, val);
	}

	/**
	 * Same as socket.
	 */
	public int getSoLinger(int timeout) throws SocketException {
		return proxy.proxySocket.getSoLinger();
	}

	/**
	 * Same as socket.
	 */
	public void setSoTimeout(int timeout) throws SocketException {
		proxy.proxySocket.setSoTimeout(timeout);
	}

	/**
	 * Same as socket.
	 */
	public int getSoTimeout(int timeout) throws SocketException {
		return proxy.proxySocket.getSoTimeout();
	}

	/**
	 * Same as socket.
	 */
	public void setTcpNoDelay(boolean on) throws SocketException {
		proxy.proxySocket.setTcpNoDelay(on);
	}

	/**
	 * Same as socket.
	 */
	public boolean getTcpNoDelay() throws SocketException {
		return proxy.proxySocket.getTcpNoDelay();
	}

	/**
	 * Get string representation of the socket.
	 */
	public String toString() {
		if (directSock != null) {
			return "Direct connection:" + directSock;
		}
		StringBuffer sb = new StringBuffer();
		sb.append("Proxy:");
		sb.append(proxy);
		sb.append(";");
		sb.append("addr:");
		sb.append(remoteHost);
		sb.append(",port:");
		sb.append(remotePort);
		sb.append(",localport:");
		sb.append(localPort);
		return sb.toString();

	}

	// Private Methods
	// ////////////////

	private void processReply(ProxyMessage reply) throws SocksException {
		localPort = reply.port;
		/*
		 * If the server have assigned same host as it was contacted on it might
		 * return an address of all zeros
		 */
		if (reply.host.equals("0.0.0.0")) {
			localIP = proxy.proxyIP;
			localHost = localIP.getHostName();
		} else {
			localHost = reply.host;
			localIP = reply.ip;
		}
	}

	private void doDirect() throws SocksException {
		try {
			//log.debug("IP: {}_{}", remoteIP, remotePort);
			directSock = new Socket(remoteIP, remotePort);
			proxy.out = directSock.getOutputStream();
			proxy.in = directSock.getInputStream();
			proxy.proxySocket = directSock;
			localIP = directSock.getLocalAddress();
			localPort = directSock.getLocalPort();
		} catch (final IOException io_ex) {
			final int errCode = SocksProxyBase.SOCKS_DIRECT_FAILED;
			throw new SocksException(errCode, "Direct connect failed:", io_ex);
		}
	}

}
