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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

@TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
public class AppRequestService extends VpnService implements Runnable {

	VpnService.Builder builder = new VpnService.Builder();
	ParcelFileDescriptor mInterface;
	Thread mThread;

	final int UDP_HEADER_SIZE = 8;
	int IP_HEADER_SIZE = 20;

	public ByteBuffer ipChecksum(byte[] ipPacket) {
		ByteBuffer checksum = ByteBuffer.allocate(2);
		int ctr = 0;
		long sum = 0;
		int headerLength = 20;
		long data = 0;

		while (ctr < headerLength) {
			// sum consecutive 16 bits
			long term1 = (ipPacket[ctr] << 8) & 0xFF00;
			long term2 = (ipPacket[ctr + 1] & 0x00FF);

			data = term1 | term2;
			sum += data;

			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}

			ctr += 2;
		}

		sum = ~sum;
		sum = sum & 0xFFFF;

		checksum.putShort((short) sum);

		return checksum;
	}

	public ByteBuffer createIPv4Packet(byte[] packet, byte[] tempPacket) {

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream dout = new DataOutputStream(out);

		int totalPacketSize = packet.length + 20;

		// size of the packet -- TCP/UDP segment + IP header = 20 bytes

		long versionIHL = 4;
		versionIHL = versionIHL << 4;
		versionIHL += 5;

		try {

			dout.writeByte((byte) (tempPacket[0] & 0xFF));

			dout.writeByte((byte) (tempPacket[1] & 0xFF));

			dout.writeShort((short) ((short) totalPacketSize & 0xFFFF));

			long identification = (tempPacket[4] & 0xFF);
			identification = identification << 8;
			identification += (tempPacket[5] & 0xFF);

			dout.writeShort((short) identification);

			// flags and fragmentation offset

			dout.writeByte((byte) tempPacket[6] & 0xFF);
			dout.writeByte((byte) tempPacket[7] & 0xFF);

			/*
			 * long flagFragmentation = tempPacket[6] & 0xFF; flagFragmentation
			 * = flagFragmentation << 4; flagFragmentation += tempPacket[7] &
			 * 0xFF;
			 * 
			 * dout.writeShort((short) flagFragmentation);
			 */

			// Time to live

			dout.writeByte((byte) (tempPacket[8] & 0xFF));

			// Protocol
			Log.d("safeDroidResponse", "Protocol logging: "
					+ (tempPacket[9] & 0xFF));

			dout.writeByte((byte) (tempPacket[9] & 0xFF));

			// include checksum = 0
			dout.writeShort((short) 0);

			// source Address
			dout.writeByte((byte) (tempPacket[16] & 0xFF));
			dout.writeByte((byte) (tempPacket[17] & 0xFF));
			dout.writeByte((byte) (tempPacket[18] & 0xFF));
			dout.writeByte((byte) (tempPacket[19] & 0xFF));

			// dst address

			dout.writeByte((byte) (tempPacket[12] & 0xFF));
			dout.writeByte((byte) (tempPacket[13] & 0xFF));
			dout.writeByte((byte) (tempPacket[14] & 0xFF));
			dout.writeByte((byte) (tempPacket[15] & 0xFF));

			// write TCP/UDP segment
			for (int i = 0; i < packet.length; i++) {
				dout.writeByte(packet[i]);
			}
		} catch (IOException e) {
			Log.d("safeDroidTCP", "Ipv4 Packet not written successfully!");
		}
		byte[] ipPacket = out.toByteArray();

		ByteBuffer checksumVal = ipChecksum(ipPacket);

		byte[] checksumBuf = checksumVal.array();

		// Update the checksum
		ipPacket[10] = checksumBuf[0];
		ipPacket[11] = checksumBuf[1];

		ByteBuffer ipPacketBuffer = ByteBuffer.allocate(packet.length + 20);

		ipPacketBuffer.order(ByteOrder.BIG_ENDIAN);

		ipPacketBuffer.put(ipPacket);

		Log.d("safeDroidResponse", Arrays.toString(tempPacket));
		Log.d("safeDroidResponse", Arrays.toString(ipPacketBuffer.array()));
		Log.d("safeDroidResponse", "dataOffsetReserve: "
				+ (tempPacket[20 + 12] & 0xFF));
		Log.d("safeDroidResponse", "PACKET END!!!");

		return ipPacketBuffer;
	}

	public ByteBuffer createIPv6Packet(byte[] packet, byte[] tempPacket) {

		// size of the packet -- TCP/UDP segment + IP header = 40 bytes
		ByteBuffer ipPacket = ByteBuffer.allocate(packet.length + 40);

		return ipPacket;

	}

	public void createUdpPacket(ByteBuffer payload, long sourcePortVal,
			long dstPortVal) {
		/*
		 * UdpPacket.put(ByteBuffer.allocate(2).putLong(sourcePortVal).array());
		 * UdpPacket.put(ByteBuffer.allocate(2).putLong(dstPortVal).array());
		 * UdpPacket.put(ByteBuffer.allocate(2).putLong(payload.capacity())
		 * .array());
		 */
		// checkSum
		// UdpPacket.put(ByteBuffer.allocate(16).putLong().array());
	}

	@SuppressWarnings("static-access")
	public ByteBuffer tcpCheckSum(byte[] tempPacket, byte[] tcpPacket,
			long dataOffset, long payloadLength) {

		ByteBuffer checksum = ByteBuffer.allocate(2);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream dout = new DataOutputStream(out);

		// Source Address -- check for sign bits -- convert to unsigned
		try {
			dout.writeByte((byte) tempPacket[16] & 0xFF);
			dout.writeByte((byte) tempPacket[17] & 0xFF);
			dout.writeByte((byte) tempPacket[18] & 0xFF);
			dout.writeByte((byte) tempPacket[19] & 0xFF);

			// Destination Address -- check for sign bits-- convert to unsigned

			dout.writeByte((byte) tempPacket[12] & 0xFF);
			dout.writeByte((byte) tempPacket[13] & 0xFF);
			dout.writeByte((byte) tempPacket[14] & 0xFF);
			dout.writeByte((byte) tempPacket[15] & 0xFF);

			// Reserved Bits
			dout.writeByte((byte) 0);

			/*
			 * Protocols TCP -- 6
			 */
			int version = tempPacket[0] >> 4;

			dout.writeByte((byte) 6);

			long tcpSegment = dataOffset + payloadLength;

			// TCP packet Segment Length -- dataOffSet field

			dout.writeShort((short) tcpSegment);

		} catch (IOException e) {
			Log.d("safeDroidTCP", "problem in computing checksum pseudo packet");
		}

		byte[] pseudoPacketBuf = out.toByteArray();

		int ctr = 0;

		long sum = 0;
		int lengthBuf = pseudoPacketBuf.length;
		long data = 0;

		while (lengthBuf > 1) {

			data = (((pseudoPacketBuf[ctr] << 8) & 0xFF00) | (pseudoPacketBuf[ctr + 1] & 0x00FF));
			sum += data;
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}

			ctr += 2;

			lengthBuf -= 2;
		}

		ctr = 0;
		lengthBuf = tcpPacket.length;
		// REDO the same for TCP packet
		while (lengthBuf > 1) {
			data = (((tcpPacket[ctr] << 8) & 0xFF00) | (tcpPacket[ctr + 1] & 0x00FF));
			sum += data;

			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}

			ctr += 2;
			lengthBuf -= 2;
		}

		if (lengthBuf > 0) {
			data = ((tcpPacket[ctr] << 8) & 0xFF00);
			sum += data;

			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}

		}

		sum = ~sum;
		sum = sum & 0xFFFF;

		checksum = ByteBuffer.allocate(2);

		checksum.putShort((short) sum);

		Log.d("safeDroidTCP", "checksum Successful!!! in method");

		return checksum;
	}

	public void connectTCP(String socketKey,
			ConcurrentHashMap<String, SocketChannel> socketMapTCP,
			String sourceAddress, long sourcePortVal, String dstAddress,
			long dstPortVal, byte[] tempPacket, FileOutputStream out,
			int ip_header_size, long ip_packet_size) {
		SocketChannel tcpTunnel = null;
		if (!socketMapTCP.containsKey(socketKey)) {
			try {
				tcpTunnel = SocketChannel.open();

			} catch (IOException e) {
				Log.d("safeDroidTCP", "failed to open the socket");
				e.printStackTrace();
			}
			if (protect(tcpTunnel.socket())) {
				Log.d("safeDroidTCP", "TCP Socket protected!");
			} else {
				Log.d("safeDroidTCP", "Failed to protect the TCP socket");
			}

			try {
				tcpTunnel.connect(new InetSocketAddress(dstAddress,
						(int) dstPortVal));
				if (tcpTunnel.isConnected()) {
					Log.d("safeDroidTCP", "TCP connection sucessfull!");
				}
				socketMapTCP.put(socketKey, tcpTunnel);
			} catch (ConnectException e) {
				Log.d("safeDroidTCP", "Connect Exception: check target Ip/Port");

			} catch (SocketTimeoutException e) {
				Log.d("safeDroidTCP", "Timeout TCP socket - address:"
						+ tcpTunnel.socket().getInetAddress());
				return;
			} catch (IOException e) {
				Log.d("safeDroidTCP", "Failed to connect TCP socket - address:"
						+ tcpTunnel.socket().getInetAddress());
				e.printStackTrace();
				return;
			} catch (Exception e) {
				Log.d("safeDroidTCP", "Connection Issues!!: " + e.getCause());

				return;
			}

		} else {
			tcpTunnel = socketMapTCP.get(socketKey);
			if (tcpTunnel == null) {
				try {
					tcpTunnel = SocketChannel.open();
				} catch (IOException e) {
					Log.d("safeDroidTCP", "failed to open the socket");
					e.printStackTrace();
				}
				if (!protect(tcpTunnel.socket())) {
					Log.d("safeDroidTCP", "Failed to protect TCP socket");
				}

				try {
					tcpTunnel.connect(new InetSocketAddress(dstAddress,
							(int) dstPortVal));
					Log.d("safeDroidTCP", "EXISTING TCP connection sucessfull!");
				} catch (ConnectException e) {
					Log.d("safeDroidTCP",
							"Connect Exceptio: check target Ip/Port");
				} catch (SocketTimeoutException e) {
					Log.d("safeDroidTCP", "Timeout TCP socket - address:"
							+ tcpTunnel.socket().getInetAddress());
					return;
				} catch (IOException e) {
					Log.d("safeDroidTCP",
							"Failed to connect TCP socket - address:"
									+ tcpTunnel.socket().getInetAddress());
					e.printStackTrace();
					return;
				}

				catch (Exception e) {
					Log.d("safeDroidTCP", "Connection Issues!!");
					return;
				}
			} else {
				Log.d("safeDroidTCP", "CONNECTION EXISTS!!");
			}

		}

		int dataOffSetIndex = 32;
		byte dataOffSetByte = (byte) tempPacket[32];
		BigInteger dataOffSetVal = BigInteger.valueOf(dataOffSetByte & 0xFF);
		long dataOffSet = dataOffSetVal.longValue() >> 4;

		// Add IP header + TCP header to establish the base index for TCP
		// payload
		long payloadBaseIndex = (ip_header_size + dataOffSet * 4) - 1;

		long payloadLength = ip_packet_size - ip_header_size - (dataOffSet * 4);

		Log.d("safeDroidTCP", "payload length: " + payloadLength);

		long sequenceNumber = 0;

		sequenceNumber += BigInteger.valueOf(
				tempPacket[ip_header_size + 4] & 0xFF).longValue();
		sequenceNumber = sequenceNumber << 8;
		sequenceNumber += BigInteger.valueOf(
				tempPacket[ip_header_size + 5] & 0xFF).longValue();
		sequenceNumber = sequenceNumber << 8;
		sequenceNumber += BigInteger.valueOf(
				tempPacket[ip_header_size + 6] & 0xFF).longValue();
		sequenceNumber = sequenceNumber << 8;
		sequenceNumber += BigInteger.valueOf(
				tempPacket[ip_header_size + 7] & 0xFF).longValue();

		long ackNumber = 0;

		ackNumber += BigInteger.valueOf(tempPacket[ip_header_size + 8] & 0xFF)
				.longValue();
		ackNumber = ackNumber << 8;
		ackNumber += BigInteger.valueOf(tempPacket[ip_header_size + 9] & 0xFF)
				.longValue();
		ackNumber = ackNumber << 8;
		ackNumber += BigInteger.valueOf(tempPacket[ip_header_size + 10] & 0xFF)
				.longValue();
		ackNumber = ackNumber << 8;
		ackNumber += BigInteger.valueOf(tempPacket[ip_header_size + 11] & 0xFF)
				.longValue();

		if (payloadLength == 0) {

			int synFinAck = tempPacket[ip_header_size + 13] & 0x13;

			int flagsVal = tempPacket[ip_header_size + 13] & 0xFFFFFFFF;

			int synFlag = synFinAck >> 1;

			int finFlag = synFinAck & 0x01;

			int ackFlag = (synFinAck & 0x10) >> 4;

			Log.d("safeDroidTCP", "SYNFIN Val: " + synFinAck);
			Log.d("safeDroidTCP", "Flag Val: " + flagsVal);
			Log.d("safeDroidTCP", "SYN Flag Val: " + synFlag);
			Log.d("safeDroidTCP", "FIN Flag Val: " + finFlag);
			Log.d("safeDroidTCP", "ACK Flag Val: " + ackFlag);
			Log.d("safeDroidTCP", "SequenceNumber: " + sequenceNumber);
			Log.d("safeDroidTCP", "ackNumber: " + ackNumber);

			if (synFlag == 1) {

				long responseSequenceNumber = sequenceNumber - 1000;
				long responseAckNumber = sequenceNumber + 1;

				Log.d("safeDroidTCP", "SYN packet");

				// SYN packet

				// ByteBuffer tcpSYNACK = ByteBuffer.allocate(50);

				ByteArrayOutputStream tcpSYNACK = new ByteArrayOutputStream();
				DataOutputStream dataTcpSYNACK = new DataOutputStream(tcpSYNACK);

				try {

					// Reverse Port Values

					// dst becomes sourcePort

					dataTcpSYNACK.writeShort((short) (dstPortVal & 0xFFFF));

					dataTcpSYNACK.writeShort((short) (sourcePortVal & 0xFFFF));

					/*
					 * Add a sequence number = sequence number of the SYN packet
					 * i.e. logical value = 0 and the same for ack number + 1
					 */

					dataTcpSYNACK
							.writeInt((int) ((int) responseSequenceNumber & 0xFFFFFFFF));

					dataTcpSYNACK
							.writeInt((int) ((int) (responseAckNumber) & 0xFFFFFFFF));

					// set flags as 01010000 i.e. 5 words of data offset and 3
					// bits
					// equal to 0 for reserve and 0 for NS bit

					dataTcpSYNACK.writeByte((byte) (tempPacket[12] & 0xFF));

					// Using same flags but setting the SYN flag to 1 and ACK
					// flag to 1
					byte flagsSYNACK = (byte) (18);

					dataTcpSYNACK.writeByte((byte) 18);

					// Set window size -- check for base Index

					dataTcpSYNACK
							.writeByte((byte) (tempPacket[ip_header_size + 14] & 0xFF));

					dataTcpSYNACK
							.writeByte((byte) (tempPacket[ip_header_size + 15] & 0xFF));

					// dataTcpSYNACK.writeShort((short) (windowSize & 0xFFFF));

					// set checksum bits to zero before checksum computation

					dataTcpSYNACK.writeShort((short) (0));

					short urgPtr = (short) (tempPacket[ip_header_size + 18] & 0xFF);
					urgPtr = (short) (urgPtr << 8);
					urgPtr = (short) (urgPtr + (short) (tempPacket[ip_header_size + 19] & 0xFF));

					Log.d("safeDroidTCP", "urgPtr: " + urgPtr);

					dataTcpSYNACK.writeShort((short) (urgPtr));

					// add remainder of the packet -- with or without options

					long remainderLength = ip_packet_size
							- (ip_header_size + 20);
					// Avoided offset by 1 error -- start with the index below
					int baseOptionsIndex = ip_header_size + 20;

					for (int i = baseOptionsIndex; i < ip_packet_size; i++) {
						dataTcpSYNACK.writeByte((byte) tempPacket[i] & 0xFF);
					}

				} catch (IOException e) {

					Log.d("safeDroid", "Failed to build tcp packet");
				}

				byte[] tcpSYNACKpacket = tcpSYNACK.toByteArray();

				Log.d("safeDroidTCP", "TCP packet without checksum complete");

				/*
				 * For SYNACK packet TCP header size is 5 words of 32-bit length
				 * and payload is 0
				 */

				long packetDataOffSet = (long) ((tempPacket[12] >> 4) & 0xFF);

				ByteBuffer checksum = tcpCheckSum(tempPacket, tcpSYNACKpacket,
						packetDataOffSet, 0);

				byte[] checksumBuf = checksum.array();

				// Substitute checksum
				tcpSYNACKpacket[16] = checksumBuf[0];
				tcpSYNACKpacket[17] = checksumBuf[1];

				long versionIHL = tempPacket[0];
				long version = (versionIHL >> 4) & 0xFF;
				ByteBuffer ipPacket = null;
				if (version == 4) {
					ipPacket = createIPv4Packet(tcpSYNACKpacket, tempPacket);

				} else if (version == 6) {
					ipPacket = createIPv6Packet(tcpSYNACKpacket, tempPacket);
				}

				Log.d("safeDroidTCP", "SYN IPv4 Packet constructed!");

				try {

					out.write(ipPacket.array(), 0, ipPacket.array().length);
					Log.d("safeDroidTCP", "Write Successfull!!!!");

				} catch (IOException e) {
					Log.d("safeDroidTCP", "SYNACK IPv4 Packet NOT written!");
					e.printStackTrace();
				}

			}

			if (finFlag == 1) {
				Log.d("safeDroidTCP", "FIN packet");

				// FIN packet
				try {
					tcpTunnel.close();
					Log.d("safeDroidTCP", "Socket close successful");
				} catch (IOException e) {
					Log.d("safeDroidTCP", "Socket close NOT scessful");
					e.printStackTrace();
				}
			}

			else if (ackFlag == 1 && finFlag != 1 && synFlag != 1) {

				Log.d("safeDroidTCPACK", "ACK PACKETS!!");
				Log.d("safeDroidTCPACK", "Source Address: " + sourceAddress);
				Log.d("safeDroidTCPACK", "Destination Address: " + dstAddress);
				Log.d("safeDroidTCPACK", "ACK number: " + ackNumber);
				Log.d("safeDroidTCPACK", "sequence number: " + sequenceNumber);

			}

			else if (ackFlag != 1 && finFlag != 1 && synFlag != 1) {
				Log.d("safeDroidTCPACK", "EMPTY FLAGS!!");
			}

		}

		// check if simple ack -- then drop the packet

		// check it SYN

		// check if SYN-ACK

		// check of FIN

		else {
			Log.d("safeDroidTCPPayload", "PAYLOAD PACKETS!!");

			// if already in the hashMap -- then continue

			// if not then TCP reset
		}

	}

	public ByteBuffer udpChecksum(byte[] udpHeader, byte[] tempPacket,
			int udpPacketLength) {
		ByteBuffer pseudoHeader = ByteBuffer.allocate(20);

		// write the address of the remote host as the destination address
		pseudoHeader.put((byte) (tempPacket[15] & 0xFF));
		pseudoHeader.put((byte) (tempPacket[17] & 0xFF));
		pseudoHeader.put((byte) (tempPacket[18] & 0xFF));
		pseudoHeader.put((byte) (tempPacket[19] & 0xFF));

		// write the local address as destination
		pseudoHeader.put((byte) (tempPacket[12] & 0xFF));
		pseudoHeader.put((byte) (tempPacket[13] & 0xFF));
		pseudoHeader.put((byte) (tempPacket[14] & 0xFF));
		pseudoHeader.put((byte) (tempPacket[15] & 0xFF));

		// put zeroes
		pseudoHeader.put((byte) (0));

		// protocol UDP -- 17
		pseudoHeader.put((byte) (17));

		// put udp packet length
		pseudoHeader.putShort((short) (udpPacketLength));

		// write udp header
		pseudoHeader.put(udpHeader);

		ByteBuffer checksum = ByteBuffer.allocate(2);
		int ctr = 0;
		long sum = 0;
		int headerLength = 20;
		long data = 0;

		byte[] udpPacket = pseudoHeader.array();
		while (ctr < headerLength) {
			// sum consecutive 16 bits
			long term1 = (udpPacket[ctr] << 8) & 0xFF00;
			long term2 = (udpPacket[ctr + 1] & 0x00FF);

			data = term1 | term2;
			sum += data;

			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}

			ctr += 2;
		}

		sum = ~sum;
		sum = sum & 0xFFFF;

		checksum.putShort((short) sum);
		Log.d("safeDroidUDP", "UDP checksum complete!");

		return checksum;

	}

	public ByteBuffer createUDPpacket(byte[] tempPacket,
			ByteBuffer responsePayload, long sourcePortVal, long dstPortVal,
			int responseLength) {

		int packetLength = responseLength + 8;
		// udpPacket = header(8) bytes + payload
		ByteBuffer udpPacketHeader = ByteBuffer.allocate(8);
		udpPacketHeader.order(ByteOrder.BIG_ENDIAN);

		// flipped ports
		udpPacketHeader.putShort((short) dstPortVal);
		udpPacketHeader.putShort((short) sourcePortVal);

		// write length

		udpPacketHeader.putShort((short) packetLength);

		// default checksum value
		udpPacketHeader.putShort((short) 0);
		byte[] udpHeader = udpPacketHeader.array();

		ByteBuffer checksum = udpChecksum(udpHeader, tempPacket, packetLength);
		byte[] checksumBuffer = checksum.array();

		udpHeader[6] = checksumBuffer[0];
		udpHeader[7] = checksumBuffer[1];

		ByteBuffer udpPacket = ByteBuffer.allocate(packetLength);
		udpPacket.order(ByteOrder.BIG_ENDIAN);
		Log.d("safeDroidUDP", "UDP packet created");
		Log.d("safeDroidUDP", "Buffer size: " + packetLength);

		udpPacket.put(udpHeader);
		Log.d("safeDroidUDP", "Buffer Remaining size: " + udpPacket.remaining());

		byte[] responsePayloadBuffer = responsePayload.array();

		if (responsePayload.limit() > 0) {
			for (int y = 0; y < responseLength; y++) {
				udpPacket.put(responsePayloadBuffer[y]);
			}
		}
		Log.d("safeDroidUDP", "Payload written");
		udpPacket.limit(packetLength);
		

		return udpPacket;
	}

	public void connectUDP(String socketKey,
			ConcurrentHashMap<String, DatagramChannel> socketMapUDP,
			String sourceAddress, long sourcePortVal, String dstAddress,
			long dstPortVal, byte[] tempPacket, FileOutputStream out,
			int ip_header_size) {
		DatagramChannel udpChannel = null;

		InetSocketAddress dest = new InetSocketAddress(dstAddress,
				(int) dstPortVal);
		if (!socketMapUDP.containsKey(socketKey)) {

			try {
				udpChannel = DatagramChannel.open();
				udpChannel.configureBlocking(false);

			} catch (IOException e) {
				Log.d("safeDroidUDP", "failed to open the socket");
				e.printStackTrace();
				return;
			}

			if (protect(udpChannel.socket())) {
				Log.d("safeDroidUDP", "Protected the socket");
			} else {
				Log.d("safeDroidUDP", "Socket not protected");
				return;
			}
			try {
				udpChannel.connect(dest);
				if (udpChannel.isConnected()) {
					Log.d("safeDroidUDP", "Connection Successful");
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			socketMapUDP.put(socketKey, udpChannel);

		}

		else {
			udpChannel = socketMapUDP.get(socketKey);
			if (udpChannel == null) {
				try {
					udpChannel = DatagramChannel.open();
					udpChannel.configureBlocking(false);

				} catch (IOException e) {
					Log.d("safeDroidUDP", "Failed to open UDP socket");
					e.printStackTrace();
				}

				if (protect(udpChannel.socket())) {
					Log.d("safeDroidUDP", "Socket protected!");
				} else {
					Log.d("safeDroidUDP", "Failed to protect socket");
				}

				try {
					udpChannel.connect(new InetSocketAddress(dstAddress,
							(int) dstPortVal));
					if (udpChannel.isConnected()) {
						Log.d("safeDroidUDP", "Connection Successfull");
					}

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}

		}

		long packetLength = (tempPacket[ip_header_size + 4] & 0xFF);
		packetLength = packetLength << 8;
		packetLength = packetLength + (tempPacket[ip_header_size + 5] & 0xFF);

		long payloadLength = packetLength - UDP_HEADER_SIZE;
		ByteBuffer payload = ByteBuffer.allocate((int) payloadLength);
		payload.order(ByteOrder.BIG_ENDIAN);

		int basePayloadIndex = ip_header_size + 8;
		int payloadCtr = 0;
		int length = 0;

		Log.d("safeDroidUDP", Arrays.toString(tempPacket));
		Log.d("safeDroidUDP", "Payload Length: " + payloadLength);

		while (payloadCtr < payloadLength) {
			payload.put((byte) (tempPacket[basePayloadIndex + payloadCtr] & 0xFF));
			payloadCtr++;
		}

		ByteBuffer responsePayload = ByteBuffer.allocate(32767);

		byte[] payloadArray = payload.array();
		Log.d("safeDroidUDP", Arrays.toString(payload.array()));

		try {
			udpChannel.socket().setSendBufferSize(32767);
			udpChannel.socket().setReceiveBufferSize(32767);

			payload.position(0);
			int writeVal = udpChannel.write(payload);

			Log.d("safeDroidUDP", "Bytes written on channel: " + writeVal);
			if (writeVal > 0) {
				payload.clear();
			}
			responsePayload.clear();
			responsePayload.order(ByteOrder.BIG_ENDIAN);
			int responseLength = udpChannel.read(responsePayload);

			Log.d("safeDroidUDP", "Bytes read from channel: " + responseLength);

			if (responseLength > 0) {
				Log.d("safeDroidUDP", "GOT UDP RESPONSE!!!!");
				Log.d("safeDroidUDP", Arrays.toString(responsePayload.array()));

				responsePayload.limit(responseLength);

				ByteBuffer udpPacket = createUDPpacket(tempPacket,
						responsePayload, sourcePortVal, dstPortVal,
						responseLength);

				int version = tempPacket[0] >> 4;
				if (version == 4) {
					// IPv4 packet

					ByteBuffer ipPacket = createIPv4Packet(udpPacket.array(),
							tempPacket);
					out.write(ipPacket.array());
					Log.d("safeDroidUDP", "Packet Written to TUN interface");

				} else if (version == 6) {
					// IPv6 packet

				}
			}

		} catch (IOException e) {
			Log.d("safeDroidUDP", "Read/Write Exception!!!");
			e.printStackTrace();
		}

	}

	public int onStartCommand(Intent intent, int flags, int startId) {
		if (mThread != null) {
			mThread.interrupt();
		}

		mThread = new Thread(this);
		mThread.start();

		// change back to sticky ?
		return START_NOT_STICKY;

	}

	public int createPacketList(byte[] packetBuffer, int length,
			ArrayList<ByteBuffer> packetList) {
		// check for IPv4 or IPv6 otherwise reject the packet

		int ctr = 0;
		int versionIndex = 0;

		while (versionIndex < length) {
			int versionIP = ((packetBuffer[versionIndex] >> 4) & 0xFF);

			if (versionIP == 4) {

				// IPv4

				int packetLength = packetBuffer[versionIndex + 2] & 0xFF;
				packetLength = packetLength << 8;
				packetLength = packetLength
						+ (packetBuffer[versionIndex + 3] & 0xFF);

				int finalIndex = versionIndex + packetLength - 1;

				if (finalIndex <= length) {
					ByteBuffer packet = ByteBuffer.allocate(packetLength);
					packet.order(ByteOrder.BIG_ENDIAN);
					packet.put(packetBuffer, versionIndex, packetLength);
					packetList.add(packet);
					byte[] sampleArray = packet.array();
					versionIndex += packetLength;
				} else {
					return (versionIndex);
				}

			} else if (versionIP == 6) {

				int payloadLength = (packetBuffer[versionIndex + 4] & 0xFF);
				payloadLength = payloadLength << 8;
				payloadLength += (packetBuffer[versionIndex + 5] & 0xFF);

				int finalIndex = (versionIndex + 40 + payloadLength) - 1;

				if (finalIndex <= length) {

					ByteBuffer packet = ByteBuffer.allocate(40 + payloadLength);

					packet.put(packetBuffer, versionIndex, (payloadLength + 40));
					packetList.add(packet);

					versionIndex += payloadLength + 40;

				} else {
					return (versionIndex);
				}

			}

			else {
				versionIndex += 1;
				Log.d("safeDroidIllegal", "Wrong Version IHL code found!!!");
			}

		}

		return versionIndex;
	}

	public void resolvePacket(ByteBuffer packet,
			ConcurrentHashMap<String, DatagramChannel> socketMapUDP,
			ConcurrentHashMap<String, SocketChannel> socketMapTCP,
			FileOutputStream out) {
		byte[] tempPacket = packet.array();

		byte versionIHL = (byte) tempPacket[0];
		int version = (int) versionIHL >> 4;

		if (version == 4) {
			int IHL = versionIHL & 0x0F;
			int ip_header_size = 0;
			long ip_packet_size = BigInteger.valueOf(tempPacket[2] & 0xFF)
					.longValue();
			ip_packet_size = ip_packet_size << 8;
			ip_packet_size += BigInteger.valueOf(tempPacket[3] & 0xFF)
					.longValue();

			if (IHL == 5) {
				ip_header_size = 20;

			} else {
				ip_header_size = IHL * 4;
			}

			Log.d("safeDroid", "IPv4 Header Size" + IP_HEADER_SIZE);

			String sourceAddress = BigInteger.valueOf(tempPacket[12] & 0xFF)
					+ "." + BigInteger.valueOf(tempPacket[13] & 0xFF) + "."
					+ BigInteger.valueOf(tempPacket[14] & 0xFF) + "."
					+ BigInteger.valueOf(tempPacket[15] & 0xFF);

			String dstAddress = BigInteger.valueOf(tempPacket[16] & 0xFF) + "."
					+ BigInteger.valueOf(tempPacket[17] & 0xFF) + "."
					+ BigInteger.valueOf(tempPacket[18] & 0xFF) + "."
					+ BigInteger.valueOf(tempPacket[19] & 0xFF);

			BigInteger protocol = BigInteger.valueOf(tempPacket[9] & 0xFF);

			// Check for protocol type

			if (protocol.equals(new BigInteger("6"))) {

				Log.d("safeDroidTCP", sourceAddress);
				Log.d("safeDroidTCP", dstAddress);
				Log.d("safeDroidTCP", "IPv4 TCP: " + protocol);

				long sourcePortVal = 0;
				BigInteger sourcePort1 = BigInteger
						.valueOf(tempPacket[20] & 0xFF);
				BigInteger sourcePort2 = BigInteger
						.valueOf(tempPacket[21] & 0xFF);

				sourcePortVal += sourcePort1.longValue();
				sourcePortVal = sourcePortVal << 8;
				sourcePortVal += sourcePort2.longValue();

				long dstPortVal = 0;

				BigInteger dstPort1 = BigInteger.valueOf(tempPacket[22] & 0xFF);

				BigInteger dstPort2 = BigInteger.valueOf(tempPacket[23] & 0xFF);

				dstPortVal += dstPort1.longValue();

				dstPortVal = dstPortVal << 8;
				dstPortVal += dstPort2.longValue();

				Log.d("SafeDroidTCP", "" + sourcePortVal);

				Log.d("SafeDroidTCP", "" + dstPortVal);

				String socketKey = sourceAddress + "|" + sourcePortVal + "|"
						+ dstAddress + "|" + dstPortVal;

				Log.d("safeDroidTCP", "" + sourcePortVal);
				Log.d("safeDroidTCP", "" + dstPortVal);

				if (!sourceAddress.equals("10.0.0.1")) {

					Log.d("safeDroidAddr", sourceAddress);
					Log.d("safeDroidAddr", dstAddress);
					Log.d("safeDroidAddr", "" + sourcePortVal);
					Log.d("safeDroidAddr", "" + dstPortVal);

				}

				connectTCP(socketKey, socketMapTCP, sourceAddress,
						sourcePortVal, dstAddress, dstPortVal, tempPacket, out,
						ip_header_size, ip_packet_size);

			}

			else if (protocol.equals(new BigInteger("17"))) {

				Log.d("safeDroidUDP", sourceAddress);
				Log.d("safeDroidUDP", dstAddress);
				Log.d("Protocol", "IPv4 UDP: " + protocol);

				long sourcePortVal = 0;
				BigInteger sourcePort1 = BigInteger
						.valueOf(tempPacket[20] & 0xFF);
				BigInteger sourcePort2 = BigInteger
						.valueOf(tempPacket[21] & 0xFF);

				sourcePortVal += sourcePort1.longValue();
				sourcePortVal = sourcePortVal << 8;
				sourcePortVal += sourcePort2.longValue();

				long dstPortVal = 0;

				BigInteger dstPort1 = BigInteger.valueOf(tempPacket[22] & 0xFF);

				BigInteger dstPort2 = BigInteger.valueOf(tempPacket[23] & 0xFF);

				dstPortVal += dstPort1.longValue();

				dstPortVal = dstPortVal << 8;
				dstPortVal += dstPort2.longValue();
				String socketKey = sourceAddress + "|" + sourcePortVal + "|"
						+ dstAddress + "|" + dstPortVal;

				Log.d("safeDroidUDP", "" + sourcePortVal);
				Log.d("safeDroidUDP", "" + dstPortVal);

				connectUDP(socketKey, socketMapUDP, sourceAddress,
						sourcePortVal, dstAddress, dstPortVal, tempPacket, out,
						ip_header_size);

			}

			else {
				Log.d("Protocol", "" + protocol);
			}

		}

		else if (version == 6) { // Find source and dst address

			StringBuffer sourceAddressBuffer = new StringBuffer();
			StringBuffer dstAddressBuffer = new StringBuffer();

			int ctr = 0;
			int sourceBaseIndex = 8;
			int dstBaseIndex = 24;

			while (ctr < 4) {
				int ctr_element = 1;
				long addrElement = 0;

				while ((ctr_element % 5) != 0) {
					addrElement += (tempPacket[sourceBaseIndex
							+ ((ctr * 4) + (ctr_element - 1))] & 0xFF);
					addrElement = addrElement << 8;
					ctr_element += 1;
				}

				sourceAddressBuffer.append(Long.toString(addrElement) + ".");
			}

			ctr = 0;

			while (ctr < 4) {
				int ctr_element = 1;
				long addrElement = 0;

				while ((ctr_element % 5) != 0) {
					addrElement += (tempPacket[dstBaseIndex
							+ ((ctr * 4) + (ctr_element - 1))] & 0xFF);
					addrElement = addrElement << 8;
					ctr_element += 1;
				}

				dstAddressBuffer.append(Long.toString(addrElement) + ".");
				ctr += 1;

			}

			String sourceAddress = sourceAddressBuffer.substring(0,
					sourceAddressBuffer.length() - 1);

			String dstAddress = dstAddressBuffer.substring(0,
					dstAddressBuffer.length() - 1);

			Log.d("safeDroid IPv6 source address", sourceAddress);
			Log.d("safeDroid IPv6 dst address", dstAddress);

			// Find transport layer protocol

			BigInteger protocol = BigInteger.valueOf(tempPacket[6] & 0xFF);

			if (protocol.equals(new BigInteger("6"))) {

				Log.d("safeDroid", "IPv6 TCP");

				long sourcePortVal = tempPacket[40] & 0xFF;
				sourcePortVal = sourcePortVal << 8;
				sourcePortVal = sourcePortVal + (tempPacket[41] & 0xFF);

				long dstPortVal = tempPacket[42] & 0xFF;
				dstPortVal = dstPortVal << 8;
				dstPortVal = dstPortVal + (tempPacket[43] & 0xFF);

				String socketKey = sourceAddress + "|" + sourcePortVal + "|"
						+ dstAddress + "|" + dstPortVal;

			}

			else if (protocol.equals(new BigInteger("17"))) {
				// UDP TO be implemented Log.d("safeDroid", "IPv6 UDP");

				long sourcePortVal = tempPacket[40] & 0xFF;
				sourcePortVal = sourcePortVal << 8;
				sourcePortVal = sourcePortVal + (tempPacket[41] & 0xFF);

				long dstPortVal = tempPacket[42] & 0xFF;
				dstPortVal = dstPortVal << 8;
				dstPortVal = dstPortVal + (tempPacket[43] & 0xFF);

				String socketKey = sourceAddress + "|" + sourcePortVal + "|"
						+ dstAddress + "|" + dstPortVal;

				connectUDP(socketKey, socketMapUDP, sourceAddress,
						sourcePortVal, dstAddress, dstPortVal, tempPacket, out,
						40);

			}

			else {
				Log.d("SafeDroidProtocol", "Protocol: " + protocol);
			}

		}

		else {
			// Log.d("safeDroid version", "" + version + "");
		}
	}

	public synchronized void run() {

		ConcurrentHashMap<String, DatagramChannel> socketMapUDP = new ConcurrentHashMap<String, DatagramChannel>();
		ConcurrentHashMap<String, SocketChannel> socketMapTCP = new ConcurrentHashMap<String, SocketChannel>();

		mInterface = builder.setSession("SafeDroidVPNService")
				.addAddress("192.168.2.73", 24).addRoute("0.0.0.0", 0)
				.establish();

		FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());

		FileOutputStream out = new FileOutputStream(
				mInterface.getFileDescriptor());

		ByteBuffer packetBuffer = ByteBuffer.allocate(32767);

		@SuppressWarnings("unused")
		boolean idle = true;
		int length = 0;

		int packetResidueIndex = 0;
		while (true) {
			// idle = true;
			try {
				length = in.read(packetBuffer.array());

				if (length > 0) {
					packetBuffer.limit(length);
					ArrayList<ByteBuffer> packetList = new ArrayList<ByteBuffer>();

					packetResidueIndex = createPacketList(packetBuffer.array(),
							length, packetList);

					if (packetResidueIndex != length) {
						packetBuffer.put(Arrays.copyOfRange(
								packetBuffer.array(), packetResidueIndex,
								length), 0, (length - packetResidueIndex));

						Log.d("safeDroidResidue",
								"PacketResidue Ignored!!!!!!!");

					}
					int packetListSize = packetList.size();

					Log.d("safeDroidInput", "packets: " + packetListSize);

					// now call getResponseMethod for every packet

					for (int i = 0; i < packetList.size(); i++) {

						resolvePacket(packetList.get(i), socketMapUDP,
								socketMapTCP, out);

					}

				}

			} catch (IOException e) {

				Log.d("safeDroid", "IO Exception socket");
				e.printStackTrace();
			}
		}

	}

	@Override
	public void onDestroy() {
		if (mThread != null) {
			mThread.interrupt();
		}
		super.onDestroy();
	}

}
