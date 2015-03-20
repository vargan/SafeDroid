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

public interface UDPEncapsulation {
	/**
	 * This method should provide any authentication depended transformation on
	 * datagrams being send from/to the client.
	 * 
	 * @param data
	 *            Datagram data (including any SOCKS related bytes), to be
	 *            encapsulated/decapsulated.
	 * @param out
	 *            Wether the data is being send out. If true method should
	 *            encapsulate/encrypt data, otherwise it should decapsulate/
	 *            decrypt data.
	 * @throw IOException if for some reason data can be transformed correctly.
	 * @return Should return byte array containing data after transformation. It
	 *         is possible to return same array as input, if transformation only
	 *         involves bit mangling, and no additional data is being added or
	 *         removed.
	 */
	byte[] udpEncapsulate(byte[] data, boolean out) throws java.io.IOException;
}
