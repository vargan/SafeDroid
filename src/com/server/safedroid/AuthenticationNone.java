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

import java.io.InputStream;
import java.io.OutputStream;

public class AuthenticationNone implements Authentication {
	
	public Object[] doSocksAuthentication(final int methodId,
			final java.net.Socket proxySocket) throws java.io.IOException {

		if (methodId != 0) {
			return null;
		}

		InputStream in = proxySocket.getInputStream();
		OutputStream out = proxySocket.getOutputStream();
		return new Object[] { in, out };
	}

}
