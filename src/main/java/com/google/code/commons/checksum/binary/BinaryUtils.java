/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.code.commons.checksum.binary;

import java.io.UnsupportedEncodingException;

/*
 *   This code is copied almost directly from Apache Gora project and Apache Commons Codec project.
 */
/**
 * Converts integer or long value into a byte array, hexadecimal Strings, or String to and from bytes using the
 * encodings required by the Java specification. These encodings are specified in <a href=
 * "http://java.sun.com/j2se/1.4.2/docs/api/java/nio/charset/Charset.html" >Standard charsets</a>.
 * 
 * @author Apache Software Foundation
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * 
 * @since Commons Checksum 1.0
 */
public class BinaryUtils {

    /**
     * Used to build output as HexUtils
     */
    private static final char[] DIGITS_LOWER = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
            'e', 'f' };

    /**
     * Converts an array of bytes into a String representing the hexadecimal values of each byte in order. The returned
     * String will be double the length of the passed array, as it takes two characters to represent any given byte.
     * 
     * @param data
     *            a byte[] to convert to HexUtils characters
     * @return A String containing hexadecimal characters
     * @since Apache Commons Codec 1.4
     * @since Commons Checksum 1.0
     */
    public static String encodeHexString(byte[] data) {
        int l = data.length;
        char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS_LOWER[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS_LOWER[0x0F & data[i]];
        }
        return new String(out);
    }

    /**
     * Encodes the given string into a sequence of bytes using the UTF-8 charset, storing the result into a new byte
     * array.
     * 
     * @param string
     *            the String to encode, may be <code>null</code>
     * @return encoded bytes, or <code>null</code> if the input string was <code>null</code>
     * @throws IllegalStateException
     *             Thrown when the charset is missing, which should be never according the the Java specification.
     * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/java/nio/charset/Charset.html">Standard charsets</a>
     * @since Commons Checksum 1.0
     */
    public static byte[] getBytesUtf8(String string) {
        if (string == null) {
            return null;
        }
        try {
            return string.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 : " + e);
        }
    }

    /**
     * Converts an int value to a byte array
     * 
     * @param value
     * 		 the value to convert
     * @return returns the byte array representing this int value.
     * @since Commons Checksum 1.0
     */
    public static byte[] toBytes(int value) {
        byte[] b = new byte[4];
        for (int i = 3; i > 0; i--) {
            b[i] = (byte) (value);
            value >>>= 8;
        }
        b[0] = (byte) (value);
        return b;
    }

    /**
     * Converts a long value to a byte array
     * 
     * @param value
     *            the value to convert
     * @param size
     *            the size of byte array representing this long value.
     * @return returns the byte array representing this long value.
     * @since Commons Checksum 1.0
     */
    public static byte[] toBytes(long value, int size) {
        if (size > 8 || size < 1) {
            size = 8;
        }
        byte[] b = new byte[size];
        for (int i = (size - 1); i > 0; i--) {
            b[i] = (byte) (value);
            value >>>= 8;
        }
        b[0] = (byte) (value);
        return b;
    }
}
