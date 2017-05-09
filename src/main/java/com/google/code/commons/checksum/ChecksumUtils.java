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

package com.google.code.commons.checksum;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

import com.google.code.commons.checksum.binary.BinaryUtils;
import com.google.code.commons.checksum.digest.DigestUtils;

/**
 * Operations to simplify common {@link java.util.zip.Checksum} and {@link java.security.MessageDigest} tasks. This
 * class is thread safe.
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * 
 * @since Commons Checksum 1.0
 */
public class ChecksumUtils extends DigestUtils {

    /**
     * Calculates the {@link Adler32 Adler-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link Adler32 Adler-32} checksum
     * @since Commons Checksum 1.0
     */
    public static byte[] adler32(byte[] data) {
        return getBytes32(getValue(getAdler32Checksum(), data));
    }

    /**
     * Calculates the {@link Adler32 Adler-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link Adler32 Adler-32} checksum
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    public static byte[] adler32(InputStream data) throws IOException {
        return getBytes32(getValue(getAdler32Checksum(), data));
    }

    /**
     * Calculates the {@link Adler32 Adler-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link Adler32 Adler-32} checksum
     * @since Commons Checksum 1.0
     */
    public static byte[] adler32(String data) {
        return adler32(getBytesUtf8(data));
    }

    /**
     * Calculates the {@link Adler32 Adler-32} checksum and returns the value as a 8 character hex string .
     * 
     * @param data
     *            Data to check
     * @return {@link Adler32 Adler-32} checksum as a hex string
     * @since Commons Checksum 1.0
     */
    public static String adler32Hex(byte[] data) {
        return BinaryUtils.encodeHexString(adler32(data));
    }

    /**
     * Calculates the {@link Adler32 Adler-32} checksum and returns the value as a 8 character hex string .
     * 
     * @param data
     *            Data to check
     * @return {@link Adler32 Adler-32} checksum as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    public static String adler32Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(adler32(data));
    }

    /**
     * Calculates the {@link Adler32 Adler-32} checksum and returns the value as a 8 character hex string .
     * 
     * @param data
     *            Data to check
     * @return {@link Adler32 Adler-32} checksum as a hex string
     * @since Commons Checksum 1.0
     */
    public static String adler32Hex(String data) {
        return BinaryUtils.encodeHexString(adler32(data));
    }

    /**
     * Calculates the {@link CRC32 CRC-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link CRC32 CRC-32} checksum
     * @since Commons Checksum 1.0
     */
    public static byte[] crc32(byte[] data) {
        return getBytes32(getValue(getCRC32Checksum(), data));
    }

    /**
     * Calculates the {@link CRC32 CRC-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link CRC32 CRC-32} checksum
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    public static byte[] crc32(InputStream data) throws IOException {
        return getBytes32(getValue(getCRC32Checksum(), data));
    }

    /**
     * Calculates the {@link CRC32 CRC-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link CRC32 CRC-32} checksum
     * @since Commons Checksum 1.0
     */
    public static byte[] crc32(String data) {
        return crc32(getBytesUtf8(data));
    }

    /**
     * Calculates the {@link CRC32 CRC-32} checksum and returns the value as a 8 character hex string.
     * 
     * @param data
     *            Data to check
     * @return {@link CRC32 CRC-32} checksum as a hex string
     * @since Commons Checksum 1.0
     */
    public static String crc32Hex(byte[] data) {
        return BinaryUtils.encodeHexString(crc32(data));
    }

    /**
     * Calculates the {@link CRC32 CRC-32} checksum and returns the value as a 8 character hex string.
     * 
     * @param data
     *            Data to check
     * @return {@link CRC32 CRC-32} checksum as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    public static String crc32Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(crc32(data));
    }

    /**
     * Calculates the {@link CRC32 CRC-32} checksum and returns the value as a 8 character hex string.
     * 
     * @param data
     *            Data to check
     * @return {@link CRC32 CRC-32} checksum as a hex string
     * @since Commons Checksum 1.0
     */
    public static String crc32Hex(String data) {
        return BinaryUtils.encodeHexString(crc32(data));
    }

    /**
     * Calculates the {@link Fletcher32 Fletcher-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link Fletcher32 Fletcher-32} checksum
     * @since Commons Checksum 1.0
     */
    public static byte[] fletcher32(byte[] data) {
        return getBytes32(getValue(getFletcher32Checksum(), data));
    }

    /**
     * Calculates the {@link Fletcher32 Fletcher-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link Fletcher32 Fletcher-32} checksum
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    public static byte[] fletcher32(InputStream data) throws IOException {
        return getBytes32(getValue(getFletcher32Checksum(), data));
    }

    /**
     * Calculates the {@link Fletcher32 Fletcher-32} checksum and returns the value as a 4 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to check
     * @return {@link Fletcher32 Fletcher-32} checksum
     * @since Commons Checksum 1.0
     */
    public static byte[] fletcher32(String data) {
        return fletcher32(getBytesUtf8(data));
    }

    /**
     * Calculates the {@link Fletcher32 Fletcher-32} checksum and returns the value as a 8 character hex string.
     * 
     * @param data
     *            Data to check
     * @return {@link Fletcher32 Fletcher-32} checksum as a hex string
     * @since Commons Checksum 1.0
     */
    public static String fletcher32Hex(byte[] data) {
        return BinaryUtils.encodeHexString(fletcher32(data));
    }

    /**
     * Calculates the {@link Fletcher32 Fletcher-32} checksum and returns the value as a 8 character hex string.
     * 
     * @param data
     *            Data to check
     * @return {@link Fletcher32 Fletcher-32} checksum as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    public static String fletcher32Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(fletcher32(data));
    }

    /**
     * Calculates the {@link Fletcher32 Fletcher-32} checksum and returns the value as a 8 character hex string.
     * 
     * @param data
     *            Data to check
     * @return {@link Fletcher32 Fletcher-32} checksum as a hex string
     * @since Commons Checksum 1.0
     */
    public static String fletcher32Hex(String data) {
        return BinaryUtils.encodeHexString(fletcher32(data));
    }

    /**
     * Returns an {@link Adler32 Adler-32} checksum.
     * 
     * @return An {@link Adler32 Adler-32} checksum instance.
     * @since Commons Checksum 1.0
     */
    private static Checksum getAdler32Checksum() {
        return new Adler32();
    }

    /**
     * Converts a long value to a four byte array
     * 
     * @param value
     *            the value to convert
     * @return returns the byte array representing this long value.
     * @since Commons Checksum 1.0
     */
    protected static byte[] getBytes32(long value) {
        return BinaryUtils.toBytes(value, 4);
    }

    /**
     * Returns an {@link CRC32 CRC-32} checksum.
     * 
     * @return An {@link CRC32 CRC-32} checksum instance.
     * @since Commons Checksum 1.0
     */
    private static Checksum getCRC32Checksum() {
        return new CRC32();
    }

    /**
     * Returns an {@link Fletcher32 Fletcher-32} checksum.
     * 
     * @return An {@link Fletcher32 Fletcher-32} checksum instance.
     * @since Commons Checksum 1.0
     */
    private static Checksum getFletcher32Checksum() {
        return new Fletcher32();
    }

    /**
     * Returns the checksum value for the data.
     * 
     * @param checksum
     *            The Checksum to use (e.g. CRC32)
     * @param data
     *            Data to check
     * @return Returns the checksum value.
     * @since Commons Checksum 1.0
     */
    protected static long getValue(Checksum checksum, byte[] data) {
        checksum.update(data, 0, data.length);
        return checksum.getValue();
    }

    /**
     * Read through an InputStream and returns the checksum value for the data.
     * 
     * @param checksum
     *            The Checksum to use (e.g. CRC32)
     * @param data
     *            Data to check
     * @return Returns the checksum value.
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    protected static long getValue(Checksum checksum, InputStream data) throws IOException {
        byte[] buffer = new byte[STREAM_BUFFER_LENGTH];
        int read = data.read(buffer, 0, STREAM_BUFFER_LENGTH);

        while (read > -1) {
            checksum.update(buffer, 0, read);
            read = data.read(buffer, 0, STREAM_BUFFER_LENGTH);
        }

        return checksum.getValue();
    }

}
