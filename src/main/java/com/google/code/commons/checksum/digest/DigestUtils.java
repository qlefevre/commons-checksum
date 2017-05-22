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

package com.google.code.commons.checksum.digest;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.concurrent.ConcurrentHashMap;

import com.google.code.commons.checksum.binary.BinaryUtils;

/*
 *   This code is copied almost directly from Apache Commons Codec project.
 */
/**
 * Operations to simplify common {@link java.security.MessageDigest} tasks. This class is thread safe.<br>
 * Original source code comes from Apache Commons Codec. See <i>org.apache.commons.codec.digest.DigestUtils</i>.
 * 
 * @author Apache Software Foundation
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * 
 * @since Commons Checksum 1.0
 * @since Apache Commons Codec 1.5
 */
public class DigestUtils {

    protected static final int STREAM_BUFFER_LENGTH = 1024;

    private static ConcurrentHashMap<String, String> digestProviderNameMap = new ConcurrentHashMap<String, String>(14);

    /**
     * Read through an InputStream and returns the digest for the data
     * 
     * @param digest
     *            The MessageDigest to use (e.g. MD5)
     * @param data
     *            Data to digest
     * @return MD5 digest
     * @throws IOException
     *             On error reading from the stream
     * @since Commons Checksum 1.0
     */
    protected static byte[] digest(MessageDigest digest, InputStream data) throws IOException {
        byte[] buffer = new byte[STREAM_BUFFER_LENGTH];
        int read = data.read(buffer, 0, STREAM_BUFFER_LENGTH);

        while (read > -1) {
            digest.update(buffer, 0, read);
            read = data.read(buffer, 0, STREAM_BUFFER_LENGTH);
        }

        return digest.digest();
    }

    /**
     * Calls {@link BinaryUtils#getBytesUtf8(String)}
     * 
     * @param data
     *            the String to encode
     * @return encoded bytes
     * @since Commons Checksum 1.0
     */
    protected static byte[] getBytesUtf8(String data) {
        return BinaryUtils.getBytesUtf8(data);
    }

    /**
     * Returns a <code>MessageDigest</code> for the given <code>algorithm</code> .
     * 
     * @param algorithm
     *            the name of the algorithm requested. See <a href=
     *            "http://java.sun.com/j2se/1.3/docs/guide/security/CryptoSpec.html#AppA" >Appendix A in the Java
     *            Cryptography Architecture API Specification &amp; Reference</a> for information about standard algorithm
     *            names.
     * @return a Message Digest object that implements the specified algorithm.
     * @see MessageDigest#getInstance(String)
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    protected static MessageDigest getDigest(String algorithm) {
        try {
            String providerName = getDigestProviderName(algorithm);
            if (providerName == null) {
                return MessageDigest.getInstance(algorithm);
            }
            return MessageDigest.getInstance(algorithm, providerName);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    /**
     * Returns the digest provider name associated to the given algorithm.
     * 
     * @param algorithm
     *            the name of the algorithm requested. See <a href=
     *            "http://java.sun.com/j2se/1.3/docs/guide/security/CryptoSpec.html#AppA" >Appendix A in the Java
     *            Cryptography Architecture API Specification &amp; Reference</a> for information about standard algorithm
     *            names.
     * @return the digest provider name in function of algorithm.
     * @since Commons Checksum 1.0
     */
    protected static String getDigestProviderName(String algorithm) {
        if (!digestProviderNameMap.isEmpty() && digestProviderNameMap.containsKey(algorithm)) {
            return digestProviderNameMap.get(algorithm);
        }
        return null;
    }
    
    /**
     * Returns an GOST3411 MessageDigest.
     * 
     * @return An GOST3411 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.1
     */
    private static MessageDigest getGost3411Digest() {
        return getDigest("GOST3411");
    }

    /**
     * Returns an MD2 MessageDigest.
     * 
     * @return An MD2 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getMd2Digest() {
        return getDigest("MD2");
    }

    /**
     * Returns an MD4 MessageDigest.
     * 
     * @return An MD4 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getMd4Digest() {
        return getDigest("MD4");
    }

    /**
     * Returns an MD5 MessageDigest.
     * 
     * @return An MD5 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getMd5Digest() {
        return getDigest("MD5");
    }

    /**
     * Returns an RIPEMD-128 MessageDigest.
     * 
     * @return An RIPEMD-128 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getRipemd128Digest() {
        return getDigest("RIPEMD128");
    }

    /**
     * Returns an RIPEMD-160 MessageDigest.
     * 
     * @return An RIPEMD-160 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getRipemd160Digest() {
        return getDigest("RIPEMD160");
    }

    /**
     * Returns an RIPEMD-256 MessageDigest.
     * 
     * @return An RIPEMD-256 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getRipemd256Digest() {
        return getDigest("RIPEMD256");
    }

    /**
     * Returns an RIPEMD-320 MessageDigest.
     * 
     * @return An RIPEMD-320 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getRipemd320Digest() {
        return getDigest("RIPEMD320");
    }

    /**
     * Returns an SHA-1 digest.
     * 
     * @return An SHA-1 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getSha1Digest() {
        return getDigest("SHA");
    }

    /**
     * Returns an SHA-224 digest.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @return An SHA-224 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getSha224Digest() {
        return getDigest("SHA-224");
    }

    /**
     * Returns an SHA-256 digest.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @return An SHA-256 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getSha256Digest() {
        return getDigest("SHA-256");
    }

    /**
     * Returns an SHA-384 digest.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @return An SHA-384 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getSha384Digest() {
        return getDigest("SHA-384");
    }

    /**
     * Returns an SHA-512 digest.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @return An SHA-512 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getSha512Digest() {
        return getDigest("SHA-512");
    }

    /**
     * Returns an SM3 digest.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @return An SM3 digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.1
     */
    private static MessageDigest getSm3Digest() {
        return getDigest("SM3");
    }

    
    /**
     * Returns an Tiger digest.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @return An Tiger digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getTigerDigest() {
        return getDigest("Tiger");
    }

    /**
     * Returns an Whirlpool digest.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @return An Whirlpool digest instance.
     * @throws RuntimeException
     *             when a {@link java.security.NoSuchAlgorithmException} is caught.
     * @since Commons Checksum 1.0
     */
    private static MessageDigest getWhirlpoolDigest() {
        return getDigest("Whirlpool");
    }

    /**
     * Return <code>true</code> if this digest algorithm is available, <code>false</code> otherwise.
     * 
     * @param algorithm
     *            the name of the algorithm requested. See <a href=
     *            "http://java.sun.com/j2se/1.3/docs/guide/security/CryptoSpec.html#AppA" >Appendix A in the Java
     *            Cryptography Architecture API Specification &amp; Reference</a> for information about standard algorithm
     *            names.
     * 
     * @return <code>true</code> if this digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isDigestAvailable(String algorithm) {
        try {
            MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
        return true;
    }
    
    /**
     * Return <code>true</code> if GOST3411 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if GOST3411 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.1
     */
    public static boolean isGost3411Available() {
        return isDigestAvailable("GOST3411");
    }
    
    /**
     * Return <code>true</code> if MD2 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if MD2 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isMd2Available() {
        return isDigestAvailable("MD2");
    }

    /**
     * Return <code>true</code> if MD4 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if MD4 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isMd4Available() {
        return isDigestAvailable("MD4");
    }

    /**
     * Return <code>true</code> if MD5 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if MD5 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isMd5Available() {
        return isDigestAvailable("MD5");
    }

    /**
     * Return <code>true</code> if RIPEMD-128 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if RIPEMD-128 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isRipmed128Available() {
        return isDigestAvailable("RIPEMD128");
    }

    /**
     * Return <code>true</code> if RIPEMD-160 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if RIPEMD-160 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isRipmed160Available() {
        return isDigestAvailable("RIPEMD160");
    }

    /**
     * Return <code>true</code> if RIPEMD-256 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if RIPEMD-256 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isRipmed256Available() {
        return isDigestAvailable("RIPEMD256");
    }

    /**
     * Return <code>true</code> if RIPEMD-320 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if RIPEMD-320 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isRipmed320Available() {
        return isDigestAvailable("RIPEMD320");
    }

    /**
     * Return <code>true</code> if SHA-1 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if SHA-1 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isSha1Available() {
        return isDigestAvailable("SHA");
    }

    /**
     * Return <code>true</code> if SHA-224 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if SHA-224 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isSha224Available() {
        return isDigestAvailable("SHA-224");
    }

    /**
     * Return <code>true</code> if SHA-256 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if SHA-256 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isSha256Available() {
        return isDigestAvailable("SHA-256");
    }

    /**
     * Return <code>true</code> if SHA-384 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if SHA-384 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isSha384Available() {
        return isDigestAvailable("SHA-384");
    }

    /**
     * Return <code>true</code> if SHA-512 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if SHA-512 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isSha512Available() {
        return isDigestAvailable("SHA-512");
    }
    
    /**
     * Return <code>true</code> if SM3 digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if SM3 digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.1
     */
    public static boolean isSM3Available() {
        return isDigestAvailable("SM3");
    }
    
    /**
     * Return <code>true</code> if Tiger digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if Tiger digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isTigerAvailable() {
        return isDigestAvailable("Tiger");
    }

    /**
     * Return <code>true</code> if Whirlpool digest algorithm is available, <code>false</code> otherwise.
     * 
     * @return <code>true</code> if Whirlpool digest algorithm is available, <code>false</code> otherwise.
     * @since Commons Checksum 1.0
     */
    public static boolean isWhirlpoolAvailable() {
        return isDigestAvailable("Whirlpool");
    }

    /**
     * Calculates the MD2 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD2 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] md2(byte[] data) {
        return getMd2Digest().digest(data);
    }

    /**
     * Calculates the GOST3411 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return GOST3411 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static byte[] gost3411(InputStream data) throws IOException {
        return digest(getGost3411Digest(), data);
    }

    /**
     * Calculates the GOST3411 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return GOST3411 digest
     * @since Commons Checksum 1.1
     */
    public static byte[] gost3411(String data) {
        return gost3411(getBytesUtf8(data));
    }

    /**
     * Calculates the GOST3411 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return GOST3411 digest as a hex string
     * @since Commons Checksum 1.1
     */
    public static String gost3411Hex(byte[] data) {
        return BinaryUtils.encodeHexString(gost3411(data));
    }

    /**
     * Calculates the GOST3411 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return GOST3411 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static String gost3411Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(gost3411(data));
    }

    /**
     * Calculates the GOST3411 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return GOST3411 digest as a hex string
     * @since Commons Checksum 1.1
     */
    public static String gost3411Hex(String data) {
        return BinaryUtils.encodeHexString(gost3411(data));
    }
    
    /**
     * Calculates the GOST3411 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return GOST3411 digest
     * @since Commons Checksum 1.1
     */
    public static byte[] gost3411(byte[] data) {
        return getGost3411Digest().digest(data);
    }

    /**
     * Calculates the MD2 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD2 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] md2(InputStream data) throws IOException {
        return digest(getMd2Digest(), data);
    }

    /**
     * Calculates the MD2 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD2 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] md2(String data) {
        return md2(getBytesUtf8(data));
    }

    /**
     * Calculates the MD2 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD2 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String md2Hex(byte[] data) {
        return BinaryUtils.encodeHexString(md2(data));
    }

    /**
     * Calculates the MD2 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD2 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String md2Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(md2(data));
    }

    /**
     * Calculates the MD2 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD2 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String md2Hex(String data) {
        return BinaryUtils.encodeHexString(md2(data));
    }

    /**
     * Calculates the MD4 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD4 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] md4(byte[] data) {
        return getMd4Digest().digest(data);
    }

    /**
     * Calculates the MD4 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD4 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] md4(InputStream data) throws IOException {
        return digest(getMd4Digest(), data);
    }

    /**
     * Calculates the MD4 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD4 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] md4(String data) {
        return md4(getBytesUtf8(data));
    }

    /**
     * Calculates the MD4 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD4 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String md4Hex(byte[] data) {
        return BinaryUtils.encodeHexString(md4(data));
    }

    /**
     * Calculates the MD4 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD4 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String md4Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(md4(data));
    }

    /**
     * Calculates the MD4 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD4 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String md4Hex(String data) {
        return BinaryUtils.encodeHexString(md4(data));
    }

    /**
     * Calculates the MD5 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD5 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] md5(byte[] data) {
        return getMd5Digest().digest(data);
    }

    /**
     * Calculates the MD5 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD5 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] md5(InputStream data) throws IOException {
        return digest(getMd5Digest(), data);
    }

    /**
     * Calculates the MD5 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return MD5 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] md5(String data) {
        return md5(getBytesUtf8(data));
    }

    /**
     * Calculates the MD5 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD5 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String md5Hex(byte[] data) {
        return BinaryUtils.encodeHexString(md5(data));
    }

    /**
     * Calculates the MD5 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD5 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String md5Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(md5(data));
    }

    /**
     * Calculates the MD5 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return MD5 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String md5Hex(String data) {
        return BinaryUtils.encodeHexString(md5(data));
    }

    /**
     * Registers provider name to use for the given algorithm.
     * 
     * @param algorithm
     *            the name of the algorithm requested. See <a href=
     *            "http://java.sun.com/j2se/1.3/docs/guide/security/CryptoSpec.html#AppA" >Appendix A in the Java
     *            Cryptography Architecture API Specification &amp; Reference</a> for information about standard algorithm
     *            names.
     * @param providerName
     *            the digest provider name to associate to this algorithm.
     * @since Commons Checksum 1.0
     * @return <code>true</code> if this digest algorithm is available for this provider.
     */
    public static boolean registerPreferredProvider(String algorithm, String providerName) {
        try {
            MessageDigest.getInstance(algorithm, providerName);
            digestProviderNameMap.put(algorithm, providerName);
        } catch (NoSuchAlgorithmException e) {
            return false;
        } catch (NoSuchProviderException e) {
            return false;
        }
        return true;
    }

    /**
     * Calculates the RIPEMD-128 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-128 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd128(byte[] data) {
        return getRipemd128Digest().digest(data);
    }

    /**
     * Calculates the RIPEMD-128 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-128 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd128(InputStream data) throws IOException {
        return digest(getRipemd128Digest(), data);
    }

    /**
     * Calculates the RIPEMD-128 digest and returns the value as a 16 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-128 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd128(String data) {
        return ripemd128(getBytesUtf8(data));
    }

    /**
     * Calculates the RIPEMD-128 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-128 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd128Hex(byte[] data) {
        return BinaryUtils.encodeHexString(ripemd128(data));
    }

    /**
     * Calculates the RIPEMD-128 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-128 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String ripemd128Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(ripemd128(data));
    }

    /**
     * Calculates the RIPEMD-128 digest and returns the value as a 32 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-128 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd128Hex(String data) {
        return BinaryUtils.encodeHexString(ripemd128(data));
    }

    /**
     * Calculates the RIPEMD-160 digest and returns the value as a 20 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-160 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd160(byte[] data) {
        return getRipemd160Digest().digest(data);
    }

    /**
     * Calculates the RIPEMD-160 digest and returns the value as a 20 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-160 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd160(InputStream data) throws IOException {
        return digest(getRipemd160Digest(), data);
    }

    /**
     * Calculates the RIPEMD-160 digest and returns the value as a 20 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-160 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd160(String data) {
        return ripemd160(getBytesUtf8(data));
    }

    /**
     * Calculates the RIPEMD-160 digest and returns the value as a 40 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-160 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd160Hex(byte[] data) {
        return BinaryUtils.encodeHexString(ripemd160(data));
    }

    /**
     * Calculates the RIPEMD-160 digest and returns the value as a 40 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-160 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String ripemd160Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(ripemd160(data));
    }

    /**
     * Calculates the RIPEMD-160 digest and returns the value as a 40 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-160 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd160Hex(String data) {
        return BinaryUtils.encodeHexString(ripemd160(data));
    }

    /**
     * Calculates the RIPEMD-256 digest and returns the value as a 32 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-256 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd256(byte[] data) {
        return getRipemd256Digest().digest(data);
    }

    /**
     * Calculates the RIPEMD-256 digest and returns the value as a 32 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-256 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd256(InputStream data) throws IOException {
        return digest(getRipemd256Digest(), data);
    }

    /**
     * Calculates the RIPEMD-256 digest and returns the value as a 32 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-256 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd256(String data) {
        return ripemd256(getBytesUtf8(data));
    }

    /**
     * Calculates the RIPEMD-256 digest and returns the value as a 64 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-256 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd256Hex(byte[] data) {
        return BinaryUtils.encodeHexString(ripemd256(data));
    }

    /**
     * Calculates the RIPEMD-256 digest and returns the value as a 64 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-256 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String ripemd256Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(ripemd256(data));
    }

    /**
     * Calculates the RIPEMD-256 digest and returns the value as a 64 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-256 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd256Hex(String data) {
        return BinaryUtils.encodeHexString(ripemd256(data));
    }

    /**
     * Calculates the RIPEMD-320 digest and returns the value as a 40 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-320 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd320(byte[] data) {
        return getRipemd320Digest().digest(data);
    }

    /**
     * Calculates the RIPEMD-320 digest and returns the value as a 40 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-320 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd320(InputStream data) throws IOException {
        return digest(getRipemd320Digest(), data);
    }

    /**
     * Calculates the RIPEMD-320 digest and returns the value as a 40 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-320 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] ripemd320(String data) {
        return ripemd320(getBytesUtf8(data));
    }

    /**
     * Calculates the RIPEMD-320 digest and returns the value as a 80 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-320 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd320Hex(byte[] data) {
        return BinaryUtils.encodeHexString(ripemd320(data));
    }

    /**
     * Calculates the RIPEMD-320 digest and returns the value as a 80 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-320 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String ripemd320Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(ripemd320(data));
    }

    /**
     * Calculates the RIPEMD-320 digest and returns the value as a 80 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return RIPEMD-320 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String ripemd320Hex(String data) {
        return BinaryUtils.encodeHexString(ripemd320(data));
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a 20 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return SHA-1 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] sha1(byte[] data) {
        return getSha1Digest().digest(data);
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a 20 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return SHA-1 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha1(InputStream data) throws IOException {
        return digest(getSha1Digest(), data);
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a 20 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return SHA-1 digest
     * @since Commons Checksum 1.0
     */
    public static byte[] sha1(String data) {
        return sha1(getBytesUtf8(data));
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a 40 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return SHA-1 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String sha1Hex(byte[] data) {
        return BinaryUtils.encodeHexString(sha1(data));
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a 40 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return SHA-1 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha1Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(sha1(data));
    }

    /**
     * Calculates the SHA-1 digest and returns the value as a 40 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return SHA-1 digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String sha1Hex(String data) {
        return BinaryUtils.encodeHexString(sha1(data));
    }

    /**
     * Calculates the SHA-224 digest and returns the value as a 28 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-224 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha224(byte[] data) {
        return getSha224Digest().digest(data);
    }

    /**
     * Calculates the SHA-224 digest and returns the value as a 28 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-224 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha224(InputStream data) throws IOException {
        return digest(getSha224Digest(), data);
    }

    /**
     * Calculates the SHA-224 digest and returns the value as a 28 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-224 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha224(String data) {
        return sha224(getBytesUtf8(data));
    }

    /**
     * Calculates the SHA-224 digest and returns the value as a 56 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-224 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha224Hex(byte[] data) {
        return BinaryUtils.encodeHexString(sha224(data));
    }

    /**
     * Calculates the SHA-224 digest and returns the value as a 56 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-224 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha224Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(sha224(data));
    }

    /**
     * Calculates the SHA-224 digest and returns the value as a 56 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-224 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha224Hex(String data) {
        return BinaryUtils.encodeHexString(sha224(data));
    }

    /**
     * Calculates the SHA-256 digest and returns the value as a 32 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-256 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha256(byte[] data) {
        return getSha256Digest().digest(data);
    }

    /**
     * Calculates the SHA-256 digest and returns the value as a 32 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-256 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha256(InputStream data) throws IOException {
        return digest(getSha256Digest(), data);
    }

    /**
     * Calculates the SHA-256 digest and returns the value as a 32 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-256 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha256(String data) {
        return sha256(getBytesUtf8(data));
    }

    /**
     * Calculates the SHA-256 digest and returns the value as a 64 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-256 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha256Hex(byte[] data) {
        return BinaryUtils.encodeHexString(sha256(data));
    }

    /**
     * Calculates the SHA-256 digest and returns the value as a 64 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-256 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha256Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(sha256(data));
    }

    /**
     * Calculates the SHA-256 digest and returns the value as a 64 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-256 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha256Hex(String data) {
        return BinaryUtils.encodeHexString(sha256(data));
    }

    /**
     * Calculates the SHA-384 digest and returns the value as a 48 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-384 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha384(byte[] data) {
        return getSha384Digest().digest(data);
    }

    /**
     * Calculates the SHA-384 digest and returns the value as a 48 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-384 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha384(InputStream data) throws IOException {
        return digest(getSha384Digest(), data);
    }

    /**
     * Calculates the SHA-384 digest and returns the value as a 48 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-384 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha384(String data) {
        return sha384(getBytesUtf8(data));
    }

    /**
     * Calculates the SHA-384 digest and returns the value as a 96 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-384 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha384Hex(byte[] data) {
        return BinaryUtils.encodeHexString(sha384(data));
    }

    /**
     * Calculates the SHA-384 digest and returns the value as a 96 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-384 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha384Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(sha384(data));
    }

    /**
     * Calculates the SHA-384 digest and returns the value as a 96 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-384 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha384Hex(String data) {
        return BinaryUtils.encodeHexString(sha384(data));
    }

    /**
     * Calculates the SHA-512 digest and returns the value as a 64 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-512 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha512(byte[] data) {
        return getSha512Digest().digest(data);
    }

    /**
     * Calculates the SHA-512 digest and returns the value as a 64 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-512 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha512(InputStream data) throws IOException {
        return digest(getSha512Digest(), data);
    }

    /**
     * Calculates the SHA-512 digest and returns the value as a 64 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-512 digest
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] sha512(String data) {
        return sha512(getBytesUtf8(data));
    }

    /**
     * Calculates the SHA-512 digest and returns the value as a 128 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-512 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha512Hex(byte[] data) {
        return BinaryUtils.encodeHexString(sha512(data));
    }

    /**
     * Calculates the SHA-512 digest and returns the value as a 128 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-512 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha512Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(sha512(data));
    }

    /**
     * Calculates the SHA-512 digest and returns the value as a 128 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SHA-512 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String sha512Hex(String data) {
        return BinaryUtils.encodeHexString(sha512(data));
    }

    /**
     * Calculates the SM3 digest and returns the value as a 32 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SM3 digest
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static byte[] sm3(byte[] data) {
        return getSm3Digest().digest(data);
    }

    /**
     * Calculates the SM3 digest and returns the value as a 32 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SM3 digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static byte[] sm3(InputStream data) throws IOException {
        return digest(getSm3Digest(), data);
    }

    /**
     * Calculates the SM3 digest and returns the value as a 32 element <code>byte[]</code>.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SM3 digest
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static byte[] sm3(String data) {
        return sm3(getBytesUtf8(data));
    }

    /**
     * Calculates the SM3 digest and returns the value as a 64 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SM3 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static String sm3Hex(byte[] data) {
        return BinaryUtils.encodeHexString(sm3(data));
    }

    /**
     * Calculates the SM3 digest and returns the value as a 64 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SM3 digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static String sm3Hex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(sm3(data));
    }

    /**
     * Calculates the SM3 digest and returns the value as a 64 character hex string.
     * <p>
     * Throws a <code>RuntimeException</code> on JRE versions prior to 1.4.0.
     * </p>
     * 
     * @param data
     *            Data to digest
     * @return SM3 digest as a hex string
     * @since 1.4
     * @since Commons Checksum 1.1
     */
    public static String sm3Hex(String data) {
        return BinaryUtils.encodeHexString(sm3(data));
    }
    
    /**
     * Calculates the Tiger digest and returns the value as a 24 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return Tiger digest
     * @since Commons Checksum 1.0
     */
    public static byte[] tiger(byte[] data) {
        return getTigerDigest().digest(data);
    }

    /**
     * Calculates the Tiger digest and returns the value as a 24 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return Tiger digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] tiger(InputStream data) throws IOException {
        return digest(getTigerDigest(), data);
    }

    /**
     * Calculates the Tiger digest and returns the value as a 24 element <code>byte[]</code>.
     * 
     * @param data
     *            Data to digest
     * @return Tiger digest
     * @since Commons Checksum 1.0
     */
    public static byte[] tiger(String data) {
        return tiger(getBytesUtf8(data));
    }

    /**
     * Calculates the Tiger digest and returns the value as a 48 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Tiger digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String tigerHex(byte[] data) {
        return BinaryUtils.encodeHexString(tiger(data));
    }

    /**
     * Calculates the Tiger digest and returns the value as a 48 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Tiger digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String tigerHex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(tiger(data));
    }

    /**
     * Calculates the Tiger digest and returns the value as a 48 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Tiger digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String tigerHex(String data) {
        return BinaryUtils.encodeHexString(tiger(data));
    }

    /**
     * Calculates the Whirlpool digest and returns the value as a 64 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Whirlpool digest
     * @since Commons Checksum 1.0
     */
    public static byte[] whirlpool(byte[] data) {
        return getWhirlpoolDigest().digest(data);
    }

    /**
     * Calculates the Whirlpool digest and returns the value as a 64 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Whirlpool digest
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static byte[] whirlpool(InputStream data) throws IOException {
        return digest(getWhirlpoolDigest(), data);
    }

    /**
     * Calculates the Whirlpool digest and returns the value as a 64 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Whirlpool digest
     * @since Commons Checksum 1.0
     */
    public static byte[] whirlpool(String data) {
        return whirlpool(getBytesUtf8(data));
    }

    /**
     * Calculates the Whirlpool digest and returns the value as a 128 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Whirlpool digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String whirlpoolHex(byte[] data) {
        return BinaryUtils.encodeHexString(whirlpool(data));
    }

    /**
     * Calculates the Whirlpool digest and returns the value as a 128 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Whirlpool digest as a hex string
     * @throws IOException
     *             On error reading from the stream
     * @since 1.4
     * @since Commons Checksum 1.0
     */
    public static String whirlpoolHex(InputStream data) throws IOException {
        return BinaryUtils.encodeHexString(whirlpool(data));
    }

    /**
     * Calculates the Whirlpool digest and returns the value as a 128 character hex string.
     * 
     * @param data
     *            Data to digest
     * @return Whirlpool digest as a hex string
     * @since Commons Checksum 1.0
     */
    public static String whirlpoolHex(String data) {
        return BinaryUtils.encodeHexString(whirlpool(data));
    }

}
