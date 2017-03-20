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
import java.security.Security;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.code.commons.checksum.AbstractTestCommonsChecksum;

/**
 * TestDigestUtils
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */
public class TestDigestUtils extends AbstractTestCommonsChecksum {

    public static final String HELLO_WORLD_MD2_HEX = "27454d000b8f9aaa97da6de8b394d986";

    public static final String HELLO_WORLD_MD4_HEX = "77a781b995cf1cfaf39d9e2f5910c2cf";

    public static final String HELLO_WORLD_MD5_HEX = "b10a8db164e0754105b7a99be72e3fe5";

    public static final String HELLO_WORLD_RIPEMD128_HEX = "2d02b563447f954eafdc4824a190ddcc";

    public static final String HELLO_WORLD_RIPEMD160_HEX = "a830d7beb04eb7549ce990fb7dc962e499a27230";

    public static final String HELLO_WORLD_RIPEMD256_HEX = "32b7b7d2408f9389d77cc00aff3c1529504508e86cdbc78a95c469fc68f80543";

    public static final String HELLO_WORLD_RIPEMD320_HEX = "66aa514f60d7b083b539420b08bde3569a8f553f60269ea41b22b06aacca57cd6aa114f315d65ac3";

    public static final String HELLO_WORLD_SHA1_HEX = "0a4d55a8d778e5022fab701977c5d840bbc486d0";

    public static final String HELLO_WORLD_SHA224_HEX = "c4890faffdb0105d991a461e668e276685401b02eab1ef4372795047";

    public static final String HELLO_WORLD_SHA256_HEX = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    public static final String HELLO_WORLD_SHA384_HEX = "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f";

    public static final String HELLO_WORLD_SHA512_HEX = "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b";

    public static final String HELLO_WORLD_TIGER_HEX = "2bab23b832ed1cc054498b8e5a9f2924d4042f35a22aaa55";

    public static final String HELLO_WORLD_WHIRLPOOL_HEX = "b77b284bffc952efee36a94397a0ce11e8624668e33b7020a80eb2fb21096f0a08518c50d023de12b010c2e30b93b5837dc471d899608d786fe9a6b60112ea4a";

    @Before
    public void addBouncyCastleProvider() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void isAvailable() {
        Assert.assertTrue(DigestUtils.isMd2Available());
        Assert.assertTrue(DigestUtils.isMd4Available());
        Assert.assertTrue(DigestUtils.isMd5Available());
        Assert.assertTrue(DigestUtils.isRipmed128Available());
        Assert.assertTrue(DigestUtils.isRipmed160Available());
        Assert.assertTrue(DigestUtils.isRipmed256Available());
        Assert.assertTrue(DigestUtils.isRipmed320Available());
        Assert.assertTrue(DigestUtils.isSha1Available());
        Assert.assertTrue(DigestUtils.isSha224Available());
        Assert.assertTrue(DigestUtils.isSha256Available());
        Assert.assertTrue(DigestUtils.isSha384Available());
        Assert.assertTrue(DigestUtils.isSha512Available());
        Assert.assertTrue(DigestUtils.isTigerAvailable());
        Assert.assertTrue(DigestUtils.isWhirlpoolAvailable());
    }

    @Test
    public void md2() throws IOException, DecoderException {
        byte[] md2 = null;
        md2 = DigestUtils.md2(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD2_HEX), md2);
        md2 = DigestUtils.md2(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD2_HEX), md2);
        md2 = DigestUtils.md2(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD2_HEX), md2);
    }

    @Test
    public void md2Hex() throws IOException {
        String md2Hex = null;
        md2Hex = DigestUtils.md2Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_MD2_HEX, md2Hex);
        md2Hex = DigestUtils.md2Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_MD2_HEX, md2Hex);
        md2Hex = DigestUtils.md2Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_MD2_HEX, md2Hex);
    }

    @Test
    public void md4() throws IOException, DecoderException {
        byte[] md4 = null;
        md4 = DigestUtils.md4(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD4_HEX), md4);
        md4 = DigestUtils.md4(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD4_HEX), md4);
        md4 = DigestUtils.md4(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD4_HEX), md4);
    }

    @Test
    public void md4Hex() throws IOException {
        String md4Hex = null;
        md4Hex = DigestUtils.md4Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_MD4_HEX, md4Hex);
        md4Hex = DigestUtils.md4Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_MD4_HEX, md4Hex);
        md4Hex = DigestUtils.md4Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_MD4_HEX, md4Hex);
    }

    @Test
    public void md5() throws IOException, DecoderException {
        byte[] md5 = null;
        md5 = DigestUtils.md5(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD5_HEX), md5);
        md5 = DigestUtils.md5(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD5_HEX), md5);
        md5 = DigestUtils.md5(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_MD5_HEX), md5);
    }

    @Test
    public void md5Hex() throws IOException {
        String md5Hex = null;
        md5Hex = DigestUtils.md5Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_MD5_HEX, md5Hex);
        md5Hex = DigestUtils.md5Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_MD5_HEX, md5Hex);
        md5Hex = DigestUtils.md5Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_MD5_HEX, md5Hex);
    }

    @Test
    public void registerPreferredProvider() {
        Assert.assertTrue(DigestUtils.registerPreferredProvider("MD5", BouncyCastleProvider.PROVIDER_NAME));
        Assert.assertEquals(BouncyCastleProvider.PROVIDER_NAME, DigestUtils.getDigest("MD5").getProvider().getName());
    }

    @After
    public void removeBouncyCastleProvider() throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void ripemd128() throws IOException, DecoderException {
        byte[] ripemd128 = null;
        ripemd128 = DigestUtils.ripemd128(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD128_HEX), ripemd128);
        ripemd128 = DigestUtils.ripemd128(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD128_HEX), ripemd128);
        ripemd128 = DigestUtils.ripemd128(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD128_HEX), ripemd128);
    }

    @Test
    public void ripemd128Hex() throws IOException {
        String ripemd128Hex = null;
        ripemd128Hex = DigestUtils.ripemd128Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_RIPEMD128_HEX, ripemd128Hex);
        ripemd128Hex = DigestUtils.ripemd128Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_RIPEMD128_HEX, ripemd128Hex);
        ripemd128Hex = DigestUtils.ripemd128Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_RIPEMD128_HEX, ripemd128Hex);
    }

    @Test
    public void ripemd160() throws IOException, DecoderException {
        byte[] ripemd160 = null;
        ripemd160 = DigestUtils.ripemd160(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD160_HEX), ripemd160);
        ripemd160 = DigestUtils.ripemd160(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD160_HEX), ripemd160);
        ripemd160 = DigestUtils.ripemd160(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD160_HEX), ripemd160);
    }

    @Test
    public void ripemd160Hex() throws IOException {
        String ripemd160Hex = null;
        ripemd160Hex = DigestUtils.ripemd160Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_RIPEMD160_HEX, ripemd160Hex);
        ripemd160Hex = DigestUtils.ripemd160Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_RIPEMD160_HEX, ripemd160Hex);
        ripemd160Hex = DigestUtils.ripemd160Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_RIPEMD160_HEX, ripemd160Hex);
    }

    @Test
    public void ripemd256() throws IOException, DecoderException {
        byte[] ripemd256 = null;
        ripemd256 = DigestUtils.ripemd256(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD256_HEX), ripemd256);
        ripemd256 = DigestUtils.ripemd256(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD256_HEX), ripemd256);
        ripemd256 = DigestUtils.ripemd256(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD256_HEX), ripemd256);
    }

    @Test
    public void ripemd256Hex() throws IOException {
        String ripemd256Hex = null;
        ripemd256Hex = DigestUtils.ripemd256Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_RIPEMD256_HEX, ripemd256Hex);
        ripemd256Hex = DigestUtils.ripemd256Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_RIPEMD256_HEX, ripemd256Hex);
        ripemd256Hex = DigestUtils.ripemd256Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_RIPEMD256_HEX, ripemd256Hex);
    }

    @Test
    public void ripemd320() throws IOException, DecoderException {
        byte[] ripemd320 = null;
        ripemd320 = DigestUtils.ripemd320(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD320_HEX), ripemd320);
        ripemd320 = DigestUtils.ripemd320(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD320_HEX), ripemd320);
        ripemd320 = DigestUtils.ripemd320(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_RIPEMD320_HEX), ripemd320);
    }

    @Test
    public void ripemd320Hex() throws IOException {
        String ripemd320Hex = null;
        ripemd320Hex = DigestUtils.ripemd320Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_RIPEMD320_HEX, ripemd320Hex);
        ripemd320Hex = DigestUtils.ripemd320Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_RIPEMD320_HEX, ripemd320Hex);
        ripemd320Hex = DigestUtils.ripemd320Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_RIPEMD320_HEX, ripemd320Hex);
    }

    @Test
    public void sha1() throws IOException, DecoderException {
        byte[] sha1 = null;
        sha1 = DigestUtils.sha1(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA1_HEX), sha1);
        sha1 = DigestUtils.sha1(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA1_HEX), sha1);
        sha1 = DigestUtils.sha1(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA1_HEX), sha1);
    }

    @Test
    public void sha1Hex() throws IOException {
        String sha1Hex = null;
        sha1Hex = DigestUtils.sha1Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_SHA1_HEX, sha1Hex);
        sha1Hex = DigestUtils.sha1Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_SHA1_HEX, sha1Hex);
        sha1Hex = DigestUtils.sha1Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_SHA1_HEX, sha1Hex);
    }

    @Test
    public void sha224() throws IOException, DecoderException {
        byte[] sha224 = null;
        sha224 = DigestUtils.sha224(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA224_HEX), sha224);
        sha224 = DigestUtils.sha224(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA224_HEX), sha224);
        sha224 = DigestUtils.sha224(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA224_HEX), sha224);
    }

    @Test
    public void sha224Hex() throws IOException {
        String sha224Hex = null;
        sha224Hex = DigestUtils.sha224Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_SHA224_HEX, sha224Hex);
        sha224Hex = DigestUtils.sha224Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_SHA224_HEX, sha224Hex);
        sha224Hex = DigestUtils.sha224Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_SHA224_HEX, sha224Hex);
    }

    @Test
    public void sha256() throws IOException, DecoderException {
        byte[] sha256 = null;
        sha256 = DigestUtils.sha256(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA256_HEX), sha256);
        sha256 = DigestUtils.sha256(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA256_HEX), sha256);
        sha256 = DigestUtils.sha256(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA256_HEX), sha256);
    }

    @Test
    public void sha256Hex() throws IOException {
        String sha256Hex = null;
        sha256Hex = DigestUtils.sha256Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_SHA256_HEX, sha256Hex);
        sha256Hex = DigestUtils.sha256Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_SHA256_HEX, sha256Hex);
        sha256Hex = DigestUtils.sha256Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_SHA256_HEX, sha256Hex);
    }

    @Test
    public void sha384() throws IOException, DecoderException {
        byte[] sha384 = null;
        sha384 = DigestUtils.sha384(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA384_HEX), sha384);
        sha384 = DigestUtils.sha384(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA384_HEX), sha384);
        sha384 = DigestUtils.sha384(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA384_HEX), sha384);
    }

    @Test
    public void sha384Hex() throws IOException {
        String sha384Hex = null;
        sha384Hex = DigestUtils.sha384Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_SHA384_HEX, sha384Hex);
        sha384Hex = DigestUtils.sha384Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_SHA384_HEX, sha384Hex);
        sha384Hex = DigestUtils.sha384Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_SHA384_HEX, sha384Hex);
    }

    @Test
    public void sha512() throws IOException, DecoderException {
        byte[] sha512 = null;
        sha512 = DigestUtils.sha512(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA512_HEX), sha512);
        sha512 = DigestUtils.sha512(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA512_HEX), sha512);
        sha512 = DigestUtils.sha512(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_SHA512_HEX), sha512);
    }

    @Test
    public void sha512Hex() throws IOException {
        String sha512Hex = null;
        sha512Hex = DigestUtils.sha512Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_SHA512_HEX, sha512Hex);
        sha512Hex = DigestUtils.sha512Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_SHA512_HEX, sha512Hex);
        sha512Hex = DigestUtils.sha512Hex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_SHA512_HEX, sha512Hex);
    }

    @Test
    public void tiger() throws IOException, DecoderException {
        byte[] tiger = null;
        tiger = DigestUtils.tiger(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_TIGER_HEX), tiger);
        tiger = DigestUtils.tiger(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_TIGER_HEX), tiger);
        tiger = DigestUtils.tiger(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_TIGER_HEX), tiger);
    }

    @Test
    public void tigerHex() throws IOException {
        String tigerHex = null;
        tigerHex = DigestUtils.tigerHex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_TIGER_HEX, tigerHex);
        tigerHex = DigestUtils.tigerHex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_TIGER_HEX, tigerHex);
        tigerHex = DigestUtils.tigerHex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_TIGER_HEX, tigerHex);
    }

    @Test
    public void whirlpool() throws IOException, DecoderException {
        byte[] whirlpool = null;
        whirlpool = DigestUtils.whirlpool(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_WHIRLPOOL_HEX), whirlpool);
        whirlpool = DigestUtils.whirlpool(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_WHIRLPOOL_HEX), whirlpool);
        whirlpool = DigestUtils.whirlpool(getHelloWorldInputStream());
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_WHIRLPOOL_HEX), whirlpool);
    }

    @Test
    public void whirlpoolHex() throws IOException {
        String whirlpoolHex = null;
        whirlpoolHex = DigestUtils.whirlpoolHex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_WHIRLPOOL_HEX, whirlpoolHex);
        whirlpoolHex = DigestUtils.whirlpoolHex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_WHIRLPOOL_HEX, whirlpoolHex);
        whirlpoolHex = DigestUtils.whirlpoolHex(getHelloWorldInputStream());
        Assert.assertEquals(HELLO_WORLD_WHIRLPOOL_HEX, whirlpoolHex);
    }
}
