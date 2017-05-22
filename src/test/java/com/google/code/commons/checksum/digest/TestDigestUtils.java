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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Map;

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
	
	public static final Map<String,String> ABC_CHECKSUMS = toMap(new String[][]{
		{ "MD2", "da853b0d3f88d99b30283a69e6ded6bb" },
	    { "MD4", "a448017aaf21d8525fc10ae87aa6729d" },
	    { "MD5", "900150983cd24fb0d6963f7d28e17f72"},
	    { "SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d" },
	    { "SHA-224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
	    { "SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
	    { "SHA-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
	    { "SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
	    { "SHA-512/224", "4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA" },
	    { "SHA-512/256", "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23" },
	    { "RIPEMD128", "c14a12199c66e4ba84636b0f69144c77" },
	    { "RIPEMD160", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
	    { "RIPEMD256", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65" },
	    { "RIPEMD320", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d" },
	    { "TIGER", "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93" },
	    { "GOST3411", "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c" },
	    { "WHIRLPOOL", "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5" },
	    { "SM3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" },
	    { "SHA3-224", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
	    { "SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
	    { "SHA3-384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25" },
	    { "SHA3-512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
	    { "KECCAK-224", "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8" },
	    { "KECCAK-256", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" },
	    { "KECCAK-288", "20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc94289f4d6" },
	    { "KECCAK-384", "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e" },
	    { "KECCAK-512", "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96" },
	    { "BLAKE2B-160", "384264f676f39536840523f284921cdc68b6846b" },
	    { "BLAKE2B-256", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319" },
	    { "BLAKE2B-384", "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4" },
	    { "BLAKE2B-512", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923" },
	});
	
	public static final Map<String,String> HELLO_WORLD_CHECKSUMS = toMap(new String[][]{
		{ "MD2", "27454d000b8f9aaa97da6de8b394d986" },
	    { "MD4", "77a781b995cf1cfaf39d9e2f5910c2cf" },
	    { "MD5", "b10a8db164e0754105b7a99be72e3fe5"},
	    { "SHA-1", "0a4d55a8d778e5022fab701977c5d840bbc486d0" },
	    { "SHA-224", "c4890faffdb0105d991a461e668e276685401b02eab1ef4372795047" },
	    { "SHA-256", "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" },
	    { "SHA-384", "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f" },
	    { "SHA-512", "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b" },
	    { "RIPEMD128", "2d02b563447f954eafdc4824a190ddcc" },
	    { "RIPEMD160", "a830d7beb04eb7549ce990fb7dc962e499a27230" },
	    { "RIPEMD256", "32b7b7d2408f9389d77cc00aff3c1529504508e86cdbc78a95c469fc68f80543" },
	    { "RIPEMD320", "66aa514f60d7b083b539420b08bde3569a8f553f60269ea41b22b06aacca57cd6aa114f315d65ac3" },
	    { "TIGER", "2bab23b832ed1cc054498b8e5a9f2924d4042f35a22aaa55" },
	    { "WHIRLPOOL", "b77b284bffc952efee36a94397a0ce11e8624668e33b7020a80eb2fb21096f0a08518c50d023de12b010c2e30b93b5837dc471d899608d786fe9a6b60112ea4a" },
	});

    @Before
    public void addBouncyCastleProvider() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void isAvailable() {
    	Assert.assertTrue(DigestUtils.isGost3411Available());
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
        Assert.assertTrue(DigestUtils.isSM3Available());
        Assert.assertTrue(DigestUtils.isTigerAvailable());
        Assert.assertTrue(DigestUtils.isWhirlpoolAvailable());
    }
    
    @Test
    public void gost3411() throws IOException, DecoderException {
        byte[] gost3411 = null;
        gost3411 = DigestUtils.gost3411(ABC_STRING);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"GOST3411"), gost3411);
        gost3411 = DigestUtils.gost3411(ABC_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"GOST3411"), gost3411);
        gost3411 = DigestUtils.gost3411(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"GOST3411"), gost3411);
    }

    @Test
    public void gost3411Hex() throws IOException {
        String gost3411Hex = null;
        gost3411Hex = DigestUtils.gost3411Hex(ABC_STRING);
        Assert.assertEquals(ABC_CHECKSUMS.get("GOST3411"), gost3411Hex);
        gost3411Hex = DigestUtils.gost3411Hex(ABC_BYTE_ARRAY);
        Assert.assertEquals(ABC_CHECKSUMS.get("GOST3411"), gost3411Hex);
        gost3411Hex = DigestUtils.gost3411Hex(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertEquals(ABC_CHECKSUMS.get("GOST3411"), gost3411Hex);
    }

    
    @Test
    public void md2() throws IOException, DecoderException {
        byte[] md2 = null;
        md2 = DigestUtils.md2(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD2"), md2);
        md2 = DigestUtils.md2(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD2"), md2);
        md2 = DigestUtils.md2(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD2"), md2);
        md2 = DigestUtils.md2(ABC_STRING);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD2"), md2);
        md2 = DigestUtils.md2(ABC_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD2"), md2);
        md2 = DigestUtils.md2(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD2"), md2);
    }

    @Test
    public void md2Hex() throws IOException {
        String md2Hex = null;
        md2Hex = DigestUtils.md2Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD2"), md2Hex);
        md2Hex = DigestUtils.md2Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD2"), md2Hex);
        md2Hex = DigestUtils.md2Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD2"), md2Hex);
        md2Hex = DigestUtils.md2Hex(ABC_STRING);
        Assert.assertEquals(ABC_CHECKSUMS.get("MD2"), md2Hex);
        md2Hex = DigestUtils.md2Hex(ABC_BYTE_ARRAY);
        Assert.assertEquals(ABC_CHECKSUMS.get("MD2"), md2Hex);
        md2Hex = DigestUtils.md2Hex(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertEquals(ABC_CHECKSUMS.get("MD2"), md2Hex);
    }

    @Test
    public void md4() throws IOException, DecoderException {
        byte[] md4 = null;
        md4 = DigestUtils.md4(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD4"), md4);
        md4 = DigestUtils.md4(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD4"), md4);
        md4 = DigestUtils.md4(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD4"), md4);
        md4 = DigestUtils.md4(ABC_STRING);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD4"), md4);
        md4 = DigestUtils.md4(ABC_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD4"), md4);
        md4 = DigestUtils.md4(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD4"), md4);
    }

    @Test
    public void md4Hex() throws IOException {
        String md4Hex = null;
        md4Hex = DigestUtils.md4Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD4"), md4Hex);
        md4Hex = DigestUtils.md4Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD4"), md4Hex);
        md4Hex = DigestUtils.md4Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD4"), md4Hex);
        md4Hex = DigestUtils.md4Hex(ABC_STRING);
        Assert.assertEquals(ABC_CHECKSUMS.get("MD4"), md4Hex);
        md4Hex = DigestUtils.md4Hex(ABC_BYTE_ARRAY);
        Assert.assertEquals(ABC_CHECKSUMS.get("MD4"), md4Hex);
        md4Hex = DigestUtils.md4Hex(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertEquals(ABC_CHECKSUMS.get("MD4"), md4Hex);
    }

    @Test
    public void md5() throws IOException, DecoderException {
        byte[] md5 = null;
        md5 = DigestUtils.md5(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD5"), md5);
        md5 = DigestUtils.md5(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD5"), md5);
        md5 = DigestUtils.md5(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"MD5"), md5);
        md5 = DigestUtils.md5(ABC_STRING);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD5"), md5);
        md5 = DigestUtils.md5(ABC_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD5"), md5);
        md5 = DigestUtils.md5(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"MD5"), md5);
    }

    @Test
    public void md5Hex() throws IOException {
        String md5Hex = null;
        md5Hex = DigestUtils.md5Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD5"), md5Hex);
        md5Hex = DigestUtils.md5Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD5"), md5Hex);
        md5Hex = DigestUtils.md5Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("MD5"), md5Hex);
        md5Hex = DigestUtils.md5Hex(ABC_STRING);
        Assert.assertEquals(ABC_CHECKSUMS.get("MD5"), md5Hex);
        md5Hex = DigestUtils.md5Hex(ABC_BYTE_ARRAY);
        Assert.assertEquals(ABC_CHECKSUMS.get("MD5"), md5Hex);
        md5Hex = DigestUtils.md5Hex(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertEquals(ABC_CHECKSUMS.get("MD5"), md5Hex);
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
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD128"), ripemd128);
        ripemd128 = DigestUtils.ripemd128(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD128"), ripemd128);
        ripemd128 = DigestUtils.ripemd128(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD128"), ripemd128);
        ripemd128 = DigestUtils.ripemd128(ABC_STRING);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"RIPEMD128"), ripemd128);
        ripemd128 = DigestUtils.ripemd128(ABC_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"RIPEMD128"), ripemd128);
        ripemd128 = DigestUtils.ripemd128(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"RIPEMD128"), ripemd128);
    }

    @Test
    public void ripemd128Hex() throws IOException {
        String ripemd128Hex = null;
        ripemd128Hex = DigestUtils.ripemd128Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD128"), ripemd128Hex);
        ripemd128Hex = DigestUtils.ripemd128Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD128"), ripemd128Hex);
        ripemd128Hex = DigestUtils.ripemd128Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD128"), ripemd128Hex);
        ripemd128Hex = DigestUtils.ripemd128Hex(ABC_STRING);
        Assert.assertEquals(ABC_CHECKSUMS.get("RIPEMD128"), ripemd128Hex);
        ripemd128Hex = DigestUtils.ripemd128Hex(ABC_BYTE_ARRAY);
        Assert.assertEquals(ABC_CHECKSUMS.get("RIPEMD128"), ripemd128Hex);
        ripemd128Hex = DigestUtils.ripemd128Hex(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertEquals(ABC_CHECKSUMS.get("RIPEMD128"), ripemd128Hex);
    }

    @Test
    public void ripemd160() throws IOException, DecoderException {
        byte[] ripemd160 = null;
        ripemd160 = DigestUtils.ripemd160(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD160"), ripemd160);
        ripemd160 = DigestUtils.ripemd160(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD160"), ripemd160);
        ripemd160 = DigestUtils.ripemd160(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD160"), ripemd160);
        ripemd160 = DigestUtils.ripemd160(ABC_STRING);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"RIPEMD160"), ripemd160);
        ripemd160 = DigestUtils.ripemd160(ABC_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"RIPEMD160"), ripemd160);
        ripemd160 = DigestUtils.ripemd160(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"RIPEMD160"), ripemd160);
        
    }

    @Test
    public void ripemd160Hex() throws IOException {
        String ripemd160Hex = null;
        ripemd160Hex = DigestUtils.ripemd160Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD160"), ripemd160Hex);
        ripemd160Hex = DigestUtils.ripemd160Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD160"), ripemd160Hex);
        ripemd160Hex = DigestUtils.ripemd160Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD160"), ripemd160Hex);
    }

    @Test
    public void ripemd256() throws IOException, DecoderException {
        byte[] ripemd256 = null;
        ripemd256 = DigestUtils.ripemd256(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD256"), ripemd256);
        ripemd256 = DigestUtils.ripemd256(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD256"), ripemd256);
        ripemd256 = DigestUtils.ripemd256(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD256"), ripemd256);
    }

    @Test
    public void ripemd256Hex() throws IOException {
        String ripemd256Hex = null;
        ripemd256Hex = DigestUtils.ripemd256Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD256"), ripemd256Hex);
        ripemd256Hex = DigestUtils.ripemd256Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD256"), ripemd256Hex);
        ripemd256Hex = DigestUtils.ripemd256Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD256"), ripemd256Hex);
    }

    @Test
    public void ripemd320() throws IOException, DecoderException {
        byte[] ripemd320 = null;
        ripemd320 = DigestUtils.ripemd320(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD320"), ripemd320);
        ripemd320 = DigestUtils.ripemd320(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD320"), ripemd320);
        ripemd320 = DigestUtils.ripemd320(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"RIPEMD320"), ripemd320);
    }

    @Test
    public void ripemd320Hex() throws IOException {
        String ripemd320Hex = null;
        ripemd320Hex = DigestUtils.ripemd320Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD320"), ripemd320Hex);
        ripemd320Hex = DigestUtils.ripemd320Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD320"), ripemd320Hex);
        ripemd320Hex = DigestUtils.ripemd320Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("RIPEMD320"), ripemd320Hex);
    }

    @Test
    public void sha1() throws IOException, DecoderException {
        byte[] sha1 = null;
        sha1 = DigestUtils.sha1(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-1"), sha1);
        sha1 = DigestUtils.sha1(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-1"), sha1);
        sha1 = DigestUtils.sha1(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-1"), sha1);
    }

    @Test
    public void sha1Hex() throws IOException {
        String sha1Hex = null;
        sha1Hex = DigestUtils.sha1Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-1"), sha1Hex);
        sha1Hex = DigestUtils.sha1Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-1"), sha1Hex);
        sha1Hex = DigestUtils.sha1Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-1"), sha1Hex);
    }

    @Test
    public void sha224() throws IOException, DecoderException {
        byte[] sha224 = null;
        sha224 = DigestUtils.sha224(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-224"), sha224);
        sha224 = DigestUtils.sha224(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-224"), sha224);
        sha224 = DigestUtils.sha224(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-224"), sha224);
    }

    @Test
    public void sha224Hex() throws IOException {
        String sha224Hex = null;
        sha224Hex = DigestUtils.sha224Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-224"), sha224Hex);
        sha224Hex = DigestUtils.sha224Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-224"), sha224Hex);
        sha224Hex = DigestUtils.sha224Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-224"), sha224Hex);
    }

    @Test
    public void sha256() throws IOException, DecoderException {
        byte[] sha256 = null;
        sha256 = DigestUtils.sha256(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-256"), sha256);
        sha256 = DigestUtils.sha256(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-256"), sha256);
        sha256 = DigestUtils.sha256(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-256"), sha256);
    }

    @Test
    public void sha256Hex() throws IOException {
        String sha256Hex = null;
        sha256Hex = DigestUtils.sha256Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-256"), sha256Hex);
        sha256Hex = DigestUtils.sha256Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-256"), sha256Hex);
        sha256Hex = DigestUtils.sha256Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-256"), sha256Hex);
    }

    @Test
    public void sha384() throws IOException, DecoderException {
        byte[] sha384 = null;
        sha384 = DigestUtils.sha384(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-384"), sha384);
        sha384 = DigestUtils.sha384(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-384"), sha384);
        sha384 = DigestUtils.sha384(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-384"), sha384);
    }

    @Test
    public void sha384Hex() throws IOException {
        String sha384Hex = null;
        sha384Hex = DigestUtils.sha384Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-384"), sha384Hex);
        sha384Hex = DigestUtils.sha384Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-384"), sha384Hex);
        sha384Hex = DigestUtils.sha384Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-384"), sha384Hex);
    }

    @Test
    public void sha512() throws IOException, DecoderException {
        byte[] sha512 = null;
        sha512 = DigestUtils.sha512(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-512"), sha512);
        sha512 = DigestUtils.sha512(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-512"), sha512);
        sha512 = DigestUtils.sha512(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"SHA-512"), sha512);
    }

    @Test
    public void sha512Hex() throws IOException {
        String sha512Hex = null;
        sha512Hex = DigestUtils.sha512Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-512"), sha512Hex);
        sha512Hex = DigestUtils.sha512Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-512"), sha512Hex);
        sha512Hex = DigestUtils.sha512Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("SHA-512"), sha512Hex);
    }

    @Test
    public void sm3() throws IOException, DecoderException {
        byte[] sm3 = null;
        sm3 = DigestUtils.sm3(ABC_STRING);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"SM3"), sm3);
        sm3 = DigestUtils.sm3(ABC_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"SM3"), sm3);
        sm3 = DigestUtils.sm3(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(ABC_CHECKSUMS,"SM3"), sm3);
    }

    @Test
    public void sm3Hex() throws IOException {
        String sm3Hex = null;
        sm3Hex = DigestUtils.sm3Hex(ABC_STRING);
        Assert.assertEquals(ABC_CHECKSUMS.get("SM3"), sm3Hex);
        sm3Hex = DigestUtils.sm3Hex(ABC_BYTE_ARRAY);
        Assert.assertEquals(ABC_CHECKSUMS.get("SM3"), sm3Hex);
        sm3Hex = DigestUtils.sm3Hex(new ByteArrayInputStream(ABC_BYTE_ARRAY));
        Assert.assertEquals(ABC_CHECKSUMS.get("SM3"), sm3Hex);
    }
    
    @Test
    public void tiger() throws IOException, DecoderException {
        byte[] tiger = null;
        tiger = DigestUtils.tiger(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"TIGER"), tiger);
        tiger = DigestUtils.tiger(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"TIGER"), tiger);
        tiger = DigestUtils.tiger(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"TIGER"), tiger);
    }

    @Test
    public void tigerHex() throws IOException {
        String tigerHex = null;
        tigerHex = DigestUtils.tigerHex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("TIGER"), tigerHex);
        tigerHex = DigestUtils.tigerHex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("TIGER"), tigerHex);
        tigerHex = DigestUtils.tigerHex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("TIGER"), tigerHex);
    }

    @Test
    public void whirlpool() throws IOException, DecoderException {
        byte[] whirlpool = null;
        whirlpool = DigestUtils.whirlpool(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"WHIRLPOOL"), whirlpool);
        whirlpool = DigestUtils.whirlpool(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"WHIRLPOOL"), whirlpool);
        whirlpool = DigestUtils.whirlpool(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"WHIRLPOOL"), whirlpool);
    }

    @Test
    public void whirlpoolHex() throws IOException {
        String whirlpoolHex = null;
        whirlpoolHex = DigestUtils.whirlpoolHex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("WHIRLPOOL"), whirlpoolHex);
        whirlpoolHex = DigestUtils.whirlpoolHex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("WHIRLPOOL"), whirlpoolHex);
        whirlpoolHex = DigestUtils.whirlpoolHex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("WHIRLPOOL"), whirlpoolHex);
    }
}
