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

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.google.code.commons.checksum.AbstractTestCommonsChecksum;

/**
 * TestDigestUtilsWithCommonsCodec
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */

public class TestDigestUtilsWithCommonsCodec extends AbstractTestCommonsChecksum {

    @Before
    public void addBouncyCastleProvider() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void md5() throws IOException, DecoderException {
        byte[] md5 = null;
        byte[] codecMd5 = null;
        md5 = DigestUtils.md5(HELLO_WORLD_STRING);
        codecMd5 = org.apache.commons.codec.digest.DigestUtils.md5(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(codecMd5, md5);
        md5 = DigestUtils.md5(HELLO_WORLD_BYTE_ARRAY);
        codecMd5 = org.apache.commons.codec.digest.DigestUtils.md5(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(codecMd5, md5);
        md5 = DigestUtils.md5(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecMd5 = org.apache.commons.codec.digest.DigestUtils.md5(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(codecMd5, md5);
    }

    @Test
    public void md5Hex() throws IOException {
        String md5Hex = null;
        String codecMd5Hex = null;
        md5Hex = DigestUtils.md5Hex(HELLO_WORLD_STRING);
        codecMd5Hex = org.apache.commons.codec.digest.DigestUtils.md5Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(codecMd5Hex, md5Hex);
        md5Hex = DigestUtils.md5Hex(HELLO_WORLD_BYTE_ARRAY);
        codecMd5Hex = org.apache.commons.codec.digest.DigestUtils.md5Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(codecMd5Hex, md5Hex);
        md5Hex = DigestUtils.md5Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecMd5Hex = org.apache.commons.codec.digest.DigestUtils.md5Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(codecMd5Hex, md5Hex);
    }

    @After
    public void removeBouncyCastleProvider() throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void sha1() throws IOException, DecoderException {
        byte[] sha1 = null;
        byte[] codecSha1 = null;
        sha1 = DigestUtils.sha1(HELLO_WORLD_STRING);
        codecSha1 = org.apache.commons.codec.digest.DigestUtils.sha(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(codecSha1, sha1);
        sha1 = DigestUtils.sha1(HELLO_WORLD_BYTE_ARRAY);
        codecSha1 = org.apache.commons.codec.digest.DigestUtils.sha(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(codecSha1, sha1);
        sha1 = DigestUtils.sha1(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha1 = org.apache.commons.codec.digest.DigestUtils.sha(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(codecSha1, sha1);
    }

    @Test
    public void sha1Hex() throws IOException {
        String sha1Hex = null;
        String codecSha1Hex = null;
        sha1Hex = DigestUtils.sha1Hex(HELLO_WORLD_STRING);
        codecSha1Hex = org.apache.commons.codec.digest.DigestUtils.shaHex(HELLO_WORLD_STRING);
        Assert.assertEquals(codecSha1Hex, sha1Hex);
        sha1Hex = DigestUtils.sha1Hex(HELLO_WORLD_BYTE_ARRAY);
        codecSha1Hex = org.apache.commons.codec.digest.DigestUtils.shaHex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(codecSha1Hex, sha1Hex);
        sha1Hex = DigestUtils.sha1Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha1Hex = org.apache.commons.codec.digest.DigestUtils.shaHex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(codecSha1Hex, sha1Hex);
    }

    @Test
    public void sha256() throws IOException, DecoderException {
        byte[] sha256 = null;
        byte[] codecSha256 = null;
        sha256 = DigestUtils.sha256(HELLO_WORLD_STRING);
        codecSha256 = org.apache.commons.codec.digest.DigestUtils.sha256(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(codecSha256, sha256);
        sha256 = DigestUtils.sha256(HELLO_WORLD_BYTE_ARRAY);
        codecSha256 = org.apache.commons.codec.digest.DigestUtils.sha256(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(codecSha256, sha256);
        sha256 = DigestUtils.sha256(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha256 = org.apache.commons.codec.digest.DigestUtils.sha256(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(codecSha256, sha256);
    }

    @Test
    public void sha256Hex() throws IOException {
        String sha256Hex = null;
        String codecSha256hex = null;
        sha256Hex = DigestUtils.sha256Hex(HELLO_WORLD_STRING);
        codecSha256hex = org.apache.commons.codec.digest.DigestUtils.sha256Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(codecSha256hex, sha256Hex);
        sha256Hex = DigestUtils.sha256Hex(HELLO_WORLD_BYTE_ARRAY);
        codecSha256hex = org.apache.commons.codec.digest.DigestUtils.sha256Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(codecSha256hex, sha256Hex);
        sha256Hex = DigestUtils.sha256Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha256hex = org.apache.commons.codec.digest.DigestUtils.sha256Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(codecSha256hex, sha256Hex);
    }

    @Test
    public void sha384() throws IOException, DecoderException {
        byte[] sha384 = null;
        byte[] codecSha384 = null;
        sha384 = DigestUtils.sha384(HELLO_WORLD_STRING);
        codecSha384 = org.apache.commons.codec.digest.DigestUtils.sha384(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(codecSha384, sha384);
        sha384 = DigestUtils.sha384(HELLO_WORLD_BYTE_ARRAY);
        codecSha384 = org.apache.commons.codec.digest.DigestUtils.sha384(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(codecSha384, sha384);
        sha384 = DigestUtils.sha384(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha384 = org.apache.commons.codec.digest.DigestUtils.sha384(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(codecSha384, sha384);
    }

    @Test
    public void sha384Hex() throws IOException {
        String sha384Hex = null;
        String codecSha384hex = null;
        sha384Hex = DigestUtils.sha384Hex(HELLO_WORLD_STRING);
        codecSha384hex = org.apache.commons.codec.digest.DigestUtils.sha384Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(codecSha384hex, sha384Hex);
        sha384Hex = DigestUtils.sha384Hex(HELLO_WORLD_BYTE_ARRAY);
        codecSha384hex = org.apache.commons.codec.digest.DigestUtils.sha384Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(codecSha384hex, sha384Hex);
        sha384Hex = DigestUtils.sha384Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha384hex = org.apache.commons.codec.digest.DigestUtils.sha384Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(codecSha384hex, sha384Hex);
    }

    @Test
    public void sha512() throws IOException, DecoderException {
        byte[] sha512 = null;
        byte[] codecSha512 = null;
        sha512 = DigestUtils.sha512(HELLO_WORLD_STRING);
        codecSha512 = org.apache.commons.codec.digest.DigestUtils.sha512(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(codecSha512, sha512);
        sha512 = DigestUtils.sha512(HELLO_WORLD_BYTE_ARRAY);
        codecSha512 = org.apache.commons.codec.digest.DigestUtils.sha512(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(codecSha512, sha512);
        sha512 = DigestUtils.sha512(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha512 = org.apache.commons.codec.digest.DigestUtils.sha512(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(codecSha512, sha512);
    }

    @Test
    public void sha512Hex() throws IOException {
        String sha512Hex = null;
        String codecSha512hex = null;
        sha512Hex = DigestUtils.sha512Hex(HELLO_WORLD_STRING);
        codecSha512hex = org.apache.commons.codec.digest.DigestUtils.sha512Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(codecSha512hex, sha512Hex);
        sha512Hex = DigestUtils.sha512Hex(HELLO_WORLD_BYTE_ARRAY);
        codecSha512hex = org.apache.commons.codec.digest.DigestUtils.sha512Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(codecSha512hex, sha512Hex);
        sha512Hex = DigestUtils.sha512Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        codecSha512hex = org.apache.commons.codec.digest.DigestUtils.sha512Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(codecSha512hex, sha512Hex);
    }

}
