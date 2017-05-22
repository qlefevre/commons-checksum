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

/**
 * TestChecksumUtils
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */
public class TestChecksumUtils extends AbstractTestCommonsChecksum {

    public static final Map<String,String> HELLO_WORLD_CHECKSUMS = toMap(new String[][]{
		{ "ADLER32", "180b041d" },
	    { "CRC32", "4a17b156" },
	    { "FLETCHER32", "1800041c"}
	});

    @Before
    public void addBouncyCastleProvider() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void adler32() throws IOException, DecoderException {
        byte[] adler32 = null;
        adler32 = ChecksumUtils.adler32(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"ADLER32"), adler32);
        adler32 = ChecksumUtils.adler32(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"ADLER32"), adler32);
        adler32 = ChecksumUtils.adler32(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"ADLER32"), adler32);
    }

    @Test
    public void adler32Hex() throws IOException {
        String adler32Hex = null;
        adler32Hex = ChecksumUtils.adler32Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("ADLER32"), adler32Hex);
        adler32Hex = ChecksumUtils.adler32Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("ADLER32"), adler32Hex);
        adler32Hex = ChecksumUtils.adler32Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("ADLER32"), adler32Hex);
    }

    @Test
    public void crc32() throws IOException, DecoderException {
        byte[] crc32 = null;
        crc32 = ChecksumUtils.crc32(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"CRC32"), crc32);
        crc32 = ChecksumUtils.crc32(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"CRC32"), crc32);
        crc32 = ChecksumUtils.crc32(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"CRC32"), crc32);
    }

    @Test
    public void crc32Hex() throws IOException {
        String crc32Hex = null;
        crc32Hex = ChecksumUtils.crc32Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("CRC32"), crc32Hex);
        crc32Hex = ChecksumUtils.crc32Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("CRC32"), crc32Hex);
        crc32Hex = ChecksumUtils.crc32Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("CRC32"), crc32Hex);
    }

    @Test
    public void fletcher32() throws IOException, DecoderException {
        byte[] fletcher32 = null;
        fletcher32 = ChecksumUtils.fletcher32(HELLO_WORLD_STRING);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"FLETCHER32"), fletcher32);
        fletcher32 = ChecksumUtils.fletcher32(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"FLETCHER32"), fletcher32);
        fletcher32 = ChecksumUtils.fletcher32(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertArrayEquals(hexToBytes(HELLO_WORLD_CHECKSUMS,"FLETCHER32"), fletcher32);
    }

    @Test
    public void fletcher32Hex() throws IOException {
        String fletcher32Hex = null;
        fletcher32Hex = ChecksumUtils.fletcher32Hex(HELLO_WORLD_STRING);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("FLETCHER32"), fletcher32Hex);
        fletcher32Hex = ChecksumUtils.fletcher32Hex(HELLO_WORLD_BYTE_ARRAY);
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("FLETCHER32"), fletcher32Hex);
        fletcher32Hex = ChecksumUtils.fletcher32Hex(new ByteArrayInputStream(HELLO_WORLD_BYTE_ARRAY));
        Assert.assertEquals(HELLO_WORLD_CHECKSUMS.get("FLETCHER32"), fletcher32Hex);
    }

    @After
    public void removeBouncyCastleProvider() throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

}
