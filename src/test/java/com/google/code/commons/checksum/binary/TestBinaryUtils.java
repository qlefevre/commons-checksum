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

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import com.google.code.commons.checksum.AbstractTestCommonsChecksum;

/**
 * TestBinaryUtils
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */
public class TestBinaryUtils extends AbstractTestCommonsChecksum {

    public static byte[] BYTE_ARRAY_4_65142 = new byte[] { 0, 0, -2, 118 }; // 65142

    public static byte[] BYTE_ARRAY_8_65142 = new byte[] { 0, 0, 0, 0, 0, 0, -2, 118 }; // 65142

    @Test
    public void encodeHexString() {
        Assert.assertEquals(Hex.encodeHexString(HELLO_WORLD_BYTE_ARRAY),
                BinaryUtils.encodeHexString(HELLO_WORLD_BYTE_ARRAY));
    }

    @Test
    public void getBytesUtf8() {
        Assert.assertArrayEquals(StringUtils.getBytesUtf8(HELLO_WORLD_STRING),
                BinaryUtils.getBytesUtf8(HELLO_WORLD_STRING));
        Assert.assertNull(BinaryUtils.getBytesUtf8(null));
    }

    @Test
    public void toBytes() {
        Assert.assertArrayEquals(BYTE_ARRAY_4_65142, BinaryUtils.toBytes(65142));
        Assert.assertArrayEquals(BYTE_ARRAY_4_65142, BinaryUtils.toBytes(65142, 4));

        // check bounds (size > 8 || size < 1)
        Assert.assertArrayEquals(BYTE_ARRAY_8_65142, BinaryUtils.toBytes(65142, -42));
        Assert.assertArrayEquals(BYTE_ARRAY_8_65142, BinaryUtils.toBytes(65142, 42));
    }
}
