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

import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import com.google.code.commons.checksum.AbstractTestCommonsChecksum;

/**
 * TestDigestUtilsWithoutBouncyCastle
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */
public class TestDigestUtilsWithoutBouncyCastle extends AbstractTestCommonsChecksum {

    @Test(expected = RuntimeException.class)
    public void getDigestNoSuchAlgorithmException() {
        DigestUtils.getDigest("RIPEMD128");
    }

    @SuppressWarnings("unchecked")
    @Test(expected = RuntimeException.class)
    public void getDigestNoSuchProviderException() throws SecurityException, NoSuchFieldException,
            IllegalArgumentException, IllegalAccessException {
        Field field = DigestUtils.class.getDeclaredField("digestProviderNameMap");
        field.setAccessible(true);
        ((ConcurrentHashMap<String, String>) field.get(new DigestUtils())).put("TOTO", "foo");
        DigestUtils.getDigest("TOTO");
    }

    /**
     * Java ™ Cryptography Architecture<br>
     * Sun Providers Documentation<br>
     * http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html<br>
     * <br>
     * SunProvider :<br>
     * <ul>
     * <li>MD2</li>
     * <li>MD5</li>
     * <li>SHA-1</li>
     * <li>SHA-256</li>
     * <li>SHA-384</li>
     * <li>SHA-512</li>
     * </ul>
     * 
     */
    @Test
    public void isAvailable() {
        Assert.assertTrue(DigestUtils.isMd2Available());
        Assert.assertFalse(DigestUtils.isMd4Available());
        Assert.assertTrue(DigestUtils.isMd5Available());
        Assert.assertFalse(DigestUtils.isRipmed128Available());
        Assert.assertFalse(DigestUtils.isRipmed160Available());
        Assert.assertFalse(DigestUtils.isRipmed256Available());
        Assert.assertFalse(DigestUtils.isRipmed320Available());
        Assert.assertTrue(DigestUtils.isSha1Available());
        Assert.assertTrue(DigestUtils.isSha224Available()); // JDK 8 / JDK 5 difference
        Assert.assertTrue(DigestUtils.isSha256Available());
        Assert.assertTrue(DigestUtils.isSha384Available());
        Assert.assertTrue(DigestUtils.isSha512Available());
        Assert.assertFalse(DigestUtils.isTigerAvailable());
        Assert.assertFalse(DigestUtils.isWhirlpoolAvailable());
    }

    @Test
    public void registerPreferredProvider() {
        Assert.assertFalse(DigestUtils.registerPreferredProvider("MD5", BouncyCastleProvider.PROVIDER_NAME));
        Assert.assertFalse(DigestUtils.registerPreferredProvider("RIPEMD128", "SUN"));
    }
}
