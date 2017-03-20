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

import java.io.UnsupportedEncodingException;

import org.junit.Assert;
import org.junit.Test;

/**
 * TestFletcher32
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */
public class TestFletcher32 extends AbstractTestCommonsChecksum {

    public static final byte[] HELLO_WORLD_42_BYTE_ARRAY = "Hello World42".getBytes();
    
    public static final long HELLO_WORLD_FLETCHER32_LONG = Long.decode("0x1800041c");
    
    public static final byte[] WIKIPEDIA_BYTE_ARRAY = "Wikipedia".getBytes();
    
    public static final long WIKIPEDIA_FLETCHER32_LONG = Long.decode("0x11dd0397");

    public static final int VALUE_42 = 42;

    public static final long VALUE_42_LONG = Long.decode("0x002A002A");

    // ("42" + HELLO_WORLD_STRING).getBytes();

    public Fletcher32 getFletcher32() {
        Fletcher32 checksum = new Fletcher32();
        checksum.update(HELLO_WORLD_BYTE_ARRAY);
        return checksum;
    }

    @Test
    public void reset() {
        Fletcher32 checksum = getFletcher32();
        checksum.reset();
        Assert.assertEquals(0, checksum.getValue());
    }

    @Test
    public void update() throws UnsupportedEncodingException {
        Fletcher32 checksum = getFletcher32();
        Assert.assertEquals(HELLO_WORLD_FLETCHER32_LONG, checksum.getValue());

        checksum.reset();
        checksum.update(HELLO_WORLD_42_BYTE_ARRAY, 0, 11);
        Assert.assertEquals(HELLO_WORLD_FLETCHER32_LONG, checksum.getValue());
        
        checksum.reset();
        checksum.update(WIKIPEDIA_BYTE_ARRAY, 0, 9);
        Assert.assertEquals(WIKIPEDIA_FLETCHER32_LONG, checksum.getValue());

        checksum.reset();
        checksum.update(VALUE_42);
        Assert.assertEquals(VALUE_42_LONG, checksum.getValue());
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void updateLowerBound() {
        Fletcher32 checksum = getFletcher32();
        checksum.update(HELLO_WORLD_42_BYTE_ARRAY, -42, 11);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void updateNegativeLength() {
        Fletcher32 checksum = getFletcher32();
        checksum.update(HELLO_WORLD_42_BYTE_ARRAY, 0, -42);
    }

    @Test(expected = NullPointerException.class)
    public void updateNullArray() {
        Fletcher32 checksum = getFletcher32();
        checksum.update(null, 1, 4);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void updateUpperOffset() {
        Fletcher32 checksum = getFletcher32();
        checksum.update(HELLO_WORLD_42_BYTE_ARRAY, 5, 11);
    }

}
