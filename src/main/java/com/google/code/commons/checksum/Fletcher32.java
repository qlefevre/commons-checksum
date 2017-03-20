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

import java.util.zip.Checksum;

import com.google.code.commons.checksum.binary.BinaryUtils;

/**
 * A class that can be used to compute the Fletcher-32 of a data stream.
 * 
 * @see Checksum
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @version $Id: Fletcher32.java 30 2012-05-19 06:49:47Z qlefevre@gmail.com $
 * @since Commons Checksum 1.0
 */

public class Fletcher32 implements Checksum {

    private int sum1 = 0;
    private int sum2 = 0;

    /**
     * Creates a new Fletcher-32 object.
     */
    public Fletcher32() {
    }

    /**
     * Returns Fletcher-32 value.
     * 
     * @since Commons Checksum 1.0
     */
    public long getValue() {
        return (sum2 << 16) | sum1;
    }

    /**
     * Resets Fletcher-32 to initial value.
     * 
     * @since Commons Checksum 1.0
     */
    public void reset() {
        sum1 = 0;
        sum2 = 0;
    }

    /**
     * Updates checksum with specified array of bytes.
     * 
     * @param b
     *            the array of bytes to update the checksum with
     * @since Commons Checksum 1.0
     */
    public void update(byte[] b) {
        update(b, 0, b.length);
    }

    /**
     * Updates Fletcher-32 with specified array of bytes.
     * 
     * @since Commons Checksum 1.0
     */
    public void update(byte[] b, int off, int len) {
        if (b == null) {
            throw new NullPointerException();
        }
        if (off < 0 || len < 0 || off > b.length - len) {
            throw new ArrayIndexOutOfBoundsException();
        }
        updateBytes(b, off, len);
    }

    /**
     * Updates Fletcher-32 with specified byte.
     * 
     * @since Commons Checksum 1.0
     */
    public void update(int b) {
        update(BinaryUtils.toBytes(b));
    }

    /**
     * Updates Fletcher-32 with specified array of bytes.
     * 
     * @since Commons Checksum 1.0
     */
    private void updateBytes(byte[] b, int off, int len) {
        for (int i = off; i < len; i++) {
            sum1 = (sum1 + (b[i] & 0xff)) % 65535;
            sum2 = (sum2 + sum1) % 65535;
        }
    }
}
