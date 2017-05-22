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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * AbstractTestCommonsChecksum
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */
public abstract class AbstractTestCommonsChecksum {

    public static final String ABC_STRING = "abc";

    public static final byte[] ABC_BYTE_ARRAY = ABC_STRING.getBytes();
	
    public static final String HELLO_WORLD_STRING = "Hello World";

    public static final byte[] HELLO_WORLD_BYTE_ARRAY = HELLO_WORLD_STRING.getBytes();

    public static byte[] hexToBytes(Map<String,String> checksumMap,String algorithm) throws DecoderException {
        return Hex.decodeHex(checksumMap.get(algorithm).toCharArray());
    }
    
    protected static Map<String,String> toMap(String[][] checksumsArray){
    	Map<String,String> checksums = new HashMap<String,String>();
    	for(String[] checksumPair : checksumsArray){
    		checksums.put(checksumPair[0], checksumPair[1]);
    	}
    	return Collections.unmodifiableMap(checksums);
    }

}
