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

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import com.google.code.commons.checksum.binary.TestBinaryUtils;
import com.google.code.commons.checksum.digest.TestDigestUtils;
import com.google.code.commons.checksum.digest.TestDigestUtilsWithCommonsCodec;
import com.google.code.commons.checksum.digest.TestDigestUtilsWithoutBouncyCastle;

/**
 * TestSuite
 * 
 * @author <a href="mailto:qlefevre+commons-checksum@gmail.com">Quentin Lefevre</a>
 * @since Commons Checksum 1.0
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({ TestBinaryUtils.class, TestChecksumUtils.class, TestFletcher32.class, TestDigestUtils.class,
        TestDigestUtilsWithoutBouncyCastle.class, TestDigestUtilsWithCommonsCodec.class })
public class TestSuite {

}
