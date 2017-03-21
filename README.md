# commons-checksum

Commons Checksum provides functional utilities for working with common checksums and hashes. Project relies on the great utilities providing by the DigestUtils class of Apache Commons Codec project.

The class [org.apache.commons.codec.digest.DigestUtils](http://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/digest/DigestUtils.html) was improved to handle new algorithms such as: 
* MD2
* MD4
* MD5
* RIPEMD-128
* RIPEMD-160
* RIPEMD-256
* RIPEMD-320
* SHA-1
* SHA-224
* SHA-256
* SHA-384
* SHA-512
* Tiger
* Whirlpool

A new class ChecksumUtils which extends DigestUtils was added. It handles checksum algorithms such as :

* Adler-32
* CRC-32
* Fletcher-32

#Two Minute Tutorial

There are six method signatures for each algorithm as described below :

public static byte[] md2(byte[] data)
public static byte[] md2(InputStream data) throws IOException
public static byte[] md2(String data)
public static String md2Hex(byte[] data)
public static String md2Hex(InputStream data) throws IOException
public static String md2Hex(String data)
Calculating the checksum of a byte array

public static final byte[] HELLO_WORLD_BYTE_ARRAY = "Hello World".getBytes(); ... String crc32Hex = ChecksumUtils.crc32Hex(HELLO_WORLD_BYTE_ARRAY); String sha512Hex = ChecksumUtils.sha512Hex(HELLO_WORLD_BYTE_ARRAY);

Calculating the checksum of a String

public static final String HELLO_WORLD_STRING = "Hello World"; ... String md5Hex = ChecksumUtils.md5Hex(HELLO_WORLD_STRING); String whirlpoolHex = ChecksumUtils.whirlpoolHex(HELLO_WORLD_STRING);

Note

Oracle JDK offers 6 digest algorithms : MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512.

| Digest | Oracle JDK 1.6> | Bouncy Castle | |:-----------|:-----------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------| | MD2 | yes | yes | | MD4 | no | yes | | MD5 | yes | yes | | RIPEMD-128 | no | yes | | RIPEMD-160 | no | yes | | RIPEMD-256 | no | yes | | RIPEMD-320 | no | yes | | SHA-1 | yes | yes | | SHA-224 | no | yes | | SHA-256 | yes | yes | | SHA-384 | yes | yes | | SHA-512 | yes | yes | | Tiger | no | yes | | Whirlpool | no | yes |

See: * Bouncy Castle : org.bouncycastle.jce.provider.JDKMessageDigest * Sun : sun.security.provider.Sun

Configuring Bouncy Castle

If you have a mavenized project, you can add this dependency : <dependency> <groupId>org.bouncycastle</groupId> <artifactId>bcprov-ext-jdk16</artifactId> <version>1.46</version> </dependency> You can now use the Whirlpool digest. You just have to register the provider programatically : ``` Security.addProvider(new BouncyCastleProvider());

String whirlpool = whirlpool2Hex("Hello world !"); ... ```
