# commons-checksum [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.qlefevre/commons-checksum/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.qlefevre/commons-checksum) [![Build Status](https://travis-ci.com/qlefevre/commons-checksum.svg)](https://travis-ci.com/qlefevre/commons-checksum) [![Coverage](https://codecov.io/gh/qlefevre/commons-checksum/branch/master/graph/badge.svg)](https://codecov.io/gh/qlefevre/commons-checksum)

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

# Installation
To use the latest release of commons-checksum, please use the following snippet in your pom.xml.
```xml
<dependency>
    <groupId>com.github.qlefevre</groupId>
    <artifactId>commons-checksum</artifactId>
    <version>1.0.0</version>
</dependency>
```

# Two Minute Tutorial

There are six method signatures for each algorithm as described below :
```java
public static byte[] md2(byte[] data)
public static byte[] md2(InputStream data) throws IOException
public static byte[] md2(String data)
public static String md2Hex(byte[] data)
public static String md2Hex(InputStream data) throws IOException
public static String md2Hex(String data)
```
## Calculating the checksum of a byte array
```java
public static final byte[] HELLO_WORLD_BYTE_ARRAY = "Hello World".getBytes();
String crc32Hex = ChecksumUtils.crc32Hex(HELLO_WORLD_BYTE_ARRAY);
String sha512Hex = ChecksumUtils.sha512Hex(HELLO_WORLD_BYTE_ARRAY);
```
## Calculating the checksum of a String
```java
public static final String HELLO_WORLD_STRING = "Hello World";
String md5Hex = ChecksumUtils.md5Hex(HELLO_WORLD_STRING);
String whirlpoolHex = ChecksumUtils.whirlpoolHex(HELLO_WORLD_STRING);
```
# Note

Oracle JDK 8 offers [7 digest algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SUNProvider) : MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.

| Digest | Oracle JDK 1.8> | Oracle JDK 1.6> | Bouncy Castle | 
|--------|-----------------|-----------------|---------------| 
| MD2 | **yes** | **yes**| **yes** |
| MD4 | no | no | **yes** |
| MD5 | **yes** | **yes** | **yes** |
| RIPEMD-128 | no | no | **yes** |
| RIPEMD-160 | no | no | **yes** |
| RIPEMD-256 | no | no | **yes** |
| RIPEMD-320 | no | no | **yes** |
| SHA-1 | **yes** | **yes** | **yes** |
| SHA-224 | **yes** | no | **yes** |
| SHA-256 | **yes** | **yes** | **yes** |
| SHA-384 | **yes** | **yes** | **yes** |
| SHA-512 | **yes** | **yes** | **yes** |
| Tiger | no | no | **yes** |
| Whirlpool | no | no | **yes** |

See: 
* Bouncy Castle : org.bouncycastle.jce.provider.JDKMessageDigest
* Sun : sun.security.provider.Sun

# Configuring Bouncy Castle

If you have a mavenized project, you can add this dependency : 
```xml
<dependency>
 <groupId>org.bouncycastle</groupId>
 <artifactId>bcprov-ext-jdk16</artifactId>
 <version>1.46</version>
</dependency>
```
 You can now use the Whirlpool digest. You just have to register the provider programatically 
```java
Security.addProvider(new BouncyCastleProvider());
String whirlpool = whirlpool2Hex("Hello world !"); 
```
