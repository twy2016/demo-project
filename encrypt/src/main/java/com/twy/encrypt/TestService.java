package com.twy.encrypt;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.lang.Assert;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.digest.*;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author gongpeng
 * @date 2023/8/9 15:59
 */
public class TestService {

    @Test
    public void testMd5() {
        String result = DigestUtil.md5Hex("test");
        System.out.println(result);
    }

    @Test
    public void testSHA() {
        String sha1 = DigestUtil.sha1Hex("test");
        String sha256 = DigestUtil.sha256Hex("test");
        Digester digester = new Digester(DigestAlgorithm.SHA384);
        String sha384 = digester.digestHex("test");
        String sha512 = DigestUtil.sha512Hex("test");
        // a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
        System.out.println(sha1);
        // 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        System.out.println(sha256);
        // 768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9
        System.out.println(sha384);
        // ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
        System.out.println(sha512);
    }

    @Test
    public void testHMac() {
        String testStr = "test";
        byte[] key = "password".getBytes();
        HMac mac = new HMac(HmacAlgorithm.HmacMD5, key);
        String HmacMD5 = mac.digestHex(testStr);
        // 3161ccfd7f23e32bbc3e4867fc94b187
        System.out.println(HmacMD5);
        mac = new HMac(HmacAlgorithm.HmacSHA1, key);
        String HmacSHA1 = mac.digestHex(testStr);
        // b0ec7dbee291c715dd50e2b4b8b700438088391a
        System.out.println(HmacSHA1);
        mac = new HMac(HmacAlgorithm.HmacSHA256, key);
        String HmacSHA256 = mac.digestHex(testStr);
        // d8402bd365a34b4d34729c3fa420818b2913de85533ae9e8b22434bef7ac7bba
        System.out.println(HmacSHA256);
        mac = new HMac(HmacAlgorithm.HmacSHA384, key);
        String HmacSHA384 = mac.digestHex(testStr);
        // 2b7c2f4456e80dcbf071c74edad222645e5bcb127c51c22496d91613a6eb54800dcecafead1cb9318b7e1303f07aebb0
        System.out.println(HmacSHA384);
        mac = new HMac(HmacAlgorithm.HmacSHA512, key);
        String HmacSHA512 = mac.digestHex(testStr);
        // fea90ff348364c8dcc4b1f7df0fe3ac38c83598dd9a9f0197cd041b12ac5b6495efb0a674d2d82da143cc5b585dc6e5cd80b0f7a7ebaf968254eb2e8d1e0e5bd
        System.out.println(HmacSHA512);
    }

    @Test
    public void testDes() {
        String content = "test";
        //随机生成密钥
        byte[] key = SecureUtil.generateKey(SymmetricAlgorithm.DES.getValue(), "password".getBytes()).getEncoded();
        //构建
        SymmetricCrypto des = new SymmetricCrypto(SymmetricAlgorithm.DES, key);
        //加密
        byte[] encrypt = des.encrypt(content);
        //解密
        byte[] decrypt = des.decrypt(encrypt);
        //加密为16进制表示
        String encryptHex = des.encryptHex(content);
        //解密为字符串
        String decryptStr = des.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        System.out.println(encryptHex);
        System.out.println(decryptStr);
    }

    @Test
    public void testAes() {
        String content = "test";
        //随机生成密钥
        byte[] key = SecureUtil.generateKey(SymmetricAlgorithm.AES.getValue(), "passwordpassword".getBytes()).getEncoded();
        //构建
        SymmetricCrypto aes = new SymmetricCrypto(SymmetricAlgorithm.AES, key);
        //加密
        byte[] encrypt = aes.encrypt(content);
        //解密
        byte[] decrypt = aes.decrypt(encrypt);
        //加密为16进制表示
        String encryptHex = aes.encryptHex(content);
        //解密为字符串
        String decryptStr = aes.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        System.out.println(encryptHex);
        System.out.println(decryptStr);
    }

    @Test
    public void testRsa() {
        //获得私钥
        KeyPair keyPair = SecureUtil.generateKeyPair("RSA");
        PrivateKey privateKey = keyPair.getPrivate();
        String privateKeyBase64 = Base64.encode(privateKey.getEncoded());
        //获得公钥
        PublicKey publicKey = keyPair.getPublic();
        String publicKeyBase64 = Base64.encode(publicKey.getEncoded());

        RSA rsa = SecureUtil.rsa(privateKeyBase64, publicKeyBase64);
        //公钥加密，私钥解密
        byte[] encrypt = rsa.encrypt(StrUtil.bytes("tangwanyan", CharsetUtil.CHARSET_UTF_8), KeyType.PublicKey);
        byte[] decrypt = rsa.decrypt(encrypt, KeyType.PrivateKey);

        //结果测试
        System.out.println("tangwanyan".equals(StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8)));

        //私钥加密，公钥解密
        byte[] encrypt2 = rsa.encrypt(StrUtil.bytes("tangwanyan", CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
        byte[] decrypt2 = rsa.decrypt(encrypt2, KeyType.PublicKey);

        //结果测试
        System.out.println("tangwanyan".equals(StrUtil.str(decrypt2, CharsetUtil.CHARSET_UTF_8)));
    }
}
