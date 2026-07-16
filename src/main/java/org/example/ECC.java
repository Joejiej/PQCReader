package org.example;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

import static org.example.TrustFramework.concatBytes;


//包括和ECC适配的hash
public class ECC {
    public static byte[] signMessage(PrivateKey privateKey, byte[] messageBytes) throws Exception {

        // 初始化签名器
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(messageBytes);

        // 生成签名
        return signature.sign();
    }

    public static boolean verifySignature(byte[] origin, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
        sig.initVerify(publicKey);
        sig.update(origin);
        return sig.verify(signature); // 返回验签结果
    }


    public static byte[] getSHA256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256算法不可用", e);
        }
    }

    public static byte[] getSHA256Hex(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256算法不可用", e);
        }
    }

    public static KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "BC"); // 指定 ECC 算法和提供者
        keyPairGen.initialize(256); // 使用 256 位密钥长度（相当于 RSA 3072 位安全性）
        return keyPairGen.generateKeyPair();
    }

    public static byte[] derToRaw(byte[] derSig) throws Exception {
        if (derSig[0] != 0x30) {
            throw new IllegalArgumentException("Not a valid DER sequence");
        }

        int idx = 2; // 跳过 0x30 和长度

        if (derSig[idx] != 0x02) {
            throw new IllegalArgumentException("Expected INTEGER for r");
        }
        int rLen = derSig[idx + 1];
        byte[] rBytes = Arrays.copyOfRange(derSig, idx + 2, idx + 2 + rLen);
        idx = idx + 2 + rLen;

        if (derSig[idx] != 0x02) {
            throw new IllegalArgumentException("Expected INTEGER for s");
        }
        int sLen = derSig[idx + 1];
        byte[] sBytes = Arrays.copyOfRange(derSig, idx + 2, idx + 2 + sLen);

        // 转成 BigInteger 去掉前导 0
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        byte[] rFixed = toFixedLength(r.toByteArray(), 32);
        byte[] sFixed = toFixedLength(s.toByteArray(), 32);

        // 拼接 r||s
        byte[] rawSig = new byte[64];
        System.arraycopy(rFixed, 0, rawSig, 0, 32);
        System.arraycopy(sFixed, 0, rawSig, 32, 32);

        return rawSig;
    }

    private static byte[] toFixedLength(byte[] src, int length) {
        if (src.length == length) return src;
        byte[] dest = new byte[length];
        if (src.length > length) {
            // 去掉前导 0
            System.arraycopy(src, src.length - length, dest, 0, length);
        } else {
            // 前面补 0
            System.arraycopy(src, 0, dest, length - src.length, src.length);
        }
        return dest;
    }

    public static byte[] rawToDer(byte[] raw) throws Exception {
        if (raw.length != 64) {
            throw new IllegalArgumentException("raw signature must be 64 bytes");
        }

        // 前32字节 r，后32字节 s
        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        System.arraycopy(raw, 0, rBytes, 0, 32);
        System.arraycopy(raw, 32, sBytes, 0, 32);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        return derEncode(r, s);
    }

    private static byte[] derEncode(BigInteger r, BigInteger s) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x30); // SEQUENCE

        // 编码 r
        byte[] rEnc = encodeInteger(r);
        // 编码 s
        byte[] sEnc = encodeInteger(s);

        int len = rEnc.length + sEnc.length;
        baos.write(len);
        baos.write(rEnc);
        baos.write(sEnc);

        return baos.toByteArray();
    }

    private static byte[] encodeInteger(BigInteger x) throws Exception {
        byte[] val = x.toByteArray();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x02); // INTEGER tag
        baos.write(val.length);
        baos.write(val);
        return baos.toByteArray();
    }

    public static byte[] extractECPublicKeyPoint(X509Certificate cert) throws IOException {
        PublicKey pk = cert.getPublicKey();

        byte[] spkiBytes = pk.getEncoded();

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(spkiBytes));

        DERBitString pubKeyBitString = (DERBitString) spki.getPublicKeyData();

        return pubKeyBitString.getOctets();
    }

    public static byte[] extractSignatureBitString(X509Certificate cert) throws IOException, CertificateEncodingException {
        // 获取证书的 DER 编码
        byte[] certBytes = cert.getEncoded();

        // 解析为 ASN.1 Certificate
        Certificate bcCert = Certificate.getInstance(ASN1Primitive.fromByteArray(certBytes));

        // 获取签名 BIT STRING
        DERBitString signatureBitString = (DERBitString) bcCert.getSignature();

        // 返回 BIT STRING 的字节内容
        return signatureBitString.getBytes();
    }

    public static byte[] generateSharedKey(PublicKey ePubK, PrivateKey ePrivK, byte[] transactionId) throws Exception {
        if (transactionId == null || transactionId.length != 16) {
            throw new IllegalArgumentException("transaction_identifier must be 16 bytes");
        }

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ePrivK);
        ka.doPhase(ePubK, true);

        byte[] sharedSecret = ka.generateSecret();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(transactionId, "HmacSHA256"));
        byte[] kdhFull = mac.doFinal(sharedSecret);

        return Arrays.copyOf(kdhFull, 32);
    }

    // HKDF-Extract
    private static byte[] HKDF_extract(byte[] salt, byte[] ikm) throws Exception {
        if (salt == null) {
            salt = new byte[32]; // 全 0
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    // HKDF-Expand
    private static byte[] HKDF_expand(byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));

        int n = (int) Math.ceil((double) length / 32);
        byte[] t = new byte[0];
        byte[] okm = new byte[0];

        for (int i = 1; i <= n; i++) {
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            okm = concatBytes(okm, t);
        }
        return Arrays.copyOfRange(okm, 0, length);
    }

    // 完整 HKDF
    public static byte[] deriveKey(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        byte[] prk = HKDF_extract(salt, ikm);
        return HKDF_expand(prk, info, length);
    }

    // GCM-AES-256
    public static byte[][] GCM_AES_encrypt(byte[] payload, byte[] SKDevice, byte[] device_counter, byte[] aad) {
        try {
            if (SKDevice.length != 32) {
                throw new IllegalArgumentException("SKDevice must be 32 bytes for AES-256");
            }
            if (device_counter.length != 4) {
                throw new IllegalArgumentException("Device counter must be 4 bytes");
            }

            byte[] iv = AES_createIV(device_counter);

            SecretKey secretKey = new SecretKeySpec(SKDevice, "AES");

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            byte[] encryptedPayload = cipher.doFinal(payload);

            return splitEncryptedDataAndTag(encryptedPayload);

        } catch (Exception e) {
            throw new RuntimeException("GCM encryption failed", e);
        }
    }

    private static byte[] AES_createIV(byte[] device_counter) {
        byte[] iv = new byte[12];
        iv[7] = 0x01;

        System.arraycopy(device_counter, 0, iv, 8, 4);

        return iv;
    }

    private static byte[][] splitEncryptedDataAndTag(byte[] encryptedData) {
        int dataLength = encryptedData.length - 16; // 认证标签占16字节
        byte[] encryptedPayload = Arrays.copyOfRange(encryptedData, 0, dataLength);
        byte[] authenticationTag = Arrays.copyOfRange(encryptedData, dataLength, encryptedData.length);

        return new byte[][]{encryptedPayload, authenticationTag};
    }

    public static byte[] GCM_AES_decrypt(byte[] encryptedPayload, byte[] authenticationTag,
                                 byte[] SKDevice, byte[] device_counter, byte[] aad) {
        try {
            if (SKDevice.length != 32) {
                throw new IllegalArgumentException("SKDevice must be 32 bytes for AES-256");
            }
            if (device_counter.length != 4) {
                throw new IllegalArgumentException("Device counter must be 4 bytes");
            }
            if (authenticationTag.length != 16) {
                throw new IllegalArgumentException("Authentication tag must be 16 bytes");
            }

            byte[] combinedData = combineEncryptedDataAndTag(encryptedPayload, authenticationTag);

            byte[] iv = AES_createIV(device_counter);

            SecretKey secretKey = new SecretKeySpec(SKDevice, "AES");

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(combinedData);

        } catch (Exception e) {
            throw new RuntimeException("GCM decryption failed", e);
        }
    }

    public static byte[] intToBigEndianBytes(int value) {
        return new byte[] {
                (byte) ((value >> 24) & 0xFF),
                (byte) ((value >> 16) & 0xFF),
                (byte) ((value >> 8) & 0xFF),
                (byte) (value & 0xFF)
        };
    }

    private static byte[] combineEncryptedDataAndTag(byte[] encryptedPayload, byte[] authenticationTag) {
        byte[] combined = new byte[encryptedPayload.length + authenticationTag.length];
        System.arraycopy(encryptedPayload, 0, combined, 0, encryptedPayload.length);
        System.arraycopy(authenticationTag, 0, combined, encryptedPayload.length, authenticationTag.length);
        return combined;
    }

}
