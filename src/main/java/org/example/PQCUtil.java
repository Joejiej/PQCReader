package org.example;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * PQ-Aliro cryptographic utilities for the Reader side.
 * Mirrors UD's PQCUtil but operates entirely in-memory (no Android KeyStore).
 *
 * Algorithms:
 *   Signing  — Dilithium (level from PQCConfig.DILITHIUM_LEVEL)
 *   KEM      — Kyber    (level from PQCConfig.KYBER_LEVEL)
 *   Hash     — SHAKE256-512  (generateTransAH0)
 *   KDF      — HKDF-Extract (HMAC-SHA256) + HKDF-Expand
 *   AEAD     — AES-256-GCM  IV = 8B(1L) ‖ 4B counter big-endian
 */
public final class PQCUtil {

    private static final String PQC_PROVIDER = "BCPQC";
    private static final String BC_PROVIDER  = "BC";

    static {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(PQC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    private PQCUtil() {}

    // ================================================================== //
    //  Dilithium                                                           //
    // ================================================================== //

    public static KeyPair generateDilithiumKeyPair(int level)
            throws GeneralSecurityException {

        DilithiumParameterSpec spec;
        switch (level) {
            case 2: spec = DilithiumParameterSpec.dilithium2; break;
            case 3: spec = DilithiumParameterSpec.dilithium3; break;
            case 5: spec = DilithiumParameterSpec.dilithium5; break;
            default:
                throw new IllegalArgumentException("Unsupported Dilithium level: " + level);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", PQC_PROVIDER);
        kpg.initialize(spec, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /** Convenience: generate at the level configured in PQCConfig. */
    public static KeyPair generateDilithiumKeyPair()
            throws GeneralSecurityException {
        return generateDilithiumKeyPair(PQCConfig.DILITHIUM_LEVEL);
    }

    public static byte[] dilithiumSign(byte[] data, PrivateKey privateKey)
            throws GeneralSecurityException {
        Signature sig = Signature.getInstance("Dilithium", PQC_PROVIDER);
        sig.initSign(privateKey, new SecureRandom());
        sig.update(data);
        return sig.sign();
    }

    public static boolean dilithiumVerify(byte[] data,
                                          byte[] signature,
                                          PublicKey publicKey)
            throws GeneralSecurityException {
        Signature sig = Signature.getInstance("Dilithium", PQC_PROVIDER);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    // ================================================================== //
    //  Kyber KEM                                                           //
    // ================================================================== //

    public static KeyPair generateKyberKeyPair(int level)
            throws GeneralSecurityException {

        KyberParameterSpec spec;
        switch (level) {
            case 512:  spec = KyberParameterSpec.kyber512;  break;
            case 768:  spec = KyberParameterSpec.kyber768;  break;
            case 1024: spec = KyberParameterSpec.kyber1024; break;
            default:
                throw new IllegalArgumentException("Unsupported Kyber level: " + level);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", PQC_PROVIDER);
        kpg.initialize(spec, new SecureRandom());
        return kpg.generateKeyPair();
    }

    /** Convenience: generate at the level configured in PQCConfig. */
    public static KeyPair generateKyberKeyPair()
            throws GeneralSecurityException {
        return generateKyberKeyPair(PQCConfig.KYBER_LEVEL);
    }

    /**
     * Encapsulate: returns SecretKeyWithEncapsulation.
     * Call .getEncapsulation() for the ciphertext to send to UD,
     * call .getEncoded() for the raw shared secret.
     */
    public static SecretKeyWithEncapsulation kyberEncapsulateRaw(
            PublicKey publicKey,
            String secretKeyAlgorithm)
            throws GeneralSecurityException {

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", PQC_PROVIDER);
        keyGen.init(new KEMGenerateSpec(publicKey, secretKeyAlgorithm), new SecureRandom());
        return (SecretKeyWithEncapsulation) keyGen.generateKey();
    }

    /** Decapsulate: given UD's ciphertext and our private key, recover shared secret. */
    public static SecretKey kyberDecapsulateRaw(
            PrivateKey privateKey,
            byte[] encapsulation,
            String secretKeyAlgorithm)
            throws GeneralSecurityException {

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", PQC_PROVIDER);
        keyGen.init(new KEMExtractSpec(privateKey, encapsulation, secretKeyAlgorithm));
        return (SecretKeyWithEncapsulation) keyGen.generateKey();
    }

    // ================================================================== //
    //  Key encoding / decoding                                             //
    // ================================================================== //

    public static PublicKey decodeDilithiumPublicKey(byte[] encoded)
            throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("Dilithium", PQC_PROVIDER);
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static PrivateKey decodeDilithiumPrivateKey(byte[] encoded)
            throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("Dilithium", PQC_PROVIDER);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    /**
     * Decode a Kyber public key from its raw (non-X.509-wrapped) byte form,
     * as sent over the wire by UD.
     */
    public static PublicKey decodeKyberPublicKeyRaw(byte[] rawBytes)
            throws GeneralSecurityException {
        try {
            org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters params =
                    PQCConfig.getKyberParameters();
            org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters pubParams =
                    new org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters(
                            params, rawBytes);
            return new org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey(pubParams);
        } catch (Exception e) {
            throw new GeneralSecurityException("Raw Kyber public key decoding failed", e);
        }
    }

    /** Decode a Kyber public key from X.509/SPKI-encoded bytes. */
    public static PublicKey decodeKyberPublicKey(byte[] encoded)
            throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("Kyber", PQC_PROVIDER);
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static PrivateKey decodeKyberPrivateKey(byte[] encoded)
            throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("Kyber", PQC_PROVIDER);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    /**
     * Extract raw public key bytes from an X.509-encoded Kyber public key
     * (i.e., strip the SubjectPublicKeyInfo wrapper).
     */
    public static byte[] getRawPublicKeyBytes(byte[] x509EncodedPub) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(x509EncodedPub);
        return spki.getPublicKeyData().getBytes();
    }

    // ================================================================== //
    //  Hash — SHAKE256-512                                                 //
    // ================================================================== //

    /**
     * Compute transAH0 = SHAKE256-512(transBytes).
     * Output is always 64 bytes.
     */
    public static byte[] generateTransAH0(byte[] transBytes) throws Exception {
        // BouncyCastle: "SHAKE256-512" = 512-bit output SHAKE256
        MessageDigest md = MessageDigest.getInstance("SHAKE256-512", BC_PROVIDER);
        return md.digest(transBytes);
    }

    // ================================================================== //
    //  KDF — HKDF-Extract + HKDF-Expand                                   //
    // ================================================================== //

    /**
     * HKDF-Extract: PRK = HMAC-SHA256(key=Se, msg=transAH0).
     * On the Reader side, Se (the Kyber shared secret) is held in memory.
     * Note: Key/msg order here mirrors the UD side (Android Keystore
     * constraint), which uses key=Se, msg=transAH0.
     *
     * @param se       Kyber shared secret (32 bytes)
     * @param transAH0 SHAKE256-512 hash of the transaction data (64 bytes)
     * @return         PRK (32 bytes)
     */
    public static byte[] deriveHS(byte[] se, byte[] transAH0) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(se, "HmacSHA256"));
        return hmac.doFinal(transAH0);
    }

    /**
     * HKDF-Expand: SKDevice = HKDF-Expand(PRK=HS, info="enc"‖transAH0, L=32).
     *
     * @param hs       PRK from deriveHS()
     * @param transAH0 same hash used in deriveHS
     * @return         32-byte session key
     */
    public static byte[] expandSKDevice(byte[] hs, byte[] transAH0) {
        byte[] label = "enc".getBytes(StandardCharsets.US_ASCII);
        byte[] info  = new byte[label.length + transAH0.length];
        System.arraycopy(label,   0, info, 0,            label.length);
        System.arraycopy(transAH0, 0, info, label.length, transAH0.length);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(hs, null, info));

        byte[] skDevice = new byte[32];
        hkdf.generateBytes(skDevice, 0, 32);
        return skDevice;
    }

    // ================================================================== //
    //  AEAD — AES-256-GCM                                                 //
    // ================================================================== //

    /**
     * Encrypt with AES-256-GCM.
     * IV = big-endian 8B(1L) ‖ 4B(counter).
     * Returns ciphertext ‖ tag (tag is last 16 bytes).
     */
    public static byte[] AEADencrypt(byte[] key, byte[] plaintext, byte[] aad, int counter)
            throws Exception {
        byte[] iv = makeIV(counter);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null) cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypt with AES-256-GCM.
     * ciphertextWithTag must be ciphertext ‖ tag (tag = last 16 bytes).
     */
    public static byte[] AEADdecrypt(byte[] key, byte[] ciphertextWithTag, byte[] aad, int counter)
            throws Exception {
        byte[] iv = makeIV(counter);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        if (aad != null) cipher.updateAAD(aad);
        return cipher.doFinal(ciphertextWithTag);
    }

    /** Split ciphertext+tag into {ciphertext, tag} (tag = last 16 bytes). */
    public static byte[][] splitCiphertextAndTag(byte[] ciphertextWithTag) {
        int dataLen = ciphertextWithTag.length - 16;
        byte[] ct  = Arrays.copyOfRange(ciphertextWithTag, 0, dataLen);
        byte[] tag = Arrays.copyOfRange(ciphertextWithTag, dataLen, ciphertextWithTag.length);
        return new byte[][]{ct, tag};
    }

    private static byte[] makeIV(int counter) {
        return ByteBuffer.allocate(12)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(1L)
                .putInt(counter)
                .array();
    }

    // ================================================================== //
    //  Misc                                                                //
    // ================================================================== //

    /** Generate random noise of given size (using PRNG seeded by SecureRandom). */
    public static byte[] generateNoise(int size) throws Exception {
        SecureRandom sr   = new SecureRandom();
        byte[]       seed = new byte[size];
        sr.nextBytes(seed);
        PRNG prng = new PRNG(seed);
        return prng.nextBytes(size);
    }
}
