package org.example;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/**
 * Standalone self-test for all PQ utility modules.
 *
 * Run:
 *   javac -encoding UTF-8 -cp bcprov-jdk18on-1.78.1.jar;<src>  PQSelfTest.java
 *   java  -cp bcprov-jdk18on-1.78.1.jar;<classes>  org.example.PQSelfTest
 */
public class PQSelfTest {

    static int passed = 0;
    static int failed = 0;

    public static void main(String[] args) throws Exception {
        testPQCConfigSizes();
        testDilithiumRoundTrip();
        testKyberRoundTrip();
        testTransAH0();
        testHKDF();
        testAEAD();

        System.out.println("\n========== SELF-TEST SUMMARY ==========");
        System.out.printf("  PASSED: %d%n", passed);
        System.out.printf("  FAILED: %d%n", failed);
        if (failed > 0) System.exit(1);
    }

    // ------------------------------------------------------------------ //
    // PQCConfig size constants vs actual keygen                           //
    // ------------------------------------------------------------------ //
    static void testPQCConfigSizes() throws Exception {
        section("PQCConfig size constants");

        for (int dil : new int[]{2, 3, 5}) {
            PQCConfig.DILITHIUM_LEVEL = dil;
            KeyPair kp = PQCUtil.generateDilithiumKeyPair();
            byte[] sig  = PQCUtil.dilithiumSign("test".getBytes(), kp.getPrivate());

            // Public key size (raw = SPKI - ASN1 wrapper; SPKI is typically 32 bytes larger)
            // BC SPKI size: level2=1344, level3=1984, level5=2624 (raw+32 header bytes)
            int rawPubLen = PQCConfig.dilithiumPublicKeySize();
            int rawSigLen = sig.length;
            int expSig    = PQCConfig.dilithiumSignatureSize();
            boolean sigOk = rawSigLen == expSig;
            check("Dilithium" + dil + " sig size " + rawSigLen + " == config " + expSig, sigOk);
        }

        for (int kyb : new int[]{512, 768, 1024}) {
            PQCConfig.KYBER_LEVEL = kyb;
            KeyPair kp = PQCUtil.generateKyberKeyPair();
            SecretKeyWithEncapsulation enc = PQCUtil.kyberEncapsulateRaw(kp.getPublic(), "AES");
            int ctLen  = enc.getEncapsulation().length;
            int expCt  = PQCConfig.kyberCiphertextSize();
            check("Kyber" + kyb + " ciphertext size " + ctLen + " == config " + expCt, ctLen == expCt);

            int rawPubLen = PQCUtil.getRawPublicKeyBytes(kp.getPublic().getEncoded()).length;
            int expPub    = PQCConfig.kyberPublicKeySize();
            check("Kyber" + kyb + " pubkey size " + rawPubLen + " == config " + expPub, rawPubLen == expPub);
        }

        // Restore defaults
        PQCConfig.DILITHIUM_LEVEL = 3;
        PQCConfig.KYBER_LEVEL = 768;
    }

    // ------------------------------------------------------------------ //
    // Dilithium sign/verify round-trip for all 3 levels                  //
    // ------------------------------------------------------------------ //
    static void testDilithiumRoundTrip() throws Exception {
        section("Dilithium sign/verify round-trip");

        byte[] msg = "Hello PQ-Aliro Dilithium".getBytes(StandardCharsets.UTF_8);

        for (int level : new int[]{2, 3, 5}) {
            PQCConfig.DILITHIUM_LEVEL = level;
            KeyPair kp = PQCUtil.generateDilithiumKeyPair();
            byte[] sig = PQCUtil.dilithiumSign(msg, kp.getPrivate());

            boolean ok = PQCUtil.dilithiumVerify(msg, sig, kp.getPublic());
            check("Dilithium" + level + " sign+verify", ok);

            // Tampered message must fail
            byte[] tampered = Arrays.copyOf(msg, msg.length);
            tampered[0] ^= 0xFF;
            boolean rejected = !PQCUtil.dilithiumVerify(tampered, sig, kp.getPublic());
            check("Dilithium" + level + " reject tampered msg", rejected);

            // Decode public key from encoded form
            PublicKey recovered = PQCUtil.decodeDilithiumPublicKey(kp.getPublic().getEncoded());
            boolean okRecov = PQCUtil.dilithiumVerify(msg, sig, recovered);
            check("Dilithium" + level + " verify with decoded pubkey", okRecov);
        }
        PQCConfig.DILITHIUM_LEVEL = 3;
    }

    // ------------------------------------------------------------------ //
    // Kyber encap/decap round-trip for all 3 levels                      //
    // ------------------------------------------------------------------ //
    static void testKyberRoundTrip() throws Exception {
        section("Kyber encap/decap round-trip");

        for (int level : new int[]{512, 768, 1024}) {
            PQCConfig.KYBER_LEVEL = level;
            KeyPair kp = PQCUtil.generateKyberKeyPair();

            // Encapsulate
            SecretKeyWithEncapsulation ske = PQCUtil.kyberEncapsulateRaw(kp.getPublic(), "AES");
            byte[] encap  = ske.getEncapsulation();
            byte[] ssEnc  = ske.getEncoded();    // shared secret at encapsulator

            // Decapsulate from raw public key (the wire path UD sends raw, Reader decaps)
            byte[] rawPub = PQCUtil.getRawPublicKeyBytes(kp.getPublic().getEncoded());
            PublicKey recoveredPub = PQCUtil.decodeKyberPublicKeyRaw(rawPub);

            // Re-encapsulate from recovered pub (simulates Reader encapping to UD's raw key)
            SecretKeyWithEncapsulation ske2 = PQCUtil.kyberEncapsulateRaw(recoveredPub, "AES");
            byte[] encap2 = ske2.getEncapsulation();
            byte[] ssEnc2 = ske2.getEncoded();

            // Decapsulate both with private key
            javax.crypto.SecretKey ssDec  = PQCUtil.kyberDecapsulateRaw(kp.getPrivate(), encap,  "AES");
            javax.crypto.SecretKey ssDec2 = PQCUtil.kyberDecapsulateRaw(kp.getPrivate(), encap2, "AES");

            check("Kyber" + level + " encap/decap ss match",
                    Arrays.equals(ssEnc, ssDec.getEncoded()));
            check("Kyber" + level + " raw-decoded pub encap/decap match",
                    Arrays.equals(ssEnc2, ssDec2.getEncoded()));
            check("Kyber" + level + " ciphertext length correct",
                    encap.length == PQCConfig.kyberCiphertextSize());
        }
        PQCConfig.KYBER_LEVEL = 768;
    }

    // ------------------------------------------------------------------ //
    // SHAKE256-512 (transAH0)                                            //
    // ------------------------------------------------------------------ //
    static void testTransAH0() throws Exception {
        section("SHAKE256-512 transAH0");

        byte[] empty = new byte[0];
        byte[] h1 = PQCUtil.generateTransAH0(empty);
        check("transAH0 output is 64 bytes", h1.length == 64);

        // Deterministic: same input => same hash
        byte[] h2 = PQCUtil.generateTransAH0(empty);
        check("transAH0 deterministic", Arrays.equals(h1, h2));

        // Different input => different hash
        byte[] h3 = PQCUtil.generateTransAH0("test".getBytes(StandardCharsets.UTF_8));
        check("transAH0 different for different inputs", !Arrays.equals(h1, h3));

        // Length of output stays 64 for long inputs
        byte[] long_in = new byte[2048];
        new SecureRandom().nextBytes(long_in);
        check("transAH0 output 64 bytes for long input",
                PQCUtil.generateTransAH0(long_in).length == 64);
    }

    // ------------------------------------------------------------------ //
    // HKDF-Extract + HKDF-Expand                                         //
    // ------------------------------------------------------------------ //
    static void testHKDF() throws Exception {
        section("HKDF-Extract/Expand (deriveHS + expandSKDevice)");

        SecureRandom rng = new SecureRandom();

        byte[] se       = new byte[32]; rng.nextBytes(se);
        byte[] transMsg = "kyberPubRaw||transId||readerId||encap||noise"
                .getBytes(StandardCharsets.UTF_8);
        byte[] transAH0 = PQCUtil.generateTransAH0(transMsg);

        byte[] hs = PQCUtil.deriveHS(se, transAH0);
        check("deriveHS output is 32 bytes", hs.length == 32);

        byte[] skDevice = PQCUtil.expandSKDevice(hs, transAH0);
        check("expandSKDevice output is 32 bytes", skDevice.length == 32);

        // Same inputs must produce identical outputs
        byte[] hs2        = PQCUtil.deriveHS(se, transAH0);
        byte[] skDevice2  = PQCUtil.expandSKDevice(hs2, transAH0);
        check("HKDF deterministic", Arrays.equals(skDevice, skDevice2));

        // Different Se => different HS => different SKDevice
        byte[] se2 = new byte[32]; rng.nextBytes(se2);
        byte[] hs3 = PQCUtil.deriveHS(se2, transAH0);
        check("Different Se => different HS", !Arrays.equals(hs, hs3));
    }

    // ------------------------------------------------------------------ //
    // AES-256-GCM AEAD                                                   //
    // ------------------------------------------------------------------ //
    static void testAEAD() throws Exception {
        section("AES-256-GCM AEAD encrypt/decrypt");

        SecureRandom rng = new SecureRandom();
        byte[] key       = new byte[32]; rng.nextBytes(key);
        byte[] plaintext = "Auth1 payload test".getBytes(StandardCharsets.UTF_8);
        byte[] aad       = new byte[0];

        // Counter = 1 (first AUTH1 message)
        byte[] ct  = PQCUtil.AEADencrypt(key, plaintext, aad, 1);
        byte[] dec = PQCUtil.AEADdecrypt(key, ct, aad, 1);
        check("AEAD round-trip counter=1", Arrays.equals(plaintext, dec));

        // Counter = 2 (second message)
        byte[] ct2  = PQCUtil.AEADencrypt(key, plaintext, aad, 2);
        byte[] dec2 = PQCUtil.AEADdecrypt(key, ct2, aad, 2);
        check("AEAD round-trip counter=2", Arrays.equals(plaintext, dec2));

        // Different counter => different ciphertext
        check("AEAD counter=1 != counter=2 ct", !Arrays.equals(ct, ct2));

        // Wrong counter => decryption must throw
        boolean rejected = false;
        try {
            PQCUtil.AEADdecrypt(key, ct, aad, 2);
        } catch (Exception e) {
            rejected = true;
        }
        check("AEAD rejects wrong counter", rejected);

        // Wrong key => must throw
        byte[] wrongKey = new byte[32]; rng.nextBytes(wrongKey);
        boolean rejKey = false;
        try {
            PQCUtil.AEADdecrypt(wrongKey, ct, aad, 1);
        } catch (Exception e) {
            rejKey = true;
        }
        check("AEAD rejects wrong key", rejKey);

        // splitCiphertextAndTag
        byte[][] parts = PQCUtil.splitCiphertextAndTag(ct);
        check("splitCiphertextAndTag ct length", parts[0].length == ct.length - 16);
        check("splitCiphertextAndTag tag length", parts[1].length == 16);
    }

    // ------------------------------------------------------------------ //
    // helpers                                                             //
    // ------------------------------------------------------------------ //
    static void section(String name) {
        System.out.println("\n--- " + name + " ---");
    }

    static void check(String desc, boolean cond) {
        if (cond) {
            System.out.println("  [PASS] " + desc);
            passed++;
        } else {
            System.out.println("  [FAIL] " + desc);
            failed++;
        }
    }
}
