package org.example;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;

/**
 * Global configuration for PQ-Aliro.
 * Toggle MODE to switch between classic ECC and post-quantum algorithms.
 * Change KYBER_LEVEL / DILITHIUM_LEVEL to select parameter set (default: Level 3).
 */
public final class PQCConfig {

    private PQCConfig() {}

    // ------------------------------------------------------------------ //
    //  Primary toggle                                                       //
    // ------------------------------------------------------------------ //

    public enum Mode { CLASSIC, PQ }

    /** Change this to Mode.CLASSIC to fall back to ECC/ECDH. */
    public static Mode MODE = Mode.PQ;

    // ------------------------------------------------------------------ //
    //  Algorithm levels                                                     //
    // ------------------------------------------------------------------ //

    /** Kyber parameter level: 512 | 768 | 1024  (default 768 = Level 3) */
    public static int KYBER_LEVEL = 768;

    /** Dilithium parameter level: 2 | 3 | 5  (default 3) */
    public static int DILITHIUM_LEVEL = 3;

    // ------------------------------------------------------------------ //
    //  BouncyCastle parameter-set helpers                                  //
    // ------------------------------------------------------------------ //

    public static KyberParameters getKyberParameters() {
        switch (KYBER_LEVEL) {
            case 512:  return KyberParameters.kyber512;
            case 768:  return KyberParameters.kyber768;
            case 1024: return KyberParameters.kyber1024;
            default:   throw new IllegalStateException("Unsupported KYBER_LEVEL: " + KYBER_LEVEL);
        }
    }

    public static DilithiumParameters getDilithiumParameters() {
        switch (DILITHIUM_LEVEL) {
            case 2: return DilithiumParameters.dilithium2;
            case 3: return DilithiumParameters.dilithium3;
            case 5: return DilithiumParameters.dilithium5;
            default: throw new IllegalStateException("Unsupported DILITHIUM_LEVEL: " + DILITHIUM_LEVEL);
        }
    }

    // ------------------------------------------------------------------ //
    //  Size constants (level-aware)                                        //
    // ------------------------------------------------------------------ //

    /** Kyber public key size in bytes. */
    public static int kyberPublicKeySize() {
        switch (KYBER_LEVEL) {
            case 512:  return 800;
            case 768:  return 1184;
            case 1024: return 1568;
            default:   throw new IllegalStateException("Unsupported KYBER_LEVEL: " + KYBER_LEVEL);
        }
    }

    /** Kyber ciphertext (encapsulation) size in bytes. */
    public static int kyberCiphertextSize() {
        switch (KYBER_LEVEL) {
            case 512:  return 768;
            case 768:  return 1088;
            case 1024: return 1568;
            default:   throw new IllegalStateException("Unsupported KYBER_LEVEL: " + KYBER_LEVEL);
        }
    }

    /** Kyber shared secret size in bytes (always 32). */
    public static int kyberSharedSecretSize() {
        return 32;
    }

    /** Dilithium public key size in bytes. */
    public static int dilithiumPublicKeySize() {
        switch (DILITHIUM_LEVEL) {
            case 2: return 1312;
            case 3: return 1952;
            case 5: return 2592;
            default: throw new IllegalStateException("Unsupported DILITHIUM_LEVEL: " + DILITHIUM_LEVEL);
        }
    }

    /** Dilithium signature size in bytes (matches BC 1.78 ML-DSA sizes). */
    public static int dilithiumSignatureSize() {
        switch (DILITHIUM_LEVEL) {
            case 2: return 2420;
            case 3: return 3309;
            case 5: return 4627;
            default: throw new IllegalStateException("Unsupported DILITHIUM_LEVEL: " + DILITHIUM_LEVEL);
        }
    }

    // ------------------------------------------------------------------ //
    //  Convenience                                                          //
    // ------------------------------------------------------------------ //

    public static boolean isPQ() {
        return MODE == Mode.PQ;
    }

    @Override
    public String toString() {
        return "PQCConfig{mode=" + MODE
                + ", kyberLevel=" + KYBER_LEVEL
                + ", dilithiumLevel=" + DILITHIUM_LEVEL + "}";
    }
}
