package org.example;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/**
 * End-to-end PQ-Aliro protocol simulation.
 *
 * Simulates the AUTH0 → LOADCERT → AUTH1 flow between Reader and UD entirely in
 * memory (no NFC, no Android KeyStore), exercising the exact TLV layout and
 * cryptographic steps that Reader.java (PC) and UserDevice.java (UD) perform.
 *
 * Each step prints intermediate values (hex prefixes) and asserts critical
 * invariants:
 *   - Reader and UD derive the same transAH0 (SHAKE256-512 of transcript)
 *   - Reader and UD derive the same SK_device (32 bytes)
 *   - Reader's Dilithium signature on toauthdata verifies on UD side
 *   - UD's Dilithium signature on reauthdata verifies on Reader side
 *   - AEAD encrypt/decrypt round-trip with counter=1 succeeds
 *
 * Run for all 3 levels of each algorithm: Dilithium {2,3,5} × Kyber {512,768,1024}.
 */
public class PQAliroProtocolTest {

    static int passed = 0;
    static int failed = 0;

    public static void main(String[] args) throws Exception {
        // Run only the configured default level first (verbose),
        // then sweep across all (D, K) combinations (terse).
        runOne(PQCConfig.DILITHIUM_LEVEL, PQCConfig.KYBER_LEVEL, /*verbose=*/true);

        System.out.println("\n========== SWEEP across all (Dilithium, Kyber) levels ==========");
        for (int d : new int[]{2, 3, 5}) {
            for (int k : new int[]{512, 768, 1024}) {
                if (d == PQCConfig.DILITHIUM_LEVEL && k == PQCConfig.KYBER_LEVEL) continue;
                runOne(d, k, /*verbose=*/false);
            }
        }

        // Restore defaults
        PQCConfig.DILITHIUM_LEVEL = 3;
        PQCConfig.KYBER_LEVEL = 768;

        System.out.println("\n=========================================");
        System.out.printf("  PASSED: %d%n", passed);
        System.out.printf("  FAILED: %d%n", failed);
        System.out.println("=========================================");
        if (failed > 0) System.exit(1);
    }

    // ====================================================================== //
    //  One full protocol run                                                  //
    // ====================================================================== //
    static void runOne(int dLevel, int kLevel, boolean verbose) throws Exception {
        PQCConfig.DILITHIUM_LEVEL = dLevel;
        PQCConfig.KYBER_LEVEL = kLevel;

        String banner = String.format("Dilithium%d × Kyber%d", dLevel, kLevel);
        if (verbose) {
            System.out.println("\n##############################################");
            System.out.println("####  PQ-Aliro protocol simulation  " + banner);
            System.out.println("##############################################");
        } else {
            System.out.println("\n--- run: " + banner + " ---");
        }

        // ------- 0. SETUP: CI, Reader long-term, UD long-term ------- //
        KeyPair readerLT = PQCUtil.generateDilithiumKeyPair();
        KeyPair udLT     = PQCUtil.generateDilithiumKeyPair();
        if (verbose) {
            System.out.println("[SETUP] Reader Dilithium long-term pubkey: "
                    + hexPrefix(readerLT.getPublic().getEncoded()));
            System.out.println("[SETUP] UD Dilithium long-term pubkey:     "
                    + hexPrefix(udLT.getPublic().getEncoded()));
        }

        // Simulated identifiers
        byte[] readerGroupId = padTo("wbl", 16);
        byte[] readerSubId   = padTo("back_door", 16);
        byte[] readerId32    = concat(readerGroupId, readerSubId);

        // ------- 1. AUTH0 (Reader → UD) ------- //
        section(verbose, "AUTH0");

        // 1a. Reader generates ephemeral Kyber keypair
        KeyPair readerKyber  = PQCUtil.generateKyberKeyPair();
        byte[]  kyberPubX509 = readerKyber.getPublic().getEncoded();
        byte[]  kyberPubRaw  = PQCUtil.getRawPublicKeyBytes(kyberPubX509);
        check("Kyber" + kLevel + " pubkey raw size == " + PQCConfig.kyberPublicKeySize(),
                kyberPubRaw.length == PQCConfig.kyberPublicKeySize());
        if (verbose) System.out.println("[AUTH0/Reader] Kyber pubkey raw (" + kyberPubRaw.length
                + " B): " + hexPrefix(kyberPubRaw));

        // 1b. Reader generates trans_id
        byte[] transId = new byte[16];
        new SecureRandom().nextBytes(transId);
        byte cmdParams = 0x00;
        byte authPolicy = 0x01;
        byte[] protoVer = new byte[]{0x01, 0x01};

        // 1c. Reader builds AUTH0 TLV body (mirrors CreateAUTH0_PQ in Reader.java)
        byte[] auth0CmdBody = buildAuth0Command(
                cmdParams, authPolicy, protoVer, kyberPubRaw, transId, readerId32);
        if (verbose) System.out.println("[AUTH0/Reader] body length: " + auth0CmdBody.length + " B");

        // 1d. UD parses, generates response (mirrors AUTH0response in UserDevice.java)
        UdAuth0Result udResp = udSimulateAuth0(auth0CmdBody);
        byte[] udEncap = udResp.encap;
        byte[] udNoise = udResp.noise;
        byte[] udTransAH0 = udResp.transAH0;
        byte[] udSe = udResp.se;
        byte[] udSk = udResp.skDevice;
        check("UD encap size == kyberCiphertextSize()",
                udEncap.length == PQCConfig.kyberCiphertextSize());
        check("UD noise size == 32",
                udNoise.length == 32);
        if (verbose) {
            System.out.println("[AUTH0/UD] encap (" + udEncap.length + " B): " + hexPrefix(udEncap));
            System.out.println("[AUTH0/UD] noise: " + hexPrefix(udNoise));
            System.out.println("[AUTH0/UD] Se:    " + hexPrefix(udSe));
        }

        // 1e. Reader processes UD's response (mirrors getAUTH0resp_PQ in Reader.java)
        byte[] auth0RespBody = buildAuth0ResponseBody(udEncap, udNoise);
        ReaderAuth0Result readerResp = readerSimulateAuth0Resp(
                auth0RespBody, readerKyber, kyberPubRaw, transId, readerId32);
        if (verbose) {
            System.out.println("[AUTH0/Reader] Se:        " + hexPrefix(readerResp.se));
            System.out.println("[AUTH0/Reader] transAH0:  " + hexPrefix(readerResp.transAH0));
            System.out.println("[AUTH0/Reader] SK_device: " + hexPrefix(readerResp.skDevice));
        }

        // 1f. Cross-verify both sides agree
        check("Se matches between Reader and UD", Arrays.equals(readerResp.se, udSe));
        check("transAH0 matches between Reader and UD",
                Arrays.equals(readerResp.transAH0, udTransAH0));
        check("SK_device matches between Reader and UD",
                Arrays.equals(readerResp.skDevice, udSk));
        check("transAH0 length == 64 (SHAKE256-512)", readerResp.transAH0.length == 64);
        check("SK_device length == 32", readerResp.skDevice.length == 32);

        // ------- 2. LOADCERT (Reader → UD) ------- //
        // In a real run this passes a CBOR profile carrying the Reader's X.509 cert.
        // For the protocol simulation we shortcut: UD already has Reader's raw Dilithium
        // public key delivered out-of-band.  (Cert verification path is covered by
        // PQCertTool's separate test run.)
        section(verbose, "LOADCERT (simulated: UD installs Reader Dilithium pubkey)");
        PublicKey udSideReaderPK = readerLT.getPublic();
        check("UD got Reader's Dilithium pubkey (non-null)", udSideReaderPK != null);

        // ------- 3. AUTH1 (Reader → UD) ------- //
        section(verbose, "AUTH1");

        // 3a. Reader builds toauthdata and signs with its Dilithium SK
        byte[] toauthdata = buildToAuthData(readerId32, readerResp.transAH0, transId,
                new byte[]{0x41, 0x5D, (byte)0x95, 0x69});
        byte[] readerSig = PQCUtil.dilithiumSign(toauthdata, readerLT.getPrivate());
        if (verbose) System.out.println("[AUTH1/Reader] sig length: " + readerSig.length
                + " (config: " + PQCConfig.dilithiumSignatureSize() + ")");
        check("Reader Dilithium sig size matches config",
                readerSig.length == PQCConfig.dilithiumSignatureSize());

        // 3b. UD reconstructs toauthdata and verifies Reader sig
        byte[] udToauthdata = buildToAuthData(readerId32, udTransAH0, transId,
                new byte[]{0x41, 0x5D, (byte)0x95, 0x69});
        check("UD's toauthdata matches Reader's", Arrays.equals(toauthdata, udToauthdata));
        boolean readerSigOk = PQCUtil.dilithiumVerify(udToauthdata, readerSig, udSideReaderPK);
        check("UD verifies Reader signature", readerSigOk);

        // 3c. UD builds reauthdata and signs with its UD Dilithium SK
        byte[] reauthdata = buildToAuthData(readerId32, udTransAH0, transId,
                new byte[]{0x4E, (byte)0x88, 0x7B, 0x4C});
        byte[] udSig = PQCUtil.dilithiumSign(reauthdata, udLT.getPrivate());
        check("UD Dilithium sig size matches config",
                udSig.length == PQCConfig.dilithiumSignatureSize());

        // 3d. UD assembles plaintext response: Tag 0x5A|UD pubkey raw || Tag 0x9E|sig || Tag 0x5E|signal_bitmap
        byte[] udRawPubkey = ((BCDilithiumPublicKey) extractBcPub(udLT.getPublic())).getEncoded();
        // The "raw" key used in UserDevice.java line 207 is dilithiumPk.getEncoded() of a
        // DilithiumPublicKeyParameters — i.e. just the raw bytes. Mirror that exactly:
        byte[] udRawPubkeyRaw = rawDilithiumPubFromEncoded(udLT.getPublic().getEncoded());
        check("UD raw Dilithium pubkey size == config",
                udRawPubkeyRaw.length == PQCConfig.dilithiumPublicKeySize());

        byte[] signalBitmap = computeUdSignalBitmap();
        byte[] auth1RespPlaintext = buildAuth1ResponsePlaintext(udRawPubkeyRaw, udSig, signalBitmap);

        // 3e. UD encrypts with AEAD using SK_device, counter=1
        int udCounter = 1;
        byte[] auth1Ciphertext = PQCUtil.AEADencrypt(udSk, auth1RespPlaintext, new byte[0], udCounter);

        // 3f. Reader decrypts with counter=1
        byte[] decrypted = PQCUtil.AEADdecrypt(readerResp.skDevice, auth1Ciphertext, new byte[0], 1);
        check("AEAD round-trip equal", Arrays.equals(decrypted, auth1RespPlaintext));

        // 3g. Reader parses plaintext and verifies UD signature
        ParsedAuth1Resp parsed = parseAuth1ResponsePlaintext(decrypted);
        check("Parsed UD pubkey == sent", Arrays.equals(parsed.udPubkeyRaw, udRawPubkeyRaw));
        check("Parsed UD sig == sent",    Arrays.equals(parsed.udSig, udSig));
        check("Parsed signal_bitmap == sent", Arrays.equals(parsed.signalBitmap, signalBitmap));

        // Reconstruct UD pubkey + verify UD sig
        DilithiumPublicKeyParameters udPubParams = new DilithiumPublicKeyParameters(
                PQCConfig.getDilithiumParameters(), parsed.udPubkeyRaw);
        PublicKey udPubReconstructed = new BCDilithiumPublicKey(udPubParams);
        boolean udSigOk = PQCUtil.dilithiumVerify(reauthdata, parsed.udSig, udPubReconstructed);
        check("Reader verifies UD signature", udSigOk);

        // 3h. Confirm the signal_bitmap bit-pack bug: bits 0-7 are dropped on UD side
        if (verbose) {
            System.out.println("[AUTH1/Reader] signal_bitmap bytes received: "
                    + bytesToHex(parsed.signalBitmap));
            int recombined = ((parsed.signalBitmap[0] & 0xFF) << 8)
                           |  (parsed.signalBitmap[1] & 0xFF);
            System.out.println("[AUTH1/Reader] recombined bitmap int: 0x"
                    + Integer.toHexString(recombined));
            System.out.println("           (UD set AD_RETRIEVED=bit0 + SUPPORT_EXCHANGE=bit6 "
                    + "→ expected 0x0041; observed 0x" + Integer.toHexString(recombined) + ")");
        }
        // The Reader expects bit 0 (AD_RETIEVED) set; after the bit-pack fix this survives.
        check("AD_RETIEVED bit (0) survives the round-trip",
                ((((parsed.signalBitmap[0] & 0xFF) << 8) | (parsed.signalBitmap[1] & 0xFF)) & 0x01) == 1);
    }

    // ====================================================================== //
    //  UD-side simulation of AUTH0response                                    //
    // ====================================================================== //
    static class UdAuth0Result {
        byte[] encap, noise, transAH0, se, skDevice;
    }

    /**
     * Mirrors UserDevice.AUTH0response — TLV parse the command, Kyber-encapsulate
     * against the parsed reader_ePubk, build response transcript, derive transAH0/HS/SK_device.
     */
    static UdAuth0Result udSimulateAuth0(byte[] cmd) throws Exception {
        ByteArrayOutputStream comTranscript = new ByteArrayOutputStream();
        ByteArrayOutputStream resTranscript = new ByteArrayOutputStream();

        int inc = 0;
        // 0x41|0x01|cmd_params
        expect(cmd[inc++], 0x41); expect(cmd[inc++], 0x01); inc++;
        // 0x42|0x01|auth_policy
        expect(cmd[inc++], 0x42); expect(cmd[inc++], 0x01); inc++;
        // 0x5C|0x02|proto_ver
        expect(cmd[inc++], 0x5C); expect(cmd[inc++], 0x02); inc += 2;
        // 0x87|<long-form len>|kyberPubRaw
        expect(cmd[inc++], 0x87);
        int[] li = readBerLen(cmd, inc); int pkLen = li[0]; inc += li[1];
        byte[] kyberPubRaw = Arrays.copyOfRange(cmd, inc, inc + pkLen);
        inc += pkLen;
        comTranscript.write(kyberPubRaw);
        // 0x4C|0x10|trans_id
        expect(cmd[inc++], 0x4C); expect(cmd[inc++], 0x10);
        byte[] transId = Arrays.copyOfRange(cmd, inc, inc + 16);
        inc += 16; comTranscript.write(transId);
        // 0x4D|0x20|reader_id
        expect(cmd[inc++], 0x4D); expect(cmd[inc++], 0x20);
        byte[] readerId = Arrays.copyOfRange(cmd, inc, inc + 32);
        inc += 32; comTranscript.write(readerId);

        // Decode raw Kyber pubkey and encapsulate
        PublicKey readerKyberPub = PQCUtil.decodeKyberPublicKeyRaw(kyberPubRaw);
        SecretKeyWithEncapsulation ske = PQCUtil.kyberEncapsulateRaw(readerKyberPub, "AES");
        byte[] encap = ske.getEncapsulation();
        byte[] se    = ske.getEncoded();
        resTranscript.write(encap);

        // Generate 32-byte UD noise
        byte[] noise = new byte[32];
        new SecureRandom().nextBytes(noise);
        resTranscript.write(noise);

        // transAH0 = SHAKE256-512(com || res)
        byte[] comBytes = comTranscript.toByteArray();
        byte[] resBytes = resTranscript.toByteArray();
        byte[] all = new byte[comBytes.length + resBytes.length];
        System.arraycopy(comBytes, 0, all, 0, comBytes.length);
        System.arraycopy(resBytes, 0, all, comBytes.length, resBytes.length);
        byte[] transAH0 = PQCUtil.generateTransAH0(all);

        byte[] hs = PQCUtil.deriveHS(se, transAH0);
        byte[] sk = PQCUtil.expandSKDevice(hs, transAH0);

        UdAuth0Result r = new UdAuth0Result();
        r.encap = encap; r.noise = noise; r.transAH0 = transAH0; r.se = se; r.skDevice = sk;
        return r;
    }

    static class ReaderAuth0Result {
        byte[] se, transAH0, skDevice;
    }

    static ReaderAuth0Result readerSimulateAuth0Resp(
            byte[] respBody, KeyPair readerKyber,
            byte[] kyberPubRaw, byte[] transId, byte[] readerId32) throws Exception {

        ByteArrayOutputStream comTranscript = new ByteArrayOutputStream();
        comTranscript.write(kyberPubRaw);
        comTranscript.write(transId);
        comTranscript.write(readerId32);

        ByteArrayOutputStream resTranscript = new ByteArrayOutputStream();
        int inc = 0;
        expect(respBody[inc++], 0x86);
        int[] li = readBerLen(respBody, inc); int ctLen = li[0]; inc += li[1];
        byte[] encap = Arrays.copyOfRange(respBody, inc, inc + ctLen);
        inc += ctLen; resTranscript.write(encap);

        expect(respBody[inc++], 0x43);
        int nLen = respBody[inc++] & 0xFF;
        byte[] noise = Arrays.copyOfRange(respBody, inc, inc + nLen);
        inc += nLen; resTranscript.write(noise);

        SecretKey seKey = PQCUtil.kyberDecapsulateRaw(readerKyber.getPrivate(), encap, "AES");
        byte[] se = seKey.getEncoded();

        byte[] comBytes = comTranscript.toByteArray();
        byte[] resBytes = resTranscript.toByteArray();
        byte[] all = new byte[comBytes.length + resBytes.length];
        System.arraycopy(comBytes, 0, all, 0, comBytes.length);
        System.arraycopy(resBytes, 0, all, comBytes.length, resBytes.length);
        byte[] transAH0 = PQCUtil.generateTransAH0(all);
        byte[] hs = PQCUtil.deriveHS(se, transAH0);
        byte[] sk = PQCUtil.expandSKDevice(hs, transAH0);

        ReaderAuth0Result r = new ReaderAuth0Result();
        r.se = se; r.transAH0 = transAH0; r.skDevice = sk;
        return r;
    }

    // ====================================================================== //
    //  TLV helpers (mirror Reader.java + UserDevice.java)                     //
    // ====================================================================== //

    static byte[] buildAuth0Command(byte cmdParams, byte authPolicy, byte[] protoVer,
                                    byte[] kyberPubRaw, byte[] transId, byte[] readerId32)
            throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x41); o.write(0x01); o.write(cmdParams);
        o.write(0x42); o.write(0x01); o.write(authPolicy);
        o.write(0x5C); o.write(0x02); o.write(protoVer, 0, 2);
        o.write(0x87); writeBerLen(o, kyberPubRaw.length); o.write(kyberPubRaw, 0, kyberPubRaw.length);
        o.write(0x4C); o.write(0x10); o.write(transId, 0, 16);
        o.write(0x4D); o.write(0x20); o.write(readerId32, 0, 32);
        return o.toByteArray();
    }

    static byte[] buildAuth0ResponseBody(byte[] encap, byte[] noise) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x86); writeBerLen(o, encap.length); o.write(encap, 0, encap.length);
        o.write(0x43); o.write(noise.length); o.write(noise, 0, noise.length);
        return o.toByteArray();
    }

    /**
     * Mirrors Reader.java (CreateAUTH1_PQ / getAUTH1resp_PQ) and UserDevice.java
     * (lines 501-518 / 542-559). The transAH0 TLV uses length 0x40 (64B) to match
     * the SHAKE256-512 output — both sides write the full 64 bytes per the
     * standard BER-TLV length encoding.
     */
    static byte[] buildToAuthData(byte[] readerId32, byte[] transAH0, byte[] transId,
                                  byte[] usageTag4) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x4D); o.write(0x20); o.write(readerId32, 0, 32);
        o.write(0x4A); o.write(0x40); o.write(transAH0, 0, transAH0.length);   // length = 64
        o.write(0x4C); o.write(0x10); o.write(transId, 0, 16);
        o.write(0x93); o.write(0x04); o.write(usageTag4, 0, 4);
        return o.toByteArray();
    }

    static byte[] buildAuth1ResponsePlaintext(byte[] udPubRaw, byte[] udSig, byte[] signalBitmap)
            throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x5A); writeBerLen(o, udPubRaw.length); o.write(udPubRaw, 0, udPubRaw.length);
        o.write(0x9E); writeBerLen(o, udSig.length);    o.write(udSig, 0, udSig.length);
        o.write(0x5E); o.write(0x02); o.write(signalBitmap, 0, 2);
        return o.toByteArray();
    }

    static class ParsedAuth1Resp {
        byte[] udPubkeyRaw, udSig, signalBitmap;
    }
    static ParsedAuth1Resp parseAuth1ResponsePlaintext(byte[] pt) {
        int inc = 0;
        expect(pt[inc++], 0x5A);
        int[] li = readBerLen(pt, inc); int pkLen = li[0]; inc += li[1];
        byte[] pk = Arrays.copyOfRange(pt, inc, inc + pkLen); inc += pkLen;

        expect(pt[inc++], 0x9E);
        int[] li2 = readBerLen(pt, inc); int sigLen = li2[0]; inc += li2[1];
        byte[] sig = Arrays.copyOfRange(pt, inc, inc + sigLen); inc += sigLen;

        expect(pt[inc++], 0x5E); expect(pt[inc++], 0x02);
        byte[] bm = new byte[]{ pt[inc++], pt[inc++] };

        ParsedAuth1Resp r = new ParsedAuth1Resp();
        r.udPubkeyRaw = pk; r.udSig = sig; r.signalBitmap = bm;
        return r;
    }

    /**
     * Replicates UserDevice.java lines 633-652 — the fixed bit pack with
     * AD_RETIEVED=1 + SUPPORT_EXCHANGE=1 set in the low byte.
     */
    static byte[] computeUdSignalBitmap() {
        int sb = 0;
        sb |= (1 & 0x01) << 0;   // AD_RETIEVED
        sb |= (0 & 0x01) << 1;
        sb |= (0 & 0x01) << 2;
        sb |= (0 & 0x01) << 3;
        sb |= (0 & 0x01) << 4;
        sb |= (0 & 0x01) << 5;
        sb |= (1 & 0x01) << 6;   // SUPPORT_EXCHANGE
        sb |= (0 & 0x01) << 7;
        // bits 8..12 are zero in default UserDevice config
        byte[] out = new byte[2];
        out[0] = (byte) ((sb >> 8) & 0xFF);   // high byte (bits 8-15)
        out[1] = (byte) (sb & 0xFF);          // low byte  (bits 0-7)
        return out;
    }

    // ====================================================================== //
    //  Misc helpers                                                           //
    // ====================================================================== //

    static void writeBerLen(ByteArrayOutputStream o, int len) {
        if (len <= 127) o.write(len);
        else if (len <= 255) { o.write(0x81); o.write(len); }
        else if (len <= 65535) { o.write(0x82); o.write((len >> 8) & 0xFF); o.write(len & 0xFF); }
        else throw new IllegalArgumentException("BER length > 65535");
    }
    static int[] readBerLen(byte[] buf, int idx) {
        int first = buf[idx] & 0xFF;
        if (first <= 0x7F) return new int[]{first, 1};
        if (first == 0x81) return new int[]{buf[idx + 1] & 0xFF, 2};
        if (first == 0x82) return new int[]{((buf[idx + 1] & 0xFF) << 8) | (buf[idx + 2] & 0xFF), 3};
        throw new IllegalArgumentException("Bad BER len byte: " + first);
    }
    static void expect(byte got, int want) {
        if ((got & 0xFF) != (want & 0xFF))
            throw new IllegalStateException(String.format(
                    "TLV tag mismatch: got 0x%02X expected 0x%02X", got & 0xFF, want));
    }
    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
    static byte[] padTo(String s, int n) {
        byte[] in = s.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[n];
        System.arraycopy(in, 0, out, 0, Math.min(in.length, n));
        return out;
    }
    static String hexPrefix(byte[] b) {
        int n = Math.min(b.length, 16);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(String.format("%02X", b[i]));
        if (b.length > n) sb.append("...(").append(b.length).append("B)");
        return sb.toString();
    }
    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    /** Extract the raw Dilithium public key bytes from an X.509-encoded PublicKey. */
    static byte[] rawDilithiumPubFromEncoded(byte[] encoded) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(encoded);
        return spki.getPublicKeyData().getBytes();
    }

    static PublicKey extractBcPub(PublicKey k) { return k; }

    static void section(boolean verbose, String name) {
        if (verbose) System.out.println("\n----- " + name + " -----");
    }

    static void check(String desc, boolean cond) {
        if (cond) { passed++; System.out.println("  [PASS] " + desc); }
        else      { failed++; System.out.println("  [FAIL] " + desc); }
    }
}
