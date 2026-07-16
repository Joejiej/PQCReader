package org.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

/**
 * PQ Credential Issuer tool — standalone CLI for generating Dilithium and Kyber
 * key material plus a CI-signed certificate chain.
 *
 * <p>Default output directory:
 *   {@code src/main/resources/cert_pq/}
 *
 * <p>Usage:
 * <pre>
 *   mvn compile exec:java -Dexec.mainClass=org.example.PQCertTool
 *   # or directly:
 *   java -cp target/classes org.example.PQCertTool [outputDir]
 *
 *   # override Dilithium / Kyber levels:
 *   java -cp target/classes org.example.PQCertTool [outputDir] [dilLevel] [kybLevel]
 *      dilLevel ∈ {2,3,5}   (default: PQCConfig.DILITHIUM_LEVEL)
 *      kybLevel ∈ {512,768,1024}  (default: PQCConfig.KYBER_LEVEL)
 * </pre>
 *
 * Files emitted:
 *   CI_dilithium_priv.pem      CI_dilithium_cert.pem
 *   Reader_dilithium_priv.pem  Reader_dilithium_cert.pem
 *   Reader_kyber_priv.pem      Reader_kyber_pub.pem
 *   AccessCred_dilithium_priv.pem  AccessCred_dilithium_cert.pem
 */
public class PQCertTool {

    private static final String PQC_PROVIDER = "BCPQC";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(PQC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public static void main(String[] args) throws Exception {
        String outDir = (args.length >= 1) ? args[0]
                : "src/main/resources/cert_pq";

        if (args.length >= 2) PQCConfig.DILITHIUM_LEVEL = Integer.parseInt(args[1]);
        if (args.length >= 3) PQCConfig.KYBER_LEVEL    = Integer.parseInt(args[2]);

        System.out.println("=== PQ-Aliro Credential Issuer Tool ===");
        System.out.printf("  Mode=%s  Dilithium=%d  Kyber=%d%n",
                PQCConfig.MODE, PQCConfig.DILITHIUM_LEVEL, PQCConfig.KYBER_LEVEL);
        System.out.println("Output directory: " + new File(outDir).getAbsolutePath());

        Files.createDirectories(Paths.get(outDir));

        // 1) CI self-signed Dilithium identity
        System.out.println("\n[1/3] Generating CI Dilithium keypair + self-signed cert...");
        KeyPair ciKeys = PQCUtil.generateDilithiumKeyPair();
        X509Certificate ciCert = generateDilithiumSelfSignedCert(
                ciKeys, "CN=Aliro_CI, O=Aliro, C=CN");
        savePrivateKeyToPem(ciKeys.getPrivate(), outDir + "/CI_dilithium_priv.pem");
        saveCertToPem(ciCert, outDir + "/CI_dilithium_cert.pem");
        System.out.println("  -> CI_dilithium_priv.pem");
        System.out.println("  -> CI_dilithium_cert.pem");

        // 2) Reader Dilithium identity (signed by CI)
        System.out.println("\n[2/3] Generating Reader Dilithium keypair + CI-signed cert...");
        KeyPair readerDilKeys = PQCUtil.generateDilithiumKeyPair();
        X509Certificate readerCert = generateDilithiumCertSignedByCI(
                readerDilKeys.getPublic(), "CN=Aliro_Reader, O=Aliro, C=CN",
                ciKeys.getPrivate(), ciCert);
        savePrivateKeyToPem(readerDilKeys.getPrivate(), outDir + "/Reader_dilithium_priv.pem");
        saveCertToPem(readerCert, outDir + "/Reader_dilithium_cert.pem");
        System.out.println("  -> Reader_dilithium_priv.pem");
        System.out.println("  -> Reader_dilithium_cert.pem");

        // 2b) Reader Kyber keypair (long-term identity; ephemeral copies are generated per session)
        System.out.println("\n[2b/3] Generating Reader Kyber keypair (template/long-term)...");
        KeyPair readerKybKeys = PQCUtil.generateKyberKeyPair();
        saveRawKeyToPem(readerKybKeys.getPrivate(), outDir + "/Reader_kyber_priv.pem", false);
        saveRawKeyToPem(readerKybKeys.getPublic(),  outDir + "/Reader_kyber_pub.pem",  true);
        System.out.println("  -> Reader_kyber_priv.pem");
        System.out.println("  -> Reader_kyber_pub.pem");

        // 3) Access Credential (UD identity) Dilithium key + CI-signed cert
        System.out.println("\n[3/3] Generating Access Credential Dilithium keypair + CI-signed cert...");
        KeyPair acKeys = PQCUtil.generateDilithiumKeyPair();
        X509Certificate acCert = generateDilithiumCertSignedByCI(
                acKeys.getPublic(), "CN=Aliro_AccessCredential, O=Aliro, C=CN",
                ciKeys.getPrivate(), ciCert);
        savePrivateKeyToPem(acKeys.getPrivate(), outDir + "/AccessCred_dilithium_priv.pem");
        saveCertToPem(acCert, outDir + "/AccessCred_dilithium_cert.pem");
        System.out.println("  -> AccessCred_dilithium_priv.pem");
        System.out.println("  -> AccessCred_dilithium_cert.pem");

        // Sanity: verify each non-CI cert against CI's public key
        System.out.println("\n=== Verification ===");
        System.out.println("Reader cert signature valid:        " + verifyDilithiumCert(readerCert, ciCert.getPublicKey()));
        System.out.println("AccessCred cert signature valid:    " + verifyDilithiumCert(acCert,     ciCert.getPublicKey()));
        System.out.println("CI cert self-signature valid:       " + verifyDilithiumCert(ciCert,     ciCert.getPublicKey()));

        System.out.println("\nAll PQ credentials generated successfully.");
    }

    // ------------------------------------------------------------------ //
    //  Certificate builders                                                 //
    // ------------------------------------------------------------------ //

    private static X509Certificate generateDilithiumSelfSignedCert(
            KeyPair kp, String dn) throws Exception {

        X500Name name = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date from = new Date();
        Date to   = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, from, to, name, kp.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(dilithiumSigAlg())
                .setProvider(PQC_PROVIDER)
                .build(kp.getPrivate());

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private static X509Certificate generateDilithiumCertSignedByCI(
            PublicKey subjectPub, String subjectDN,
            PrivateKey caPriv, X509Certificate caCert) throws Exception {

        X500Name issuer  = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDN);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date from = new Date();
        Date to   = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, from, to, subject, subjectPub);

        ContentSigner signer = new JcaContentSignerBuilder(dilithiumSigAlg())
                .setProvider(PQC_PROVIDER)
                .build(caPriv);

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    /** Map Dilithium level to the JCA signature algorithm name BC expects. */
    private static String dilithiumSigAlg() {
        switch (PQCConfig.DILITHIUM_LEVEL) {
            case 2: return "Dilithium2";
            case 3: return "Dilithium3";
            case 5: return "Dilithium5";
            default:
                throw new IllegalStateException(
                        "Unsupported Dilithium level: " + PQCConfig.DILITHIUM_LEVEL);
        }
    }

    private static boolean verifyDilithiumCert(X509Certificate cert, PublicKey caPub) {
        try {
            cert.verify(caPub, PQC_PROVIDER);
            return true;
        } catch (Exception e) {
            System.err.println("  verify failed: " + e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------ //
    //  PEM helpers                                                          //
    // ------------------------------------------------------------------ //

    private static void saveCertToPem(X509Certificate cert, String filename) throws Exception {
        byte[] der = cert.getEncoded();
        writePem("CERTIFICATE", der, filename);
    }

    private static void savePrivateKeyToPem(PrivateKey key, String filename) throws Exception {
        writePem("PRIVATE KEY", key.getEncoded(), filename);
    }

    private static void saveRawKeyToPem(Key key, String filename, boolean isPublic) throws Exception {
        writePem(isPublic ? "PUBLIC KEY" : "PRIVATE KEY", key.getEncoded(), filename);
    }

    private static void writePem(String type, byte[] der, String filename) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");

        Path path = Paths.get(filename);
        Path parent = path.getParent();
        if (parent != null) Files.createDirectories(parent);
        try (FileWriter fw = new FileWriter(filename)) {
            fw.write(sb.toString());
        }
    }
}
