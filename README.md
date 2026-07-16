# PQCReader

**PQ-Aliro NFC Reader (PC side)** — A post-quantum cryptographic implementation of the Aliro 1.0 NFC access-control protocol, using ML-KEM (Kyber) and ML-DSA (Dilithium).

## Overview

This is the PC-side NFC reader component of the PQ-Aliro project. It communicates with an Android HCE (Host Card Emulation) user device over ISO/IEC 14443 NFC, executing the three-round Aliro Expedited Flow (AUTH0 / LOADCERT / AUTH1) with post-quantum cryptographic primitives.

- **Key encapsulation**: ML-KEM-768 (CRYSTALS-Kyber), FIPS 203
- **Digital signatures**: ML-DSA-65 (CRYSTALS-Dilithium), FIPS 204
- **Crypto backend**: BouncyCastle 1.78 BCPQC
- **NFC interface**: `javax.smartcardio` (PC/SC), compatible with ACR122U and similar USB readers

## Repository Structure

```
PQCReader/
├── pom.xml                              # Maven build config
├── src/main/java/org/example/
│   ├── Main.java                        # Entry stub
│   ├── Reader.java                      # Main reader logic (interactive menu + benchmark)
│   ├── PQCConfig.java                   # PQC parameter configuration (MODE / levels)
│   ├── PQCUtil.java                     # PQC utility functions
│   ├── PQCertTool.java                  # Certificate generation tool
│   ├── ECC.java                         # Legacy ECC code (for baseline comparison)
│   ├── Profile0000.java                 # Aliro Profile0000 certificate
│   ├── TrustFramework.java              # Trust framework
│   ├── Credential_Issuer.java           # Credential issuer
│   ├── Access_Document.java             # Access document
│   ├── AccessDataElement.java
│   ├── IssuerSignedItem.java
│   └── PRNG.java
├── src/main/resources/cert/             # Pre-generated certificates and keys
│   ├── CI_certificate.pem
│   ├── Credential_certificate.pem
│   ├── Credential_SK.pem
│   ├── Reader_certificate.pem
│   └── Reader_SK.pem
└── src/test/java/org/example/
    ├── PQSelfTest.java                  # 42 basic PQC unit tests
    └── PQAliroProtocolTest.java         # 200 end-to-end protocol tests (9 configs)
```

## Build

Requirements: Java 11+, Maven 3.6+

```bash
mvn clean compile -q
mvn clean package -q        # produces target/Aliro_Reader-1.0-SNAPSHOT.jar
```

## Self-Test

Run the basic PQC unit tests (Kyber/Dilithium/HKDF/AEAD/SHAKE256):

```bash
mvn test-compile -q
CP=$(mvn dependency:build-classpath -q -Dmdep.outputFile=/dev/stdout)
java -cp "target/test-classes:target/classes:$CP" org.example.PQSelfTest
```

Expected: 42/42 PASSED.

Run the full end-to-end protocol test (9 PQC configurations):

```bash
java -cp "target/test-classes:target/classes:$CP" org.example.PQAliroProtocolTest
```

Expected: 200/200 PASSED.

## Run with Real NFC Hardware

1. Connect a USB NFC reader (e.g., ACS ACR122U) to the PC.
2. Install the companion Android app: [Ailiro_UD](https://github.com/Joejiej/Ailiro_UD).
3. Launch the reader:

```bash
java -jar target/Aliro_Reader-1.0-SNAPSHOT.jar
```

4. Use the interactive menu:
   - `1` — List NFC readers
   - `2` — Wait for Android device
   - `7` — Full protocol test (single run)
   - `9` — Benchmark (5 iterations, real timing)
   - `0` — Exit

5. Place the Android phone (with Ailiro_UD app in foreground) on the NFC reader.

## Configuration

Edit `src/main/java/org/example/PQCConfig.java` to switch between PQ and ECC modes, or to change the security level:

```java
public static Mode MODE = Mode.PQ;          // PQ or CLASSIC
public static int KYBER_LEVEL = 768;        // 512 | 768 | 1024
public static int DILITHIUM_LEVEL = 3;      // 2 | 3 | 5
```

Default: D3×K768 (ML-DSA-65 + ML-KEM-768, NIST Security Level 3).

## Related

- **Android UD app**: https://github.com/Joejiej/Ailiro_UD
- **Paper + full project**: https://github.com/Joejiej/Aliro_Paper
- **Aliro 1.0 specification**: CSA, 2024

## License

For research and evaluation purposes.

## Citation

If you use this code in academic work, please cite:

> Post-Quantum Aliro: Integrating NIST Post-Quantum Cryptography Standards into NFC Access Control.
