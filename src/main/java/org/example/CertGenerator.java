package org.example;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


public class CertGenerator {
    public static X509Certificate generateCert(KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name("CN=Aliro, O=Aliro_CI, C=CN");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        // 使用BC的证书构建器
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic()
        );

        // 签名并生成证书
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());


        // 添加基本约束（CA证书）
        certBuilder.addExtension(
                Extension.basicConstraints, true, new BasicConstraints(true)
        );
        // 添加密钥用法（数字签名与密钥加密）
        certBuilder.addExtension(
                Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        );

        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    public static void exportCertificateToPem(X509Certificate cert, String filePath) throws Exception {
        try (PEMWriter writer = new PEMWriter(new FileWriter(filePath))) {
            writer.writeObject(cert); // 自动添加BEGIN/END标签和Base64编码
        }
    }

    public static void exportPrivateKeyToPem(PrivateKey privateKey, String filePath) throws Exception {
        try (PEMWriter writer = new PEMWriter(new FileWriter(filePath))) {
            writer.writeObject(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
        }
    }

    // 从PEM文件加载证书
    public static X509Certificate loadCertificate(String pemFilePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(pemFilePath)) {
            return (X509Certificate) certFactory.generateCertificate(fis);
        }
    }

    // 从PEM中加载PK
    public static PublicKey loadPublicKeyWithBC(String certPath) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(certPath)) {
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);
            return certificate.getPublicKey();
        }
    }

    // 从PEM中加载SK
    public static PrivateKey loadPrivateKeyWithBC(String pemFilePath) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(pemFilePath))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (object instanceof PEMKeyPair) {
                return converter.getKeyPair((PEMKeyPair) object).getPrivate();
            } else if (object instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) object);
            }
            throw new IllegalArgumentException("Unsupported private key format");
        }
    }

    // 验证证书签名（支持自签名和CA签发）
    public static int verifyCertSignature(X509Certificate cert) throws Exception { //验证失败返回0否则返回1
        try {
            PublicKey issPublickKey = cert.getPublicKey();
            cert.verify(issPublickKey); // 若为CA签发，需传入CA公钥；自签名则用cert.getPublicKey()
            System.out.println("签名验证通过");
            return 0;
        } catch (Exception e) {
            System.err.println("签名验证失败: " + e.getMessage());

        }

        try {
            cert.checkValidity();  // 使用当前系统时间验证
            System.out.println("当前证书仍在有效期内");
            return 1;
        } catch (Exception e) {
            System.out.println("证书已过期或尚未生效: " + e.getMessage());
        }
        return 0;
    }

    //从ecc的公钥byte中提取x,y
    public static byte[] extractPublicKey(byte[] pubEncoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        PublicKey pubKey = kf.generatePublic(pubSpec);

        if (pubKey instanceof ECPublicKey) {
            ECPublicKey ecPub = (ECPublicKey) pubKey;
            ECPoint point = ecPub.getW();
            BigInteger x = point.getAffineX();
            BigInteger y = point.getAffineY();

            byte[] xBytes = toFixedLength(x, 32); // 固定32字节
            byte[] yBytes = toFixedLength(y, 32);

            // 拼接 x || y
            byte[] xy = new byte[xBytes.length + yBytes.length + 1 ];
            xy[0] = (byte) 0x04;
            System.arraycopy(xBytes, 0, xy, 1, xBytes.length);
            System.arraycopy(yBytes, 0, xy, xBytes.length + 1, yBytes.length);

            return xy;
        } else {
            throw new IllegalArgumentException("Not an EC public key");
        }
    }

    public static PublicKey decodeECPublicKey(byte[] pubBytes, String curveName) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        X9ECParameters x9 = ECNamedCurveTable.getByName(curveName);
        if (x9 == null) {
            throw new IllegalArgumentException("Unsupported curve: " + curveName);
        }
        ECParameterSpec bcSpec = new ECParameterSpec(
                x9.getCurve(),
                x9.getG(),
                x9.getN(),
                x9.getH(),
                x9.getSeed()
        );

        org.bouncycastle.math.ec.ECPoint q = x9.getCurve().decodePoint(pubBytes);

        ECPublicKeySpec pubSpec = new ECPublicKeySpec(q, bcSpec);

        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(pubSpec);
    }


    private static byte[] toFixedLength(BigInteger bi, int length) {
        byte[] tmp = bi.toByteArray();
        byte[] result = new byte[length];
        if (tmp.length > length) {
            System.arraycopy(tmp, tmp.length - length, result, 0, length);
        } else {
            System.arraycopy(tmp, 0, result, length - tmp.length, tmp.length);
        }
        return result;
    }


    public static void savePQCKeyToFile(Key key, String filename) throws Exception {
        byte[] keyBytes = key.getEncoded();
        String pemHeader = key instanceof PublicKey ?
                "-----BEGIN PUBLIC KEY-----\n" : "-----BEGIN PRIVATE KEY-----\n";
        String pemFooter = key instanceof PublicKey ?
                "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";

        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(pemHeader.getBytes());
            fos.write(Base64.getEncoder().encodeToString(keyBytes).getBytes());
            fos.write(pemFooter.getBytes());
        }
    }

    public static PublicKey loadPQCPublicKeyFromPEM(String filename) throws Exception {
        // 读取PEM文件内容
        String pemContent = new String(Files.readAllBytes(Paths.get(filename)));

        // 去除头尾标记和空白字符
        pemContent = pemContent.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        // Base64解码并生成公钥
        byte[] decodedBytes = Base64.getDecoder().decode(pemContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");; // 或根据实际算法调整
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey loadPQCPrivateKeyFromPEM(String filename) throws Exception {
        String pemContent = new String(Files.readAllBytes(Paths.get(filename)));
        pemContent = pemContent.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decodedBytes = Base64.getDecoder().decode(pemContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");; // 或根据实际算法调整
        return keyFactory.generatePrivate(keySpec);
    }


    // 用CI给一个 Subject（Reader/UserDevice）签发证书
    public static X509Certificate generateCert_by_CI(KeyPair subjectKeyPair, String subjectDN,
                                               PrivateKey caPrivKey, X509Certificate caCert) throws Exception {

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 有效期 1 年

        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName()); // CI 作为 Issuer
        X500Name subject = new X500Name(subjectDN);

        BigInteger serial = BigInteger.valueOf(now);

        SubjectPublicKeyInfo subPubKeyInfo =
                SubjectPublicKeyInfo.getInstance(subjectKeyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, startDate, endDate, subject, subjectKeyPair.getPublic());

        // 签名算法（比如 ECDSA + SHA256）
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(caPrivKey);

        X509CertificateHolder holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    // 从 byte[] 解析 X509 证书
    public static X509Certificate loadCertFromBytes(byte[] certBytes) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    //压缩成Profile0000格式
    public static byte[] encodeProfile0000(Profile0000 profile) {
        ASN1EncodableVector dataVector = new ASN1EncodableVector();

        // 可选字段
        if (profile.getData().getSerialNumber() != null) {
            dataVector.add(new DERTaggedObject(0, new DEROctetString(profile.getData().getSerialNumber())));
        }
        if (profile.getData().getIssuer() != null) {
            dataVector.add(new DERTaggedObject(1, new DEROctetString(profile.getData().getIssuer())));
        }
        if (profile.getData().getNotBefore() != null) {
            dataVector.add(new DERTaggedObject(2, new DEROctetString(profile.getData().getNotBefore())));
        }
        if (profile.getData().getNotAfter() != null) {
            dataVector.add(new DERTaggedObject(3, new DEROctetString(profile.getData().getNotAfter())));
        }
        if (profile.getData().getSubject() != null) {
            dataVector.add(new DERTaggedObject(4, new DEROctetString(profile.getData().getSubject())));
        }

        // mandatory fields
        dataVector.add(new DERTaggedObject(5, new DEROctetString(profile.getData().getPublicKey())));
        dataVector.add(new DERTaggedObject(6, new DEROctetString(profile.getData().getSignature())));

        DERSequence dataSeq = new DERSequence(dataVector);

        // Profile0000 SEQUENCE
        ASN1EncodableVector profileVector = new ASN1EncodableVector();
        profileVector.add(new DEROctetString(profile.getProfile())); // 2 bytes
        profileVector.add(dataSeq);

        DERSequence profileSeq = new DERSequence(profileVector);

        try {
            return profileSeq.getEncoded("DER");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, byte[]> parseProfile0000(byte[] der) throws Exception {
        Map<String, byte[]> out = new HashMap<>();

        ASN1Sequence top = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));

        // profile: OCTET STRING (SIZE(2))
        ASN1OctetString profile = ASN1OctetString.getInstance(top.getObjectAt(0));
        out.put("profile", profile.getOctets()); // 应该是 {0x00, 0x00}

        // data: SEQUENCE of [n] IMPLICIT OCTET STRING
        ASN1Sequence dataSeq = ASN1Sequence.getInstance(top.getObjectAt(1));

        for (int i = 0; i < dataSeq.size(); i++) {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(dataSeq.getObjectAt(i));
            int tag = tagged.getTagNo();

            // IMPLICIT -> 第二个参数传 false
            ASN1OctetString os = ASN1OctetString.getInstance(tagged, false);
            byte[] val = os.getOctets();

            switch (tag) {
                case 0: out.put("serialNumber", val); break;         // 原样字节（1..20）
                case 1: out.put("issuer", val); break;                // UTF8String 的字节
                case 2: out.put("notBefore", val); break;             // 13 字节 UTCTime 的字节
                case 3: out.put("notAfter", val); break;              // 13 字节 UTCTime 的字节
                case 4: out.put("subject", val); break;               // UTF8String 的字节
                case 5: out.put("publicKey", val); break;             // DER BIT STRING 的字节串（含 unused-bits 首字节）
                case 6: out.put("signature", val); break;             // DER BIT STRING 的字节串（含 unused-bits 首字节）
                default: /* 忽略未知标签 */ break;
            }
        }
        return out;
    }

    public static X509Certificate decompressToX509Certificate(Map<String, byte[]> profileMap) throws Exception {
        // 取字段（使用文档中提到的默认值作为备选）
        byte[] serialBytes = profileMap.getOrDefault("serialNumber", new byte[]{0x01});
        byte[] issuerBytes = profileMap.get("issuer");    // 可能为 null
        byte[] notBeforeBytes = profileMap.getOrDefault("notBefore", "230101000000Z".getBytes(StandardCharsets.US_ASCII));
        byte[] notAfterBytes = profileMap.getOrDefault("notAfter", "250101000000Z".getBytes(StandardCharsets.US_ASCII));
        byte[] subjectBytes = profileMap.get("subject");   // 可能为 null
        byte[] pubkeyField = profileMap.get("publicKey"); // 必须：BIT STRING bytes (含unused bits 首字节)
        byte[] sigField = profileMap.get("signature"); // 必须：BIT STRING bytes (含unused bits 首字节)

        if (pubkeyField == null || sigField == null) {
            throw new IllegalArgumentException("publicKey 和 signature 是必填字段！");
        }

        // 1) 构造 X500Name (issuer & subject)
        X500Name issuerName = buildX500Name(issuerBytes, "Issuer");
//        X500Name subjectName = buildX500NameFromBytesOrCN(subjectBytes, "CN=Subject");
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, "Reader");
        nameBuilder.addRDN(BCStyle.O, "MyOrg");
        nameBuilder.addRDN(BCStyle.C, "CN");
        X500Name subjectName = nameBuilder.build();

        // 2) serialNumber
        ASN1Integer serial = new ASN1Integer(new BigInteger(1, serialBytes));

        // 3) 签名算法 (此处以 ECDSA with SHA256 为例)
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);

        // 4) 有效期
        Date notBefore;
        try (ASN1InputStream asn1is = new ASN1InputStream(new ByteArrayInputStream(notBeforeBytes))) {
            ASN1UTCTime nb = (ASN1UTCTime) asn1is.readObject();
            notBefore = nb.getDate();
        }

        Date notAfter;
        try (ASN1InputStream asn1is = new ASN1InputStream(new ByteArrayInputStream(notAfterBytes))) {
            ASN1UTCTime na = (ASN1UTCTime) asn1is.readObject();
            notAfter = na.getDate();
        }


        // 5) 公钥：profile 中存的是 "BIT STRING 的内容（含首字节 unusedBits）"
        //    -> 拆出 unusedBits 与内容，然后用 DERBitString(content, unusedBits)
//        int pubUnused = pubkeyField[0] & 0xFF;
//        byte[] pubContent = new byte[pubkeyField.length - 1];
//        System.arraycopy(pubkeyField, 1, pubContent, 0, pubContent.length);
//        DERBitString pubBitString = new DERBitString(pubContent, pubUnused);
        DERBitString pubBitString = new DERBitString(pubkeyField);

        // 构造 SubjectPublicKeyInfo：algorithm = id-ecPublicKey + prime256v1
        AlgorithmIdentifier pkAlg = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                X9ObjectIdentifiers.prime256v1
        );
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(pkAlg, pubBitString);

        // 6) 构造 TBSCertificate (使用 V3 generator)
        V3TBSCertificateGenerator tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(serial);
        tbsGen.setSignature(sigAlg);           // tbsCertificate.signature
        tbsGen.setIssuer(issuerName);
        tbsGen.setStartDate(new Time(notBefore));
        tbsGen.setEndDate(new Time(notAfter));
        tbsGen.setSubject(subjectName);
        tbsGen.setSubjectPublicKeyInfo(spki);

        TBSCertificate tbsCert = tbsGen.generateTBSCertificate();

        // 7) signatureValue
//        int sigUnused = sigField[0] & 0xFF;
//        byte[] sigContent = sigField; // 直接整个数组
        DERBitString signatureBitString = new DERBitString(sigField);

        // 8) 组装 Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(sigAlg);
        v.add(signatureBitString);
        DERSequence certSeq = new DERSequence(v);
        byte[] certDer = certSeq.getEncoded("DER");

        // 9) 转为 Java X509Certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
    }

    private static X500Name buildX500NameFromBytesOrCN(byte[] maybeDerOrCN, String defaultCN) {
        if (maybeDerOrCN != null) {
            // 先尝试按 DER Name 解析
            try {
                ASN1Primitive p = ASN1Primitive.fromByteArray(maybeDerOrCN);
                return X500Name.getInstance(p);
            } catch (Exception ignored) {
                // 不是 DER 编码，则当作 UTF-8 的 CN 值
                String cn = new String(maybeDerOrCN, StandardCharsets.UTF_8);
                return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, cn).build();
            }
        } else {
            // 没提供，使用默认 CN
            return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, defaultCN).build();
        }
    }

    public static X500Name buildX500Name(byte[] dnBytes, String defaultCN) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        // 用于存储解析出的字段
        Map<ASN1ObjectIdentifier, String> fields = new HashMap<>();

        if (dnBytes != null && dnBytes.length > 0) {
            String dnStr = new String(dnBytes, StandardCharsets.UTF_8);
            String[] parts = dnStr.split(",");

            for (String part : parts) {
                part = part.trim();
                if (part.startsWith("C=")) {
                    fields.put(BCStyle.C, part.substring(2));
                } else if (part.startsWith("O=")) {
                    fields.put(BCStyle.O, part.substring(2));
                } else if (part.startsWith("CN=")) {
                    fields.put(BCStyle.CN, part.substring(3));
                } else if (part.startsWith("OU=")) {
                    fields.put(BCStyle.OU, part.substring(3));
                } else if (part.startsWith("L=")) {
                    fields.put(BCStyle.L, part.substring(2));
                } else if (part.startsWith("ST=")) {
                    fields.put(BCStyle.ST, part.substring(3));
                }
            }

            // 按照指定顺序添加字段：C → O → CN → 其他字段
            addFieldInOrder(builder, fields, BCStyle.C);
            addFieldInOrder(builder, fields, BCStyle.O);
            addFieldInOrder(builder, fields, BCStyle.CN);
            addFieldInOrder(builder, fields, BCStyle.OU);
            addFieldInOrder(builder, fields, BCStyle.L);
            addFieldInOrder(builder, fields, BCStyle.ST);

        } else {
            // 默认多段 DN，按照 C → O → CN 顺序
            builder.addRDN(BCStyle.C, "CN");
            builder.addRDN(BCStyle.O, "MyOrg");
            builder.addRDN(BCStyle.CN, defaultCN);
        }

        return builder.build();
    }

    private static void addFieldInOrder(X500NameBuilder builder, Map<ASN1ObjectIdentifier, String> fields, ASN1ObjectIdentifier oid) {
        if (fields.containsKey(oid)) {
            builder.addRDN(oid, fields.get(oid));
        }
    }

}