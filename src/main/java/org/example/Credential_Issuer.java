package org.example;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.FileReader;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Credential_Issuer {
    public  Credential_Issuer(){
        System.out.println("Initialized Credential_Issuer.");
    }

    //创建Issuer的证书，导出公私钥证书
    public static void create_Issuer_Cert() throws Exception {
        //Reader_keypair
        // 1. 创建 KeyPairGenerator 实例，指定 ECC 算法
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // 2. 初始化 P-256 曲线（secp256r1）
        keyGen.initialize(256); // 256 位对应 P-256 曲线

        // 3. 生成密钥对
        KeyPair Reader_keyPair = keyGen.generateKeyPair();
        PublicKey Reader_publicKey = Reader_keyPair.getPublic();
        PrivateKey Reader_privateKey = Reader_keyPair.getPrivate();

        // 4. 输出 Base64 编码的公钥和私钥
        System.out.println("Reader Public Key (Base64): " +
                Base64.getEncoder().encodeToString(Reader_publicKey.getEncoded()));
        System.out.println("Reader Private Key (Base64): " +
                Base64.getEncoder().encodeToString(Reader_privateKey.getEncoded()));


        //创建证书
        X509Certificate Reader_Cert = CertGenerator.generateCert(Reader_keyPair);


        //PK_cert
        String cert_path = "src/main/java/org/example/cert/Credential_certificate.pem";

        //SK_Pem
        String SK_path = "src/main/java/org/example/cert/Credential_SK.pem";

        //导出证书
        CertGenerator.exportCertificateToPem(Reader_Cert,cert_path);
        //导出私钥
        CertGenerator.exportPrivateKeyToPem(Reader_privateKey, SK_path);

    }

    //验证证书有效性
    public static int verify_Reader_Cert() throws Exception {   //验证失败返回1否则返回0
        //PK_cert
        String cert_path = "src/main/java/org/example/cert/Credential_certificate.pem";

        X509Certificate  Reader_Cert = CertGenerator.loadCertificate(cert_path);

        if(CertGenerator.verifyCertSignature(Reader_Cert)!=0){
            return 1;
        }

        return 0;
    }

    public static PublicKey getPublicKeyFromPEMCert(String certPath) throws Exception {
        // 注册 BouncyCastle 提供者（只需执行一次）
        Security.addProvider(new BouncyCastleProvider());

        // 读取 PEM 格式证书
        try (PEMParser pemParser = new PEMParser(new FileReader(certPath))) {
            Object object = pemParser.readObject();
            if (!(object instanceof X509CertificateHolder)) {
                throw new IllegalArgumentException("不是合法的X.509 PEM证书！");
            }

            X509CertificateHolder certHolder = (X509CertificateHolder) object;
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certHolder);

            return certificate.getPublicKey();
        }
    }

    public static PrivateKey getPrivateKeyFromPEM(String pemPath) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        try (PEMParser pemParser = new PEMParser(new FileReader(pemPath))) {
            Object obj = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (obj instanceof PEMKeyPair) {
                // 如 EC 私钥格式为：-----BEGIN EC PRIVATE KEY-----
                return converter.getKeyPair((PEMKeyPair) obj).getPrivate();
            } else if (obj instanceof PrivateKeyInfo) {
                // 如私钥格式为：-----BEGIN PRIVATE KEY-----
                return converter.getPrivateKey((PrivateKeyInfo) obj);
            } else {
                throw new IllegalArgumentException("无法识别的私钥格式！");
            }
        }
    }
}
