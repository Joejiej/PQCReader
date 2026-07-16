package org.example;


import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.example.CertGenerator.*;


public class TrustFramework {

//    public static String CIPKcert_path = "F:/Aliro/Aliro/src/main/resources/org/example/cert/CI_certificate.pem";
//    public static String CISK_path = "F:/Aliro/Aliro/src/main/resources/org/example/cert/CISK_path.pem";

    public static String CIPKcert_path = "F:/Aliro/Aliro/src/main/resources/org/example/cert/CI_PQC_certificate.pem";
    public static String CISK_path = "F:/Aliro/Aliro/src/main/resources/org/example/cert/CI_PQCSK_path.pem";

    public static PublicKey CIPK;

    public static void InitiateCICert() throws Exception {
        // 添加Bouncy Castle提供者
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider()); // 注册BCPQC

        //ECC
        //初始化生成
//        KeyPair CIkeypair = generateECCKeyPair();
//        PublicKey CIPK = CIkeypair.getPublic();
//        PrivateKey CISK = CIkeypair.getPrivate();
//        X509Certificate CI_cert = generateCert(CIkeypair);
//        exportCertificateToPem(CI_cert,CIPKcert_path);
//        exportPrivateKeyToPem(CISK, CISK_path);

        //文件中读取
        X509Certificate CI_cert = loadCertificate(CIPKcert_path);
        CIPK = loadPublicKeyWithBC(CIPKcert_path);
//        PrivateKey CISK = loadPrivateKeyWithBC(CISK_path);


        //Dilithium
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium3", "BCPQC");
        KeyPair DilithumkeyPair = kpg.generateKeyPair();

        savePQCKeyToFile(DilithumkeyPair.getPublic(),CIPKcert_path);
        savePQCKeyToFile(DilithumkeyPair.getPrivate(),CISK_path);

    }

    public static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            char c = (char) (Math.random() * 26 + 'a'); // 生成小写字母
            sb.append(c);
        }
        return sb.toString();
    }

    public static byte[] mapToBytes(Map<Integer, Object> map) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(map);
            return bos.toByteArray();
        }
    }

    public static Map<Integer, Object> bytesToMap(byte[] bytes)
            throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            return (Map<Integer, Object>) ois.readObject();
        }
    }

    public static Map<Integer, Object> cborToMap(CBORObject cborObject){
        Map<Integer, Object> map = new HashMap<>();
        for(CBORObject key: cborObject.getKeys()){
            CBORObject value = cborObject.get(key);
            map.put(key.AsInt32(), cborToJava(value));
        }
        return map;
    }

    // 把 CBORObject 转换成 Java 类型
    private static Object cborToJava(CBORObject obj) {
        if (obj == null) {
            return null;
        }

        switch (obj.getType()) {
            case Map:
                Map<Object, Object> map = new HashMap<>();
                for (CBORObject key : obj.getKeys()) {
                    map.put(cborToJava(key), cborToJava(obj.get(key)));
                }
                return map;

            case Array:
                List<Object> list = new ArrayList<>();
                for (int i = 0; i < obj.size(); i++) {
                    list.add(cborToJava(obj.get(i)));
                }
                return list;

            case Integer:
                if (obj.CanValueFitInInt32()) {
                    return obj.AsInt32();
                } else if (obj.CanValueFitInInt64()) {
                    return obj.AsInt64();
                } else {
                    return obj.AsNumber();
                }

            case FloatingPoint:
                return obj.AsDouble();

            case Boolean:
                return obj.AsBoolean();

            case TextString:
                return obj.AsString();

            case ByteString:
                return obj.GetByteString();

            case SimpleValue: // Null 可能是 SimpleValue 类型
                if (obj.isNull()) {
                    return null;
                }
                // 其他简单值类型
                return obj;

            default:
                return obj;
        }
    }

    // 解析CBOR时，map的key会从int转为string，做一个递归强制转换
    public static List<Map<Integer, Object>> convertList(List<?> list) {
        return list.stream()
                .map(item -> {
                    if (item instanceof Map) {
                        return convertMap((Map<?, ?>) item);
                    } else {
                        return item; // 不是 Map 直接返回
                    }
                })
                .map(obj -> (Map<Integer, Object>) obj)
                .collect(Collectors.toList());
    }

    // 递归转换 Map
    public static Map<Integer, Object> convertMap(Map<?, ?> oldMap) {
        Map<Integer, Object> newMap = new HashMap<>();
        for (Map.Entry<?, ?> entry : oldMap.entrySet()) {
            Integer newKey = Integer.parseInt(String.valueOf(entry.getKey()));
            Object value = entry.getValue();
            if (value instanceof Map) {
                value = convertMap((Map<?, ?>) value);
            } else if (value instanceof List) {
                value = convertList((List<?>) value);
            }
            newMap.put(newKey, value);
        }
        return newMap;
    }

    //byte[]转15进制
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b)); // 大写十六进制
        }
        return sb.toString();
    }

    //将string转为byte，不足填充长则截断
    public static byte[] toFixedLengthBytes(String str, int length) {
        byte[] bytes = new byte[length]; // 默认填充 0
        byte[] strBytes = str.getBytes();
        int copyLength = Math.min(strBytes.length, length);
        System.arraycopy(strBytes, 0, bytes, 0, copyLength);
        return bytes;
    }

    //拼接两个byte[]
    public static byte[] concatBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }




    public static void main(String[] args) {
        System.out.println(generateRandomString(8)); // 输出如：abc123456
    }


}
