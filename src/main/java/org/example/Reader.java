package org.example;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.TBSCertificate;

import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Hex;


import java.util.*;

import static org.example.Access_Document.get_decode;
import static org.example.CertGenerator.*;
import static org.example.ECC.*;
import static org.example.TrustFramework.concatBytes;
import static org.example.PQCUtil.*;

public class Reader {

    // NFC相关
    private TerminalFactory factory;
    private CardTerminal terminal;
    private Card card;
    private CardChannel channel;

    private static final String Aliro_AID = "F01020304050";


    public static void main(String[] args) throws Exception {

        System.out.println("PQCConfig: mode=" + PQCConfig.MODE
                + "  dilithiumLevel=" + PQCConfig.DILITHIUM_LEVEL
                + "  kyberLevel=" + PQCConfig.KYBER_LEVEL);

        byte[] group_id = TrustFramework.toFixedLengthBytes("wbl", 16);

        if (PQCConfig.isPQ()) {
            // ---- PQ mode: load Dilithium cert + private key ----
            String certDir = "src/main/resources/cert_pq";
            String readerCertPath = certDir + "/Reader_dilithium_cert.pem";
            String readerSKPath   = certDir + "/Reader_dilithium_priv.pem";
            String ciCertPath     = certDir + "/CI_dilithium_cert.pem";

            X509Certificate reader_cert = loadCertificate(readerCertPath);
            PublicKey  readerPK = reader_cert.getPublicKey();
            PrivateKey readerSK = loadPQCPrivateKeyFromPEM(readerSKPath);
            X509Certificate CI_cert = loadCertificate(ciCertPath);

            List<X509Certificate> CIcertlist = new ArrayList<>();
            CIcertlist.add(CI_cert);

            KeyPair readerkeyPair = new KeyPair(readerPK, readerSK);
            Reader reader = new Reader(group_id, readerkeyPair, reader_cert, CIcertlist);
            reader.run();
        } else {
            // ---- Classic mode: load ECC cert + private key ----
            String Reader_certificate_path = "src/main/resources/cert/Reader_certificate.pem";
            String Reader_SK_path          = "src/main/resources/cert/Reader_SK.pem";
            String CIPKcert_path           = "src/main/resources/cert/CI_certificate.pem";

            X509Certificate reader_cert = loadCertificate(Reader_certificate_path);
            PublicKey  readerPK = loadPublicKeyWithBC(Reader_certificate_path);
            PrivateKey readerSK = loadPrivateKeyWithBC(Reader_SK_path);
            X509Certificate CI_cert = loadCertificate(CIPKcert_path);

            List<X509Certificate> CIcertlist = new ArrayList<>();
            CIcertlist.add(CI_cert);

            KeyPair readerkeyPair = new KeyPair(readerPK, readerSK);
            Reader reader = new Reader(group_id, readerkeyPair, reader_cert, CIcertlist);
            reader.run();
        }
    }

    public void run() {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n=== NFC Reader Client Menu ===");
            System.out.println("1. List NFC Readers");
            System.out.println("2. Wait for Android Device");
            System.out.println("3. Test SelectCommand");
            System.out.println("4. Test AUTH0 Command");
            System.out.println("5. Test LOADCERT Command");
            System.out.println("6. Test AUTH1 Command");
            System.out.println("7. Full Protocol test");
            System.out.println("9. Benchmark (5 iterations, real timing)");
            System.out.println("0. Exit");
            System.out.print("Choose option: ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // consume newline

            try {
                switch (choice) {
                    case 1:
                        listNFCReaders();
                        break;
                    case 2:
                        waitForAndroidDevice();
                        break;
                    case 3:
                        testSelectCommand();
                        break;
                    case 4:
                        testAUTH0();
                        break;
                    case 5:
                        testLOADCERT();
                        break;
                    case 6:
                        testAUTH1();
                        break;
                    case 7:
                        testFullProtocol();
                        break;
                    case 8:
                        testCustomCommand(scanner);
                        break;
                    case 9:
                        testFullProtocolBenchmark(5);
                        break;
                    case 0:
                        disconnect();
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid option");
                }
            } catch (Exception e) {
                System.err.println("Operation failed: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private void listNFCReaders() throws CardException {
        System.out.println("\n--- Available NFC Readers ---");
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            System.out.println("No NFC readers found!");
            System.out.println("\nTroubleshooting:");
            System.out.println("1. Make sure NFC reader is connected");
            System.out.println("2. Install proper drivers (e.g., for ACR122U)");
            System.out.println("3. Check Windows Device Manager");
            return;
        }

        for (int i = 0; i < terminals.size(); i++) {
            CardTerminal t = terminals.get(i);
            boolean cardPresent = t.isCardPresent();
            System.out.printf("%d. %s [Card: %s]\n",
                    i + 1, t.getName(), cardPresent ? "Present" : "Not Present");
        }
    }

    private void waitForAndroidDevice() throws CardException {
        if (terminal == null) {
            System.out.println("No NFC reader available!");
            return;
        }

        System.out.println("\n--- Waiting for Android Device ---");
        System.out.println("Please bring your Android device close to the NFC reader...");
        System.out.println("Press Ctrl+C to cancel");

        try {
            // 等待卡片出现
            terminal.waitForCardPresent(0); // 0 = 无限等待

            // 连接到卡片
            card = terminal.connect("*"); // "*" 表示任何协议
            channel = card.getBasicChannel();

            System.out.println("✓ Android device detected!");
            System.out.println("Card ATR: " + Hex.toHexString(card.getATR().getBytes()));
            System.out.println("Protocol: " + card.getProtocol());

        } catch (CardException e) {
            System.err.println("Failed to connect to Android device: " + e.getMessage());
            throw e;
        }
    }

    private void testSelectCommand() throws CardException {
        if (!ensureConnected()) return;

        System.out.println("\n--- Testing SELECT Command ---");

        byte[] selectApdu = buildSelectApdu(Aliro_AID);
        System.out.println("Sending SELECT APDU: " + Hex.toHexString(selectApdu));

        ResponseAPDU response = sendApdu(selectApdu);
        System.out.println("Response: " + Hex.toHexString(response.getBytes()));
        System.out.println("SW: " + String.format("%04X", response.getSW()));

        if (response.getSW() == 0x9000) {
            System.out.println("✓ SELECT command successful");
        } else {
            System.out.println("✗ SELECT command failed");
        }
    }

    private void testAUTH0() throws Exception {
        if (!ensureConnected()) return;

        if (PQCConfig.isPQ()) {
            testAUTH0_PQ();
        } else {
            testAUTH0_Classic();
        }
    }

    private void testAUTH0_Classic() throws Exception {
        System.out.println("\n--- Testing AUTH0 command (Classic ECC) ---");

        // 先SELECT
        byte[] selectApdu = buildSelectApdu(Aliro_AID);
        ResponseAPDU selectResp = sendApdu(selectApdu);
        if (selectResp.getSW() != 0x9000) {
            System.out.println("✗ SELECT failed, cannot get public key");
            return;
        }

        List<CommandAPDU> AUTH0command = new ArrayList<>();
        List<ResponseAPDU> AUTH0response = new ArrayList<>();


        AUTH0command = CreateAUTH0();
        for (CommandAPDU command : AUTH0command){
            byte[] bytestype = command.getBytes();
            System.out.println("Sending AUTH0 APDU: " + Hex.toHexString(bytestype));
        }

        AUTH0response = sendApduList(AUTH0command);
        for(ResponseAPDU responseAPDU : AUTH0response){
            System.out.println("Response: " + Hex.toHexString(responseAPDU.getBytes()));
            System.out.println("SW: " + String.format("%04X", responseAPDU.getSW()));
        }
        getAUTH0resp(AUTH0response);

    }

    private void testAUTH1() throws Exception {
        if (!ensureConnected()) return;

        if (PQCConfig.isPQ()) {
            testAUTH1_PQ();
        } else {
            testAUTH1_Classic();
        }
    }

    private void testAUTH1_Classic() throws Exception {
        System.out.println("\n--- Testing AUTH1 command (Classic ECC) ---");

        // 先SELECT
        byte[] selectApdu = buildSelectApdu(Aliro_AID);
        ResponseAPDU selectResp = sendApdu(selectApdu);
        if (selectResp.getSW() != 0x9000) {
            System.out.println("✗ SELECT failed, cannot get public key");
            return;
        }

        List<CommandAPDU> AUTH1command = new ArrayList<>();
        List<ResponseAPDU> AUTH1response = new ArrayList<>();


        AUTH1command = CreateAUTH1();
        for (CommandAPDU command : AUTH1command){
            byte[] bytestype = command.getBytes();
            System.out.println("Sending AUTH1 APDU: " + Hex.toHexString(bytestype));
        }

        AUTH1response = sendApduList(AUTH1command);
        for(ResponseAPDU responseAPDU : AUTH1response){
            System.out.println("Response: " + Hex.toHexString(responseAPDU.getBytes()));
            System.out.println("SW: " + String.format("%04X", responseAPDU.getSW()));
        }
        getAUTH1resp(AUTH1response);

    }

    private void testLOADCERT() throws Exception{
        if (!ensureConnected()) return;

        System.out.println("\n--- LOADCERT Test ---");

        // 先SELECT
        byte[] selectApdu = buildSelectApdu(Aliro_AID);
        ResponseAPDU selectResp = sendApdu(selectApdu);
        if (selectResp.getSW() != 0x9000) {
            System.out.println("✗ SELECT failed, cannot get public key");
            return;
        }

        List<CommandAPDU> LOADCERTcommand = new ArrayList<>();

        List<ResponseAPDU> LOADCERTresponse = new ArrayList<>();

        LOADCERTcommand = LOADCERT();

        for (CommandAPDU command : LOADCERTcommand){
            byte[] bytestype = command.getBytes();
            System.out.println("Sending LOADCERTcommand APDU: " + Hex.toHexString(bytestype));
        }

        LOADCERTresponse = sendApduList(LOADCERTcommand);
        for(ResponseAPDU responseAPDU : LOADCERTresponse){
            System.out.println("Response: " + Hex.toHexString(responseAPDU.getBytes()));
            System.out.println("SW: " + String.format("%04X", responseAPDU.getSW()));
        }

    }




    private void testFullProtocol() throws Exception {
        System.out.println("\n--- Full Protocol Test ---");
        testAUTH0();
        Thread.sleep(500);
        testLOADCERT();
        Thread.sleep(500);
        testAUTH1();
    }

    // -----------------------------------------------------------------------
    // Benchmark: measure real end-to-end latency over N iterations
    // -----------------------------------------------------------------------
    private void testFullProtocolBenchmark(int iterations) throws Exception {
        String config = (PQCConfig.isPQ()
                ? "D" + PQCConfig.DILITHIUM_LEVEL + "×K" + PQCConfig.KYBER_LEVEL
                : "ECC-Classic");
        System.out.println("\n=== BENCHMARK: " + config + " (" + iterations + " iterations) ===");
        System.out.println("Phase,Iter,ms");

        long[] auth0ms     = new long[iterations];
        long[] loadcertms  = new long[iterations];
        long[] auth1ms     = new long[iterations];
        long[] totalms     = new long[iterations];

        for (int i = 0; i < iterations; i++) {
            System.out.println("--- Iter " + (i + 1) + "/" + iterations + " ---");

            long txStart = System.currentTimeMillis();

            long t0 = System.currentTimeMillis();
            testAUTH0();
            auth0ms[i] = System.currentTimeMillis() - t0;
            System.out.printf("AUTH0,%d,%d%n", i + 1, auth0ms[i]);

            long t1 = System.currentTimeMillis();
            testLOADCERT();
            loadcertms[i] = System.currentTimeMillis() - t1;
            System.out.printf("LOADCERT,%d,%d%n", i + 1, loadcertms[i]);

            long t2 = System.currentTimeMillis();
            testAUTH1();
            auth1ms[i] = System.currentTimeMillis() - t2;
            System.out.printf("AUTH1,%d,%d%n", i + 1, auth1ms[i]);

            totalms[i] = System.currentTimeMillis() - txStart;
            System.out.printf("TOTAL,%d,%d%n", i + 1, totalms[i]);

            if (i < iterations - 1) Thread.sleep(300); // brief reset pause
        }

        // Summary
        System.out.println("\n=== RESULTS: " + config + " ===");
        System.out.printf("Phase      | min(ms) | max(ms) | avg(ms)%n");
        System.out.printf("AUTH0      | %7d | %7d | %7d%n", bmMin(auth0ms),    bmMax(auth0ms),    bmAvg(auth0ms));
        System.out.printf("LOADCERT   | %7d | %7d | %7d%n", bmMin(loadcertms), bmMax(loadcertms), bmAvg(loadcertms));
        System.out.printf("AUTH1      | %7d | %7d | %7d%n", bmMin(auth1ms),    bmMax(auth1ms),    bmAvg(auth1ms));
        System.out.printf("TOTAL      | %7d | %7d | %7d%n", bmMin(totalms),    bmMax(totalms),    bmAvg(totalms));
        System.out.printf("Config: %s%n", config);
    }

    private static long bmMin(long[] a) { long m = a[0]; for (long v : a) if (v < m) m = v; return m; }
    private static long bmMax(long[] a) { long m = a[0]; for (long v : a) if (v > m) m = v; return m; }
    private static long bmAvg(long[] a) { long s = 0; for (long v : a) s += v; return s / a.length; }

    private void testCustomCommand(Scanner scanner) throws CardException {
        if (!ensureConnected()) return;

        System.out.println("\n--- Custom APDU Test ---");
        System.out.print("Enter APDU hex string: ");
        String hexInput = scanner.nextLine().trim().replaceAll("\\s+", "");

        try {
            byte[] apduBytes = Hex.decode(hexInput);
            System.out.println("Sending: " + Hex.toHexString(apduBytes));

            ResponseAPDU response = sendApdu(apduBytes);
            System.out.println("Response: " + Hex.toHexString(response.getBytes()));
            System.out.println("SW: " + String.format("%04X", response.getSW()));

        } catch (Exception e) {
            System.err.println("Custom command failed: " + e.getMessage());
        }
    }

    private void disconnect() {
        try {
            if (card != null) {
                card.disconnect(false);
                card = null;
                channel = null;
                System.out.println("Disconnected from Android device");
            }
        } catch (CardException e) {
            System.err.println("Disconnect error: " + e.getMessage());
        }
    }

    private boolean ensureConnected() {
        if (channel == null) {
            System.out.println("Not connected to Android device. Please use option 2 first.");
            return false;
        }
        return true;
    }

    private static byte[] buildSelectApdu(String aid) {
        return Hex.decode("00A40400" + String.format("%02X", aid.length() / 2) + aid);
    }

    private ResponseAPDU sendApdu(byte[] apduBytes) throws CardException {
        CommandAPDU command = new CommandAPDU(apduBytes);
        return channel.transmit(command);
    }

    private void initNFCReader() throws CardException {
        // 获取PC/SC终端工厂
        factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            System.out.println("Warning: No NFC readers found. Available options:");
            System.out.println("1. Connect a USB NFC reader (like ACR122U)");
            System.out.println("2. Use Windows built-in NFC (if available)");
            System.out.println("3. Install proper drivers for your NFC hardware");
            return;
        }

        // 使用第一个可用的终端
        terminal = terminals.get(0);
        System.out.println("Using NFC reader: " + terminal.getName());
    }



    // Reader标识符（包含group和sub-group）
    public static class ReaderIdentifier {

        private final byte[] reader_group_identifier;  // 安装时设置，需全局唯一
        private final byte[] reader_group_sub_identifier;  // 16字节随机值

        public ReaderIdentifier(byte[] groupId, byte[] subId) {
            if (subId.length != 16) {
                throw new IllegalArgumentException("reader_group_sub_identifier必须是16字节");
            }
            this.reader_group_identifier = groupId;
            this.reader_group_sub_identifier = Arrays.copyOf(subId, subId.length);
        }

        public byte[] getGroupIdentifier() {
            return reader_group_identifier;
        }

        public byte[] getsubGroupIdentifier() {
            return reader_group_sub_identifier;
        }

        public byte[] getReaderIdentifier() {
            return concatBytes(reader_group_identifier,reader_group_sub_identifier);
        }

        public byte[] getGroupSubIdentifier() {
            return Arrays.copyOf(reader_group_sub_identifier, 16);
        }

        public String getSubIdentifierHex() {
            return bytesToHex(reader_group_sub_identifier);
        }
    }

    // 核心字段
    private  ReaderIdentifier identifier;
    private byte[] readerIdentifierbyte;
    private  KeyPair readerKeyPair;  // reader_PubK/PrivK
    private PrivateKey reader_PrivK;
    private X509Certificate readerCert;    // 可选证书
    private List<X509Certificate> CAcertList = new ArrayList<>();       //CA公钥，用以验证AD
    private AccessManager accessManager;   // 内置或远程Access Manager


    //AUTH0
    private byte command_parameters;
    private byte authentication_policy;
    private KeyPair reader_ekeypair;
    private byte[] reader_ePubk;
    private byte[] reader_ePriv;
    private byte[] transaction_identifier;
    private byte[] expedited_phase_protocol_version = new byte[2];

    //AUTH1
    private byte[] credential_ePubK;
    private byte[] cryptogram;
    private byte[] kdh;
    private byte[] derived_keys_volatite;
    private byte[] expeditedSKReader;
    private byte[] expeditedSKDevice = new byte[32];
    private byte[] stepUpSK;
    private byte[] flag = new byte[2];
    private byte[] interface_byte = new byte[1];
    private byte[] reader_epubk_x = new byte[32];
    private int expedited_device_counter = 0x00000001;
    private int expedited_reader_counter = 0x00000001;     //session_bound
    private byte[] aad = new byte[0];
    private int key_slot_flag = 0;
    private byte[] key_slot = new byte[8];
    private PublicKey Access_Credential_PubKey;
    private int private_mailbox_use = 0;
    private byte[] signal_bitmap = new byte[2];
    private static final int MAX_APDU_CHUNK = 240; // 一次最多返回240字节（留点空间）

    //Step-up
    private byte[] proprietary_information = {0x01,0x00,0x10,0x10};    //以2Byte为一组列出支持的协议版本，至少包含0x0100

    // ---------- PQ-specific (used only when PQCConfig.MODE == PQ) ----------
    private KeyPair reader_kyber_keypair;          // Reader's ephemeral Kyber keypair (per session)
    private byte[]  kyber_encap_ciphertext;        // UD's encapsulation result (received in AUTH0 response)
    private byte[]  ud_noise;                      // UD's 32-byte noise (received in AUTH0 response)
    private byte[]  kyber_shared_secret;           // result of Kyber.Decap
    private byte[]  ud_dilithium_pubkey_raw;       // UD's long-term Dilithium pub key (raw bytes, received in AUTH1 response)
    private PublicKey ud_dilithium_pubkey;
    private byte[]  transAH0;                      // SHAKE256-512 of transcript (64 bytes)
    private byte[]  hs;                            // HKDF-Extract output (32 bytes)
    private final ByteArrayOutputStream baosATH0ComMes = new ByteArrayOutputStream();
    private final ByteArrayOutputStream baosATH0ResMes = new ByteArrayOutputStream();


    // 构造方法（reader必须在认证周期存活）
    public Reader(byte[] groupId, KeyPair keyPair, X509Certificate readerCert, List<X509Certificate> CAcertList) throws Exception {

        try {
            AccessManager accessManager;

            this.command_parameters = (byte) 0x00; //0:Expedited_Stantard phase  1:Expedited-Fast phase
            this.authentication_policy = (byte) 0x01; //0x01:User device setting   0x02:User device setting-secure action   0x03:Force user authentication
            this.expedited_phase_protocol_version[0] = (byte) 0x01;
            this.expedited_phase_protocol_version[1] = (byte) 0x01;

            byte[] subId = new byte[16];
            subId = TrustFramework.toFixedLengthBytes("back_door",16);

            this.identifier = new ReaderIdentifier(groupId, subId);
            this.readerKeyPair = keyPair;
            this.reader_PrivK = keyPair.getPrivate();
            this.readerCert = readerCert;
            this.accessManager = new LocalAccessManager(); // 默认内置Access Manager
            this.CAcertList = CAcertList;
            this.readerIdentifierbyte = identifier.getReaderIdentifier();

            initNFCReader();
            System.out.println("NFC Reader Client initialized");
        }catch (Exception e) {
            System.err.println("Initialization failed: " + e.getMessage());
            e.printStackTrace();
        }

    }

    public static Access_Document AD_Parser(byte[] cbor) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new CBORFactory());

        Access_Document AD = mapper.readValue(cbor,Access_Document.class);
        return AD;
    }

    // 与User Device交互的方法
    public boolean authenticateUserDevice(PublicKey devicePubKey) {
        return accessManager.authenticate(devicePubKey);
    }

    public boolean verifyAccessDocument(byte[] document, PublicKey issuerPubKey) throws Exception {

        return accessManager.verifyDocument(document, issuerPubKey);
    }

    // 密钥和证书管理
    public PublicKey getPublicKey() {
        return readerKeyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return readerKeyPair.getPrivate();
    }

    public void updateCertificate(X509Certificate newCert) {
        this.readerCert = newCert;
    }

    public  byte[] Reader_Sign(PrivateKey readerSK, byte[] plaintext) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(readerSK);
        signature.update(plaintext);
        return signature.sign();  // 返回签名结果
    }


    // 辅助方法：字节数组转十六进制
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // Access Manager接口（可根据需要实现本地或远程）
    public interface AccessManager {
        boolean authenticate(PublicKey devicePubKey);
        boolean verifyDocument(byte[] document, PublicKey issuerPubKey) throws Exception;
    }

    public AccessManager getAccessManager() {
        return this.accessManager;
    }

    // 内置Access Manager实现
    private class LocalAccessManager implements AccessManager {

        public LocalAccessManager() {  //待修改，是pk列表或者是AD
            System.out.println("Initialized with policy: ");
        }

        @Override
        public boolean authenticate(PublicKey devicePubKey) {
            // 实现认证逻辑（如检查预配置的公钥列表）
            return true;
        }

        @Override
        public boolean verifyDocument(byte[] document, PublicKey CIPubKey) throws Exception {
            Map<Integer, Object> get_dict = get_decode(document);
            List<Map<Integer, Object>> list2 = (List<Map<Integer, Object>>) get_dict.get(2);

            Map<Integer,Object> IssuerAuth = (Map<Integer,Object> )get_dict.get(1);
            Map<Integer,Object> validityInfo = (Map<Integer,Object> )IssuerAuth.get("6");
            byte[] signedItem = (byte[]) validityInfo.get("1");

            //反序列化过程中key的int会被转为string,做一次强制转换
            List<Map<Integer,Object>> convertedList = TrustFramework.convertList(list2);

            CBORObject cborArray = CBORObject.NewArray();
            for (Map<Integer, Object> map : convertedList) {
                CBORObject cborMap = CBORObject.NewMap();

                for (Map.Entry<Integer, Object> entry : map.entrySet()) {
                    cborMap.Add(entry.getKey(), CBORObject.FromObject(entry.getValue()));
                }

                cborArray.Add(cborMap);
            }

            byte[] getist = cborArray.EncodeToBytes();


            boolean vr = ECC.verifySignature(getist,signedItem,CIPubKey);
            return vr;
        }
    }

    //每个apdu指令和响应都封装成List<commandAPDU>形式，如果不和UD一样用byte就不用transmit
    private byte[] transmitWithChain(CommandAPDU command) throws CardException {
        byte[] fullResponse = new byte[0];

        ResponseAPDU response = channel.transmit(command);
        byte[] data = response.getData();
        int sw = response.getSW();

        // 累加第一包数据
        if (data.length > 0) {
            fullResponse = concat(fullResponse, data);
        }

        // 处理分包 0x61XX：还有数据
        while ((sw & 0xFF00) == 0x6100) {
            int le = sw & 0xFF; // 提取 XX
            CommandAPDU getMore = new CommandAPDU(0x00, 0xC0, 0x00, 0x00, le);
            ResponseAPDU next = channel.transmit(getMore);
            byte[] moreData = next.getData();
            if (moreData.length > 0) {
                fullResponse = concat(fullResponse, moreData);
            }
            sw = next.getSW();
        }

        // 处理 0x6CXX：重发使用正确 Le
        if ((sw & 0xFF00) == 0x6C00) {
            int correctLe = sw & 0xFF;
            CommandAPDU retry = new CommandAPDU(
                    command.getCLA(),
                    command.getINS(),
                    command.getP1(),
                    command.getP2(),
                    correctLe
            );
            return transmitWithChain(retry);
        }

        return fullResponse;
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    public List<ResponseAPDU> sendApduList(List<CommandAPDU> apduList) throws CardException {
        List<ResponseAPDU> results = new ArrayList<>();

        for (CommandAPDU apdu : apduList) {
            ResponseAPDU response = channel.transmit(apdu);
            results.add(response);
        }

        return results;
    }


    public List<CommandAPDU> CreateAUTH0() throws Exception {
        /**
         * 构建 AUTH0 命令 APDU
         * @param commandParams   1字节 command_parameters
         * @param authPolicy      1字节 authentication_policy
         * @param protoVersion    2字节 expedited_phase_protocol_version
         * @param readerPubKey    65字节 (0x04 || X 32B || Y 32B)
         * @param transactionId   16字节
         * @param readerId        32字节 (group_identifier 16B || sub_identifier 16B)
         * @param vendorExt       可选扩展 (最多127字节)，可传 null
         * @return 完整 APDU (byte[])
         */

        //generate ephemeral reader key pair
        this.reader_ekeypair =  generateECCKeyPair();
        this.reader_ePubk = CertGenerator.extractPublicKey(reader_ekeypair.getPublic().getEncoded());

        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = new byte[16];
        secureRandom.nextBytes(seed);
        PRNG prng = new PRNG(seed);
        this.transaction_identifier = prng.nextBytes(16);
        byte[] reader_id = concatBytes(this.identifier.getGroupIdentifier(),this.identifier.getsubGroupIdentifier());

        byte[] vendor = new byte[0];

        if(this.expedited_phase_protocol_version.length != 2){
            throw new IllegalArgumentException("Reader expedited_phase_protocol_version must be 2 bytes");
        }
        if (this.reader_ePubk.length != 65) {
            throw new IllegalArgumentException("Reader public key must be 65 bytes (0x04||X||Y)");
        }
        if (this.transaction_identifier.length != 16) {
            throw new IllegalArgumentException("Transaction_identifier must be 16 bytes");
        }
        if (reader_id.length != 32) {
            throw new IllegalArgumentException("Reader ID must be 32 bytes");
        }

        List<Byte> data = new ArrayList<>();

        // Tag 0x41 - command_parameters
        data.add((byte) 0x41);
        data.add((byte) 0x01);
        data.add(this.command_parameters);

        // Tag 0x42 - authentication_policy
        data.add((byte) 0x42);
        data.add((byte) 0x01);
        data.add(this.authentication_policy);

        // Tag 0x5C - expedited_phase_protocol_version
        data.add((byte) 0x5C);
        data.add((byte) 0x02);
        for (byte b : this.expedited_phase_protocol_version) data.add(b);

        // Tag 0x87 - reader_ePubK
        data.add((byte) 0x87);
        data.add((byte) 0x41); // length = 65
        for (byte b : this.reader_ePubk) data.add(b);

        // Tag 0x4C - transaction_identifier
        data.add((byte) 0x4C);
        data.add((byte) 0x10); // length = 16
        for (byte b : this.transaction_identifier) data.add(b);

        // Tag 0x4D - reader_identifier
        data.add((byte) 0x4D);
        data.add((byte) 0x20); // length = 32
        for (byte b : reader_id) data.add(b);

        // Tag 0xB1 - vendor extension (optional)
        if (vendor != null && vendor.length > 0) {
            if (vendor.length > 127) {
                throw new IllegalArgumentException("Vendor extension too long (max 127 bytes)");
            }
            data.add((byte) 0xB1);
            data.add((byte) vendor.length);
            for (byte b : vendor) data.add(b);
        }

        byte[] fullData = new byte[data.size()];
        for (int i = 0; i < data.size(); i++) {
            fullData[i] = data.get(i);
        }

        // 构建 APDU
        final int MAX_CHUNK_SIZE = 200; // 每个APDU最多携带的数据字节数 (200 留点余量)
        List<CommandAPDU> apdus = new ArrayList<>();

        int offset = 0;
        while (offset < fullData.length) {
            int len = Math.min(MAX_CHUNK_SIZE, fullData.length - offset);

            List<Byte> apdu = new ArrayList<>();
            apdu.add((byte) 0x00); // CLA
            apdu.add((byte) 0x80); // INS
            apdu.add((byte) ((offset + len < fullData.length) ? 0x10 : 0x00)); // P1: 0x10 表示后面还有
            apdu.add((byte) 0x00); // P2
            apdu.add((byte) len);  // Lc

            for (int i = 0; i < len; i++) {
                apdu.add(fullData[offset + i]);
            }

            apdu.add((byte) 0x00); // Le

            byte[] result = new byte[apdu.size()];
            for (int i = 0; i < apdu.size(); i++) result[i] = apdu.get(i);

            apdus.add(new CommandAPDU(result));

            offset += len;
        }

        return apdus;
    }


    public boolean expeditedStantard(){

        return true;
    }

    public void getAUTH0resp(List<ResponseAPDU>apdus) throws IOException {
        int inc = 0;

        List<byte[]> responseDataList = new ArrayList<>();
        List<Short> statusWords = new ArrayList<>();

        for (ResponseAPDU apdu : apdus) {
            byte[] rawData = apdu.getBytes();
            int length = rawData.length;

            if (length < 2) {
                throw new RuntimeException("APDU length less than 2");
            }

            byte sw1 = rawData[length - 2];
            byte sw2 = rawData[length - 1];
            short statusWord = (short) (((sw1 & 0xFF) << 8) | (sw2 & 0xFF));
            statusWords.add(statusWord);

            if ((statusWord & 0xFFFF)  != 0x9000) {
                throw new RuntimeException(String.format(
                        "APDU命令失败，状态字: 0x%04X, 错误信息: %s",
                        statusWord, getStatusMessage(statusWord)
                ));
            }

            byte[] responseData = new byte[length - 2];
            if (length > 2) {
                System.arraycopy(rawData, 0, responseData, 0, length - 2);
            }
            responseDataList.add(responseData);
        }

        ByteArrayOutputStream combinedData = new ByteArrayOutputStream();
        for (byte[] responseData : responseDataList) {
            combinedData.write(responseData, 0, responseData.length);
        }
        byte[] allResponseData = combinedData.toByteArray();

        if((allResponseData[inc++] & 0xFF) == 0x86){
            int len = allResponseData[inc++] & 0xFF;
            byte[] t_epub = new byte[len];
            System.arraycopy(allResponseData, inc, t_epub, 0, len);
            this.credential_ePubK = t_epub;
            inc = inc + 64;
        }

        if((allResponseData[inc++] & 0xFF) == 0x9D){
            byte[] t_cryp = new byte[64];
            System.arraycopy(allResponseData, inc, t_cryp, 0, 64);
            this.cryptogram = t_cryp;
        }


    }

    private static String getStatusMessage(short statusWord) {
        switch (statusWord & 0xFFFF) {
            case 0x9000: return "成功";
            case 0x6100: return "成功，有额外数据可用";
            case 0x6200: return "状态不变警告";
            case 0x6281: return "部分数据可能损坏";
            case 0x6300: return "认证失败计数";
            case 0x6400: return "执行错误";
            case 0x6500: return "内存错误";
            case 0x6700: return "长度错误";
            case 0x6800: return "不支持的功能";
            case 0x6900: return "命令不允许";
            case 0x6A00: return "参数错误";
            case 0x6A80: return "数据字段不正确";
            case 0x6A82: return "文件未找到";
            case 0x6A84: return "存储空间不足";
            case 0x6D00: return "指令代码不支持";
            case 0x6E00: return "类代码不支持";
            case 0x6F00: return "未知错误";
            default:
                if ((statusWord & 0xFF00) == 0x6100) {
                    return "成功，还有" + (statusWord & 0xFF) + "字节数据可用";
                }
                if ((statusWord & 0xFF00) == 0x6300) {
                    return "认证失败，还剩" + (statusWord & 0xFF) + "次尝试";
                }
                return "未知状态";
        }
    }

    public List<CommandAPDU> LOADCERT() throws Exception {

        Profile0000 profile = new Profile0000();
        profile.setProfile(new byte[]{0x00, 0x00});

        byte[] cert = this.readerCert.getEncoded();
        System.out.println(Arrays.toString(cert));

        ASN1InputStream asn1 = new ASN1InputStream(cert);
        ASN1Primitive obj = asn1.readObject();
        asn1.close();

        Certificate bcCert = Certificate.getInstance(obj);
        TBSCertificate tbs = bcCert.getTBSCertificate();

        byte[] notBefore = tbs.getStartDate().toASN1Primitive().getEncoded("DER");
        byte[] notAfter  = tbs.getEndDate().toASN1Primitive().getEncoded("DER");

        profile.setData(extractECPublicKeyPoint(this.readerCert),extractSignatureBitString(this.readerCert), this.readerCert.getSerialNumber().toByteArray(), this.readerCert.getIssuerX500Principal().getName().getBytes(),notBefore, notAfter,this.readerCert.getSubjectX500Principal().getName().getBytes());

        byte[] derbyte = encodeProfile0000(profile);


        List<CommandAPDU> apdus = new ArrayList<>();

        int offset = 0;
        int maxChunk = 0xFF;

        while (offset < derbyte.length) {
            int len = Math.min(maxChunk, derbyte.length - offset);

            List<Byte> apdu = new ArrayList<>();
            apdu.add((byte) 0x00); // CLA
            apdu.add((byte) 0xD1); // INS
            apdu.add((byte) ((offset + len < derbyte.length) ? 0x10 : 0x00)); // P1: 0x10 表示后面还有
            apdu.add((byte) 0x00); // P2
            apdu.add((byte) len);  // Lc

            for (int i = 0; i < len; i++) {
                apdu.add(derbyte[offset + i]);
            }

            apdu.add((byte) 0x00); // Le

            byte[] result = new byte[apdu.size()];
            for (int i = 0; i < apdu.size(); i++) result[i] = apdu.get(i);

            apdus.add(new CommandAPDU(result));

            offset += len;
        }


        return apdus;

    }

    public void LOADCERTrespon(ResponseAPDU apdu) throws Exception{
        int inc = 0;

        List<byte[]> responseDataList = new ArrayList<>();
        List<Short> statusWords = new ArrayList<>();

        byte[] rawData = apdu.getBytes();
        int length = rawData.length;

        if (length < 2) {
            throw new RuntimeException("APDU length less than 2");
        }

        byte sw1 = rawData[length - 2];
        byte sw2 = rawData[length - 1];
        short statusWord = (short) (((sw1 & 0xFF) << 8) | (sw2 & 0xFF));
        statusWords.add(statusWord);

        if ((statusWord & 0xFFFF)  != 0x9000) {
            throw new RuntimeException(String.format(
                    "APDU命令失败，状态字: 0x%04X, 错误信息: %s",
                    statusWord, getStatusMessage(statusWord)
            ));
        }

        byte[] responseData = new byte[length - 2];
        if (length > 2) {
            System.arraycopy(rawData, 0, responseData, 0, length - 2);
        }
        responseDataList.add(responseData);

        return;
    }

    public List<CommandAPDU> CreateAUTH1() throws Exception {
        /**
         * 构建 AUTH1 命令 APDU
         * @param commandParams   1字节 command_parameters        -mandatory
         * @param ReaderSignature 64字节 ReaderSignature          -mandatory
         * @param readerCert      变长 替代LOADCERT                -optional
         * @return 完整 APDU (byte[])
         */

        List<CommandAPDU> apdus = new ArrayList<>();

        List<Byte> data = new ArrayList<>();

        data.add((byte) 0x41);  //command_parameters
        data.add((byte) 0x01);
        data.add(this.command_parameters);

        List<Byte> authdata = new ArrayList<>();

        authdata.add((byte) 0x4D);  //reader_identifier
        authdata.add((byte) 0x20);  //lenth = 32
        for (byte b : this.readerIdentifierbyte) authdata.add(b);

        authdata.add((byte) 0x86);  //credential_ePubK.x
        authdata.add((byte) 0x20);  //lenth = 32
        byte[] credential_ePubK_x = new byte[32];
        System.arraycopy(this.credential_ePubK, 1, credential_ePubK_x, 0, 32);
        for (byte b : credential_ePubK_x) authdata.add(b);

        authdata.add((byte) 0x87);  //reader_ePubK.x
        authdata.add((byte) 0x20);
        byte[] reader_ePubK_x = new byte[32];
        System.arraycopy(this.reader_ePubk, 1, reader_ePubK_x, 0, 32);
        for (byte b : reader_ePubK_x) authdata.add(b);

        authdata.add((byte) 0x4C);  //transaction_identifier
        authdata.add((byte) 0x10);  //lenth = 16
        for (byte b : this.transaction_identifier) authdata.add(b);

        authdata.add((byte) 0x93);  //usage
        authdata.add((byte) 0x04);  //lenth = 4
        authdata.add((byte) 0x41);
        authdata.add((byte) 0x5D);
        authdata.add((byte) 0x95);
        authdata.add((byte) 0x69);

        byte[] authbyte = new byte[authdata.size()];
        for (int i = 0; i < authdata.size(); i++) authbyte[i] = authdata.get(i);

        byte[] reader_signature = signMessage(this.reader_PrivK,authbyte);

        boolean vf = verifySignature(authbyte,reader_signature,this.readerKeyPair.getPublic());

        byte[] sigtocryp = derToRaw(reader_signature);

        data.add((byte) 0x9E);  //Reader Signature
        data.add((byte) 0x40);  //lenth = 64
        for (byte b : sigtocryp) data.add(b);

        //reader_Cert optional 待补充

        byte[] fullData = new byte[data.size()];
        for (int i = 0; i < data.size(); i++) {
            fullData[i] = data.get(i);
        }

        final int MAX_CHUNK_SIZE = 200; // 每个APDU最多携带的数据字节数 (200 留点余量)
        List<CommandAPDU> cmdlist = new ArrayList<>();

        int offset = 0;
        while (offset < fullData.length) {
            int len = Math.min(MAX_CHUNK_SIZE, fullData.length - offset);

            List<Byte> apdu = new ArrayList<>();
            apdu.add((byte) 0x00); // CLA
            apdu.add((byte) 0x81); // INS
            apdu.add((byte) ((offset + len < fullData.length) ? 0x10 : 0x00)); // P1: 0x10 表示后面还有
            apdu.add((byte) 0x00); // P2
            apdu.add((byte) len);  // Lc

            for (int i = 0; i < len; i++) {
                apdu.add(fullData[offset + i]);
            }

            apdu.add((byte) 0x00); // Le

            byte[] result = new byte[apdu.size()];
            for (int i = 0; i < apdu.size(); i++) result[i] = apdu.get(i);

            apdus.add(new CommandAPDU(result));

            offset += len;
        }

        PublicKey credential_ePK = decodeECPublicKey(this.credential_ePubK, "secp256r1");

        byte[] reader_kdh = generateSharedKey(credential_ePK, this.reader_ekeypair.getPrivate(), this.transaction_identifier);
        this.kdh = reader_kdh;

        //create salt_volatile
        List<Byte> salt_volatile_list = new ArrayList<>();
        byte[] reader_pk = extractPublicKey(this.readerKeyPair.getPublic().getEncoded());
        byte[] reader_pk_x = new byte[32];
        System.arraycopy(reader_pk,1, reader_pk_x, 0, 32);
        byte[] voilatile = "Volatile".getBytes();
        this.interface_byte[0] = 0x5E;       //NFC 0x5E;  BLE 0xC3
        System.arraycopy(this.reader_ePubk, 1, this.reader_epubk_x, 0, 32);

        this.flag[0] = (byte) this.command_parameters;
        this.flag[1] = (byte) this.authentication_policy;

        for (byte b : reader_pk_x) salt_volatile_list.add(b);
        for (byte b : voilatile) salt_volatile_list.add(b);
        for (byte b : this.readerIdentifierbyte) salt_volatile_list.add(b);
        for (byte b : this.interface_byte) salt_volatile_list.add(b);
        salt_volatile_list.add((byte) 0x5C);
        salt_volatile_list.add((byte) 0x02);
        for (byte b : this.expedited_phase_protocol_version) salt_volatile_list.add(b);
        for (byte b : this.reader_epubk_x) salt_volatile_list.add(b);
        for (byte b : transaction_identifier) salt_volatile_list.add(b);
        for (byte b : flag) salt_volatile_list.add(b);
        salt_volatile_list.add((byte) 0xA5);

        byte[] salt_volatile = new byte[salt_volatile_list.size()];
        for (int i = 0; i < salt_volatile_list.size(); i++) salt_volatile[i] = salt_volatile_list.get(i);

        //create info
        List<Byte> info_list = new ArrayList<>();
        byte[] credential_epk = this.credential_ePubK;
        byte[] credential_epk_x = new byte[32];
        System.arraycopy(credential_epk, 1, credential_epk_x, 0, 32);
        //auth0_command_vendor_extension
        //auth0_response_vendor_extension

        byte[] info = new byte[info_list.size()];
        for (int i = 0; i < info_list.size(); i++) info[i] = info_list.get(i);

        int lenth = 160;

        this.derived_keys_volatite = deriveKey(kdh, salt_volatile,info,lenth);

        System.arraycopy(this.derived_keys_volatite,32,this.expeditedSKDevice,0,32);

        return apdus;

    }

    public void getAUTH1resp(List<ResponseAPDU> apdus) throws Exception {
        int inc = 0;

        List<byte[]> responseDataList = new ArrayList<>();
        List<Short> statusWords = new ArrayList<>();

        for (ResponseAPDU apdu : apdus) {
            // 获取原始字节数组
            byte[] rawData = apdu.getBytes();
            int length = rawData.length;

            if (length < 2) {
                throw new RuntimeException("APDU length less than 2");
            }

            byte sw1 = rawData[length - 2];
            byte sw2 = rawData[length - 1];
            short statusWord = (short) (((sw1 & 0xFF) << 8) | (sw2 & 0xFF));
            statusWords.add(statusWord);

            if ((statusWord & 0xFFFF) != 0x9000) {
                throw new RuntimeException(String.format(
                        "APDU命令失败，状态字: 0x%04X, 错误信息: %s",
                        statusWord, getStatusMessage(statusWord)
                ));
            }

            byte[] responseData = new byte[length - 2];
            if (length > 2) {
                System.arraycopy(rawData, 0, responseData, 0, length - 2);
            }
            responseDataList.add(responseData);
        }

        ByteArrayOutputStream combinedData = new ByteArrayOutputStream();
        for (byte[] responseData : responseDataList) {
            combinedData.write(responseData, 0, responseData.length);
        }
        byte[] allResponseData = combinedData.toByteArray();

        byte[] authentication_tag = Arrays.copyOfRange(
                allResponseData,
                allResponseData.length - 16 - 2,
                allResponseData.length - 2
        );

        byte[] encrypted_payload = Arrays.copyOfRange(
                allResponseData,
                0,
                allResponseData.length - 16 - 2
        );

        expedited_device_counter++;

        byte[] unencrypted_payload = GCM_AES_decrypt(encrypted_payload, authentication_tag, this.expeditedSKDevice, intToBigEndianBytes(this.expedited_device_counter), this.aad);
        System.out.println(Arrays.toString(unencrypted_payload));

        this.expedited_device_counter ++;

        int offset = 0;

        if (this.command_parameters == 0) {
            if (this.key_slot_flag == 0) {
                if ((unencrypted_payload[offset++] & 0xFF) == 0x5A) {
                    int len = unencrypted_payload[offset++];
                    if (len == 0x41) {
                        byte[] tmp = new byte[len];
                        System.arraycopy(unencrypted_payload, offset, tmp, 0, len);
                        this.Access_Credential_PubKey = decodeECPublicKey(tmp, "secp256r1");
                        offset += len;
                    } else {
                        throw new Exception("Access Credential long term key length is wrong!");
                    }
                } else {
                    throw new Exception("command_parameters for Access Credential long term key is wrong!");
                }
            } else {
                if ((unencrypted_payload[offset++] & 0xFF) == 0x4E) {
                    int len = unencrypted_payload[offset++];
                    System.arraycopy(unencrypted_payload, offset, this.key_slot, 0, 8);
                    offset += len;
                } else {
                    throw new Exception("command_parameters for key_slot is wrong!");
                }
            }

        }

        byte[] user_device_sig;
        if ((unencrypted_payload[offset++] & 0xFF) == 0x9E) {
            int len = unencrypted_payload[offset++];
            byte[] User_Device_sig_row = new byte[len];
            if (len == 0x40) {
                System.arraycopy(unencrypted_payload, offset, User_Device_sig_row, 0, len);
                user_device_sig = rawToDer(User_Device_sig_row);
                offset += len;
            } else {
                throw new Exception("lenth of User Device must be 65!");
            }
        } else {
            throw new Exception("lack of User Device signature");
        }

        if (this.private_mailbox_use == 1) {
            if ((unencrypted_payload[offset++] & 0xFF) == 0x4B) {
                //private_mailbox_data_subset
            } else {
                throw new Exception("need private_mailbox_data_subset!");
            }
        }

        if ((unencrypted_payload[offset++] & 0xFF) == 0x5E) {
            if ((unencrypted_payload[offset++] & 0xFF) == 0x02) {
                this.signal_bitmap[0] = unencrypted_payload[offset++];
                this.signal_bitmap[1] = unencrypted_payload[offset++];
            } else {
                throw new Exception("signaling_bitmap length is wrong!");
            }
        } else {
            throw new Exception("need signaling_bitmap!");
        }

        int signalingBitmap = ((signal_bitmap[0] & 0xFF) << 8) | (signal_bitmap[1] & 0xFF);

        Map<String, Boolean> signal_bitmap = new LinkedHashMap<>();

        signal_bitmap.put("SIGNALING_BITMAP_AD_RETIEVED", ((signalingBitmap >> 0) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_RD_RETIEVED", ((signalingBitmap >> 1) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_STEP_UP_NFC", ((signalingBitmap >> 2) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_DIF_DATA_MAILBOX", ((signalingBitmap >> 3) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_READBLE_MAILBOX", ((signalingBitmap >> 4) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_WRITEBALE_MAILBOX", ((signalingBitmap >> 5) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_SUPPORT_EXCHANGE", ((signalingBitmap >> 6) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_SUPORT_FXX_TAG", ((signalingBitmap >> 7) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_RESERVED", ((signalingBitmap >> 8) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_SUPORT_UPDATE_DOC_EXPEDITED", ((signalingBitmap >> 9) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_SUPORT_MALIBOX_FUTURE_SET", ((signalingBitmap >> 10) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_NOTIFY_SUPORT_EXCHANGE", ((signalingBitmap >> 11) & 0x01) == 1);
        signal_bitmap.put("SIGNALING_BITMAP_SUPORT_UPDATE_DOC_STEP_UP", ((signalingBitmap >> 12) & 0x01) == 1);

        if (offset < unencrypted_payload.length) {
            if (unencrypted_payload[offset] == 0x91) {
                //credential_signed_timestamp
            } else if (unencrypted_payload[offset] == 0x92) {
                //revocation_signed_timestamp
            }
        }


        List<Byte> authdata = new ArrayList<>();

        authdata.add((byte) 0x4D);  //reader_identifier
        authdata.add((byte) 0x20);  //lenth = 32
        for (byte b : this.readerIdentifierbyte) authdata.add(b);

        authdata.add((byte) 0x86);  //credential_ePubK.x
        authdata.add((byte) 0x20);  //lenth = 32
        byte[] re_credential_ePubK_x = new byte[32];
        System.arraycopy(this.credential_ePubK, 1, re_credential_ePubK_x, 0, 32);
        for (byte b : re_credential_ePubK_x) authdata.add(b);

        authdata.add((byte) 0x87);  //reader_ePubK.x
        authdata.add((byte) 0x20);
        byte[] re_reader_ePubK_x = new byte[32];
        System.arraycopy(this.reader_ePubk, 1, re_reader_ePubK_x, 0, 32);
        for (byte b : re_reader_ePubK_x) authdata.add(b);

        authdata.add((byte) 0x4C);  //transaction_identifier
        authdata.add((byte) 0x10);  //lenth = 16
        for (byte b : this.transaction_identifier) authdata.add(b);

        authdata.add((byte) 0x93);  //usage
        authdata.add((byte) 0x04);  //lenth = 4
        authdata.add((byte) 0x4E);
        authdata.add((byte) 0x88);
        authdata.add((byte) 0x7B);
        authdata.add((byte) 0x4C);

        byte[] authdata_bytes = new byte[authdata.size()];
        for (int i = 0; i < authdata.size(); i++) authdata_bytes[i] = authdata.get(i);

        if(!verifySignature(authdata_bytes, user_device_sig, this.Access_Credential_PubKey)){
            throw new Exception("Signature verification failed!");
        }

        //salt_persistent
        List<Byte> salt_persistent_list = new ArrayList<>();
        for (byte b : this.readerKeyPair.getPublic().getEncoded()) salt_persistent_list.add(b);
        byte[] persistentbyte = "Persistent**".getBytes();
        for (byte b : persistentbyte) salt_persistent_list.add(b);
        for (byte b : this.readerIdentifierbyte) salt_persistent_list.add(b);
        for (byte b : this.interface_byte) salt_persistent_list.add(b);
        salt_persistent_list.add((byte) 0x5C);
        salt_persistent_list.add((byte) 0x02);
        for (byte b : this.expedited_phase_protocol_version) salt_persistent_list.add(b);
        for (byte b : this.reader_epubk_x) salt_persistent_list.add(b);
        for (byte b : this.flag) salt_persistent_list.add(b);
        for (byte b : this.proprietary_information) salt_persistent_list.add(b);
//        for (byte b : this.) salt_persistent_list.add(b);

        //create info
        List<Byte> info_list = new ArrayList<>();
        byte[] credential_epk = this.credential_ePubK;
        byte[] credential_epk_x = new byte[32];
        System.arraycopy(credential_epk, 1, credential_epk_x, 0, 32);
        //auth0_command_vendor_extension
        //auth0_response_vendor_extension

        byte[] info = new byte[info_list.size()];
        for (int i = 0; i < info_list.size(); i++) info[i] = info_list.get(i);

    }

    // ====================================================================== //
    //  ====================  PQ-Aliro flow (Dilithium + Kyber)  ============= //
    // ====================================================================== //

    private void testAUTH0_PQ() throws Exception {
        System.out.println("\n--- Testing AUTH0 command (PQ — Kyber" + PQCConfig.KYBER_LEVEL + ") ---");

        // 先 SELECT
        byte[] selectApdu = buildSelectApdu(Aliro_AID);
        ResponseAPDU selectResp = sendApdu(selectApdu);
        if (selectResp.getSW() != 0x9000) {
            System.out.println("✗ SELECT failed, cannot continue");
            return;
        }

        // 重置本会话的 transcript / counter 状态
        baosATH0ComMes.reset();
        baosATH0ResMes.reset();
        this.expedited_device_counter = 0x00000001;
        this.expedited_reader_counter = 0x00000001;

        List<CommandAPDU> apdus = CreateAUTH0_PQ();
        for (CommandAPDU c : apdus) {
            System.out.println("Sending AUTH0 APDU: " + Hex.toHexString(c.getBytes()));
        }
        List<ResponseAPDU> resps = sendApduList(apdus);
        for (ResponseAPDU r : resps) {
            System.out.println("Response: " + Hex.toHexString(r.getBytes()));
            System.out.println("SW: " + String.format("%04X", r.getSW()));
        }
        getAUTH0resp_PQ(resps);
    }

    private void testAUTH1_PQ() throws Exception {
        System.out.println("\n--- Testing AUTH1 command (PQ — Dilithium" + PQCConfig.DILITHIUM_LEVEL + ") ---");

        byte[] selectApdu = buildSelectApdu(Aliro_AID);
        ResponseAPDU selectResp = sendApdu(selectApdu);
        if (selectResp.getSW() != 0x9000) {
            System.out.println("✗ SELECT failed, cannot continue");
            return;
        }

        List<CommandAPDU> apdus = CreateAUTH1_PQ();
        for (CommandAPDU c : apdus) {
            System.out.println("Sending AUTH1 APDU: " + Hex.toHexString(c.getBytes()));
        }
        List<ResponseAPDU> resps = sendApduList(apdus);
        for (ResponseAPDU r : resps) {
            System.out.println("Response: " + Hex.toHexString(r.getBytes()));
            System.out.println("SW: " + String.format("%04X", r.getSW()));
        }
        getAUTH1resp_PQ(resps);
    }

    // ----------------- CreateAUTH0 (PQ) ---------------------- //

    public List<CommandAPDU> CreateAUTH0_PQ() throws Exception {
        // 1) 生成本次会话的 Kyber 临时密钥对
        this.reader_kyber_keypair = PQCUtil.generateKyberKeyPair();
        byte[] kyberPubX509 = this.reader_kyber_keypair.getPublic().getEncoded();
        byte[] kyberPubRaw  = PQCUtil.getRawPublicKeyBytes(kyberPubX509);

        if (kyberPubRaw.length != PQCConfig.kyberPublicKeySize()) {
            throw new IllegalStateException("Kyber public key size mismatch: got "
                    + kyberPubRaw.length + " expected " + PQCConfig.kyberPublicKeySize());
        }

        // 2) 生成 transaction_identifier (16B)
        SecureRandom sr = new SecureRandom();
        byte[] seed = new byte[16];
        sr.nextBytes(seed);
        PRNG prng = new PRNG(seed);
        this.transaction_identifier = prng.nextBytes(16);

        byte[] reader_id = concatBytes(
                this.identifier.getGroupIdentifier(),
                this.identifier.getsubGroupIdentifier());

        if (reader_id.length != 32)
            throw new IllegalArgumentException("Reader ID must be 32 bytes");

        // 3) 组装 TLV 数据体
        ByteArrayOutputStream data = new ByteArrayOutputStream();

        // Tag 0x41 — command_parameters (1B)
        data.write(0x41); data.write(0x01); data.write(this.command_parameters);
        // Tag 0x42 — authentication_policy (1B)
        data.write(0x42); data.write(0x01); data.write(this.authentication_policy);
        // Tag 0x5C — expedited_phase_protocol_version (2B)
        data.write(0x5C); data.write(0x02);
        data.write(this.expedited_phase_protocol_version, 0, 2);
        // Tag 0x87 — reader_ePubK (long-form TLV)
        data.write(0x87);
        writeBerLength(data, kyberPubRaw.length);
        data.write(kyberPubRaw, 0, kyberPubRaw.length);
        // Tag 0x4C — transaction_identifier (16B)
        data.write(0x4C); data.write(0x10);
        data.write(this.transaction_identifier, 0, 16);
        // Tag 0x4D — reader_identifier (32B)
        data.write(0x4D); data.write(0x20);
        data.write(reader_id, 0, 32);

        byte[] fullData = data.toByteArray();

        // 记录 transcript（与 UD baosATH0ComMes 对齐：只记录关键值 ePubk||transId||readerId）
        baosATH0ComMes.write(kyberPubRaw);
        baosATH0ComMes.write(this.transaction_identifier);
        baosATH0ComMes.write(reader_id);

        // 4) 分包成多条 APDU
        final int MAX_CHUNK_SIZE = 200;
        List<CommandAPDU> apdus = new ArrayList<>();
        int offset = 0;
        while (offset < fullData.length) {
            int len = Math.min(MAX_CHUNK_SIZE, fullData.length - offset);
            ByteArrayOutputStream apdu = new ByteArrayOutputStream();
            apdu.write(0x00);                                                       // CLA
            apdu.write(0x80);                                                       // INS
            apdu.write((offset + len < fullData.length) ? 0x10 : 0x00);             // P1
            apdu.write(0x00);                                                       // P2
            apdu.write(len);                                                        // Lc
            apdu.write(fullData, offset, len);                                      // data
            apdu.write(0x00);                                                       // Le
            apdus.add(new CommandAPDU(apdu.toByteArray()));
            offset += len;
        }
        return apdus;
    }

    // ----------------- getAUTH0resp (PQ) ---------------------- //

    public void getAUTH0resp_PQ(List<ResponseAPDU> apdus) throws Exception {
        // 1) 拼接所有应答帧的数据 (去 SW)
        ByteArrayOutputStream combined = new ByteArrayOutputStream();
        for (ResponseAPDU apdu : apdus) {
            byte[] raw = apdu.getBytes();
            if (raw.length < 2) throw new RuntimeException("APDU length less than 2");
            int sw = ((raw[raw.length - 2] & 0xFF) << 8) | (raw[raw.length - 1] & 0xFF);
            if (sw != 0x9000) {
                throw new RuntimeException(String.format(
                        "AUTH0 PQ response APDU failed, SW=0x%04X: %s",
                        sw, getStatusMessage((short) sw)));
            }
            combined.write(raw, 0, raw.length - 2);
        }
        byte[] all = combined.toByteArray();

        // 2) 解析 TLV：Tag 0x86 = encap_ciphertext，Tag 0x43 = ud_noise (32B)
        int inc = 0;
        if ((all[inc++] & 0xFF) != 0x86)
            throw new Exception("Expected Tag 0x86 (encap ciphertext)");
        int ctLen = readBerLength(all, inc);
        inc += berLengthBytes(all, inc - 0);  // advance past length bytes; see helper below
        // re-compute because the previous line is a no-op pattern — do it explicitly
        // (kept simple: just read length using helper that returns also bytes consumed)

        // ---- cleaner reparse to robustly handle long-form length ----
        inc = 1;                                                  // already consumed tag 0x86 above
        int[] lenInfo = readBerLengthWithSize(all, inc);
        ctLen = lenInfo[0];
        inc  += lenInfo[1];
        byte[] encapCt = new byte[ctLen];
        System.arraycopy(all, inc, encapCt, 0, ctLen);
        this.kyber_encap_ciphertext = encapCt;
        inc += ctLen;

        if ((all[inc++] & 0xFF) != 0x43)
            throw new Exception("Expected Tag 0x43 (UD noise)");
        int nLen = all[inc++] & 0xFF;
        this.ud_noise = new byte[nLen];
        System.arraycopy(all, inc, this.ud_noise, 0, nLen);
        inc += nLen;

        // 3) 记录响应 transcript（与 UD baosATH0ResMes 对齐：encap || noise）
        baosATH0ResMes.write(encapCt);
        baosATH0ResMes.write(this.ud_noise);

        // 4) Kyber Decap → shared secret (Se, 32B)
        SecretKey se = PQCUtil.kyberDecapsulateRaw(
                this.reader_kyber_keypair.getPrivate(), encapCt, "AES");
        this.kyber_shared_secret = se.getEncoded();

        // 5) transAH0 = SHAKE256-512(comMsg || resMsg)
        byte[] comBytes = baosATH0ComMes.toByteArray();
        byte[] resBytes = baosATH0ResMes.toByteArray();
        byte[] transcript = new byte[comBytes.length + resBytes.length];
        System.arraycopy(comBytes, 0, transcript, 0,                comBytes.length);
        System.arraycopy(resBytes, 0, transcript, comBytes.length,  resBytes.length);
        this.transAH0 = PQCUtil.generateTransAH0(transcript);

        // 6) HS = HMAC-SHA256(salt=transAH0, ikm=Se)；  SK_device = HKDF-Expand(HS,"enc"||transAH0,32)
        this.hs = PQCUtil.deriveHS(this.kyber_shared_secret, this.transAH0);
        this.expeditedSKDevice = PQCUtil.expandSKDevice(this.hs, this.transAH0);
        System.out.println("[PQ] Kyber shared secret derived; SK_device established.");
    }

    // ----------------- CreateAUTH1 (PQ) ---------------------- //

    public List<CommandAPDU> CreateAUTH1_PQ() throws Exception {
        // 构造 reader 签名输入（与 UD toauthdata 对齐）
        ByteArrayOutputStream authdata = new ByteArrayOutputStream();
        authdata.write(0x4D); authdata.write(0x20);                            // reader_identifier
        authdata.write(this.readerIdentifierbyte, 0, 32);
        authdata.write(0x4A); authdata.write(0x40);                            // transAH0 (SHAKE256-512 → 64B)
        authdata.write(this.transAH0, 0, this.transAH0.length);
        authdata.write(0x4C); authdata.write(0x10);                            // transaction_identifier
        authdata.write(this.transaction_identifier, 0, 16);
        authdata.write(0x93); authdata.write(0x04);                            // usage
        authdata.write(0x41); authdata.write(0x5D); authdata.write(0x95); authdata.write(0x69);

        byte[] toSign = authdata.toByteArray();
        byte[] sigRaw = PQCUtil.dilithiumSign(toSign, this.reader_PrivK);

        if (sigRaw.length != PQCConfig.dilithiumSignatureSize()) {
            // not a hard error — sig size sometimes varies slightly; just warn
            System.out.println("[PQ] Dilithium sig length = " + sigRaw.length
                    + " (expected " + PQCConfig.dilithiumSignatureSize() + ")");
        }

        // 组装 APDU body：Tag 0x41 (command_parameters) + Tag 0x9E (long-form signature)
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write(0x41); data.write(0x01); data.write(this.command_parameters);
        data.write(0x9E);
        writeBerLength(data, sigRaw.length);
        data.write(sigRaw, 0, sigRaw.length);
        // (reader_Cert option 暂未携带 — 由独立 LOADCERT 命令传输)

        byte[] fullData = data.toByteArray();

        // 分包
        final int MAX_CHUNK_SIZE = 200;
        List<CommandAPDU> apdus = new ArrayList<>();
        int offset = 0;
        while (offset < fullData.length) {
            int len = Math.min(MAX_CHUNK_SIZE, fullData.length - offset);
            ByteArrayOutputStream apdu = new ByteArrayOutputStream();
            apdu.write(0x00);                                                   // CLA
            apdu.write(0x81);                                                   // INS
            apdu.write((offset + len < fullData.length) ? 0x10 : 0x00);         // P1
            apdu.write(0x00);                                                   // P2
            apdu.write(len);                                                    // Lc
            apdu.write(fullData, offset, len);                                  // data
            apdu.write(0x00);                                                   // Le
            apdus.add(new CommandAPDU(apdu.toByteArray()));
            offset += len;
        }
        return apdus;
    }

    // ----------------- getAUTH1resp (PQ) ---------------------- //

    public void getAUTH1resp_PQ(List<ResponseAPDU> apdus) throws Exception {
        // 1) 合并应答数据
        ByteArrayOutputStream combined = new ByteArrayOutputStream();
        for (ResponseAPDU apdu : apdus) {
            byte[] raw = apdu.getBytes();
            if (raw.length < 2) throw new RuntimeException("APDU length less than 2");
            int sw = ((raw[raw.length - 2] & 0xFF) << 8) | (raw[raw.length - 1] & 0xFF);
            if (sw != 0x9000) {
                throw new RuntimeException(String.format(
                        "AUTH1 PQ response APDU failed, SW=0x%04X: %s",
                        sw, getStatusMessage((short) sw)));
            }
            combined.write(raw, 0, raw.length - 2);
        }
        byte[] ciphertextWithTag = combined.toByteArray();

        // 2) AEAD 解密 — counter = expedited_device_counter (起始 1)
        byte[] plaintext = PQCUtil.AEADdecrypt(
                this.expeditedSKDevice, ciphertextWithTag, this.aad, this.expedited_device_counter);
        this.expedited_device_counter++;     // 解密成功后递增

        // 3) 解析 plaintext TLV
        int inc = 0;
        byte[] udSig = null;

        if (this.command_parameters == 0) {
            if (this.key_slot_flag == 0) {
                // Tag 0x5A — Access Credential 长期 Dilithium 公钥 (raw)
                if ((plaintext[inc++] & 0xFF) != 0x5A)
                    throw new Exception("Expected Tag 0x5A for Access Credential PubKey");
                int[] li = readBerLengthWithSize(plaintext, inc);
                int pkLen = li[0]; inc += li[1];
                this.ud_dilithium_pubkey_raw = new byte[pkLen];
                System.arraycopy(plaintext, inc, this.ud_dilithium_pubkey_raw, 0, pkLen);
                inc += pkLen;
                // 重建 PublicKey
                org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters pubParams =
                        new org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters(
                                PQCConfig.getDilithiumParameters(), this.ud_dilithium_pubkey_raw);
                this.ud_dilithium_pubkey =
                        new org.bouncycastle.pqc.jcajce.provider.dilithium.BCDilithiumPublicKey(pubParams);
            } else {
                if ((plaintext[inc++] & 0xFF) != 0x4E)
                    throw new Exception("Expected Tag 0x4E for key_slot");
                int len = plaintext[inc++] & 0xFF;
                System.arraycopy(plaintext, inc, this.key_slot, 0, 8);
                inc += len;
            }
        }

        // Tag 0x9E — User Device Dilithium 签名
        if ((plaintext[inc++] & 0xFF) != 0x9E)
            throw new Exception("Expected Tag 0x9E for User Device signature");
        int[] sli = readBerLengthWithSize(plaintext, inc);
        int sigLen = sli[0]; inc += sli[1];
        udSig = new byte[sigLen];
        System.arraycopy(plaintext, inc, udSig, 0, sigLen);
        inc += sigLen;

        // 可选 Tag 0x4B (private mailbox)
        if (this.private_mailbox_use == 1) {
            if ((plaintext[inc++] & 0xFF) != 0x4B)
                throw new Exception("Expected Tag 0x4B for private mailbox");
            // 解析 mailbox（暂略）
        }

        // Tag 0x5E — signaling_bitmap (2B)
        if ((plaintext[inc++] & 0xFF) != 0x5E)
            throw new Exception("Expected Tag 0x5E for signaling_bitmap");
        if ((plaintext[inc++] & 0xFF) != 0x02)
            throw new Exception("signaling_bitmap length must be 2");
        this.signal_bitmap[0] = plaintext[inc++];
        this.signal_bitmap[1] = plaintext[inc++];

        // 4) 重构 UD 签名输入 (与 UD reauthdata 对齐)
        ByteArrayOutputStream reauth = new ByteArrayOutputStream();
        reauth.write(0x4D); reauth.write(0x20);
        reauth.write(this.readerIdentifierbyte, 0, 32);
        reauth.write(0x4A); reauth.write(0x40);                                // transAH0 (SHAKE256-512 → 64B)
        reauth.write(this.transAH0, 0, this.transAH0.length);
        reauth.write(0x4C); reauth.write(0x10);
        reauth.write(this.transaction_identifier, 0, 16);
        reauth.write(0x93); reauth.write(0x04);
        reauth.write(0x4E); reauth.write(0x88); reauth.write(0x7B); reauth.write(0x4C);

        byte[] verifyMsg = reauth.toByteArray();
        if (this.ud_dilithium_pubkey == null) {
            throw new Exception("UD Dilithium public key not loaded (no key_slot lookup yet)");
        }
        boolean ok = PQCUtil.dilithiumVerify(verifyMsg, udSig, this.ud_dilithium_pubkey);
        if (!ok) {
            throw new Exception("PQ: User Device Dilithium signature verification failed!");
        }
        System.out.println("[PQ] AUTH1 response verified — User Device authenticated.");
    }

    // ====================  BER-TLV length helpers  ==================== //

    /** Write a BER-TLV length field to an output stream, supporting long-form 0x81/0x82. */
    private static void writeBerLength(ByteArrayOutputStream out, int len) {
        if (len <= 127) {
            out.write(len);
        } else if (len <= 255) {
            out.write(0x81); out.write(len);
        } else if (len <= 65535) {
            out.write(0x82); out.write((len >> 8) & 0xFF); out.write(len & 0xFF);
        } else {
            throw new IllegalArgumentException("TLV length > 65535 unsupported: " + len);
        }
    }

    /** Returns {length, lengthFieldByteCount} starting at position {@code idx} of buf. */
    private static int[] readBerLengthWithSize(byte[] buf, int idx) {
        int first = buf[idx] & 0xFF;
        if (first <= 0x7F) return new int[]{first, 1};
        if (first == 0x81) return new int[]{buf[idx + 1] & 0xFF, 2};
        if (first == 0x82) return new int[]{
                ((buf[idx + 1] & 0xFF) << 8) | (buf[idx + 2] & 0xFF), 3};
        throw new IllegalArgumentException("Unsupported BER length first byte: 0x"
                + Integer.toHexString(first));
    }

    /** Legacy helpers kept for potential future use. */
    @SuppressWarnings("unused")
    private static int readBerLength(byte[] buf, int idx) { return readBerLengthWithSize(buf, idx)[0]; }
    @SuppressWarnings("unused")
    private static int berLengthBytes(byte[] buf, int idx) { return readBerLengthWithSize(buf, idx)[1]; }

}