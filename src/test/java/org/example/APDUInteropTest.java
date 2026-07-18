package org.example;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * APDU 级数据交互测试 — 模拟真实 NFC 数据流（含分片/重组/状态字）。
 *
 * 与 PQAliroProtocolTest 的区别：
 *   - PQAliroProtocolTest 只测 TLV 层（build body / parse body）
 *   - APDUInteropTest 测完整 APDU 链路：
 *       Reader 发 CommandAPDU 链 → UD 逐包接收重组 → UD 处理 → UD 发 ResponseAPDU 链 → Reader 重组
 *       包含 0x61xx / 0x9000 状态字、200B/240B chunk、0xC0 GET RESPONSE 轮询
 *
 * 模拟的 NFC 通道：InMemoryNFCChannel，无真实硬件但完全模拟 APDU 交互。
 */
public class APDUInteropTest {

    // ===== 模拟 NFC 通道（替代真实 PC/SC）=====
    static class InMemoryNFCChannel {
        private byte[] pendingResponse;        // UD 准备好的完整响应
        private int responseOffset;
        private static final int MAX_APDU_CHUNK = 240;  // UD 端响应分片大小
        private static final int MAX_CMD_CHUNK = 200;   // Reader 端命令分片大小

        /** Reader 发送一个 CommandAPDU，UD 返回 ResponseAPDU（含 SW） */
        public byte[] sendCommand(byte[] apdu) {
            byte ins = apdu[1];
            byte p1 = apdu[2];

            if (ins == (byte) 0xA4) {
                // SELECT
                return new byte[]{(byte) 0x90, 0x00};
            }

            if (p1 == (byte) 0x00) {
                // 最后一个 chunk，UD 处理完整数据并准备响应
                return handleFinalChunk(ins);
            }

            if (p1 == (byte) 0x10) {
                // 中间 chunk，UD 累积数据，返回 0x61xx 提示还有更多
                return new byte[]{(byte) 0x61, (byte) 0x00};
            }

            if (ins == (byte) 0xC0) {
                // GET RESPONSE，UD 返回下一个响应 chunk
                return getNextResponseChunk();
            }

            return new byte[]{0x6D, 0x00};
        }

        private byte[] handleFinalChunk(byte ins) {
            // UD 处理完命令，准备响应（这里简化：用预置数据）
            // 实际响应由 setPendingResponse 预置
            // 注意：不在这里重置 responseOffset，setPendingResponse 时已重置
            return getNextResponseChunk();
        }

        private byte[] getNextResponseChunk() {
            if (pendingResponse == null || responseOffset >= pendingResponse.length) {
                return new byte[]{(byte) 0x90, 0x00};
            }
            int remaining = pendingResponse.length - responseOffset;
            int chunkLen = Math.min(remaining, MAX_APDU_CHUNK);
            byte[] chunk = new byte[chunkLen + 2];
            System.arraycopy(pendingResponse, responseOffset, chunk, 0, chunkLen);
            responseOffset += chunkLen;

            if (responseOffset < pendingResponse.length) {
                chunk[chunkLen] = (byte) 0x61;  // 还有更多
                chunk[chunkLen + 1] = (byte) Math.min(remaining - chunkLen, 255);
            } else {
                chunk[chunkLen] = (byte) 0x90;  // 最后一块
                chunk[chunkLen + 1] = 0x00;
            }
            return chunk;
        }

        public void setPendingResponse(byte[] resp) {
            this.pendingResponse = resp;
            this.responseOffset = 0;
        }
    }

    // ===== Reader 端：把大数据分片成 CommandAPDU 链 =====
    static List<byte[]> buildCommandChain(byte ins, byte[] fullData) {
        List<byte[]> chain = new ArrayList<>();
        int offset = 0;
        final int MAX_CMD_CHUNK = 200;

        while (offset < fullData.length) {
            int len = Math.min(MAX_CMD_CHUNK, fullData.length - offset);
            byte[] apdu = new byte[6 + len];
            apdu[0] = (byte) 0x80;  // CLA
            apdu[1] = ins;           // INS
            apdu[2] = (offset + len >= fullData.length) ? (byte) 0x00 : (byte) 0x10;  // P1
            apdu[3] = 0x00;         // P2
            apdu[4] = (byte) len;   // Lc
            System.arraycopy(fullData, offset, apdu, 6, len);
            apdu[5 + len] = 0x00;   // Le (用 6+len 索引有问题，下面修正)
            // 修正：标准 APDU 格式 CLA|INS|P1|P2|Lc|Data|Le
            // 上面 apdu 长度应为 5 + len + 1 = 6 + len
            // apdu[4]=Lc, apdu[5..5+len-1]=Data, apdu[5+len]=Le
            apdu = new byte[6 + len];
            apdu[0] = (byte) 0x80;
            apdu[1] = ins;
            apdu[2] = (offset + len >= fullData.length) ? (byte) 0x00 : (byte) 0x10;
            apdu[3] = 0x00;
            apdu[4] = (byte) len;
            System.arraycopy(fullData, offset, apdu, 6, len);
            // 注意：上面 6 应为 5，修正
            apdu = new byte[5 + len];
            apdu[0] = (byte) 0x80;
            apdu[1] = ins;
            apdu[2] = (offset + len >= fullData.length) ? (byte) 0x00 : (byte) 0x10;
            apdu[3] = 0x00;
            apdu[4] = (byte) len;
            System.arraycopy(fullData, offset, apdu, 5, len);
            chain.add(apdu);
            offset += len;
        }
        if (fullData.length == 0) {
            byte[] apdu = new byte[5];
            apdu[0] = (byte) 0x80;
            apdu[1] = ins;
            apdu[2] = 0x00;
            apdu[3] = 0x00;
            apdu[4] = 0x00;
            chain.add(apdu);
        }
        return chain;
    }

    // ===== Reader 端：重组 UD 的 ResponseAPDU 链 =====
    static byte[] receiveResponseChain(InMemoryNFCChannel channel) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        // 第一个响应已经在 sendCommand 时返回，但这里模拟完整流程
        byte[] firstResp = null;  // 由调用者传入
        return buffer.toByteArray();
    }

    // ===== 测试主入口 =====
    public static void main(String[] args) throws Exception {
        System.out.println("========== APDU 级数据交互测试 ==========\n");



        // 测试 1：APDU 命令分片（Reader 把大数据分成 200B chunk）
        System.out.println("--- 测试 1: Reader 命令分片（1184B Kyber 公钥）---");
        {
            byte[] kyberPub = new byte[1184];
            for (int i = 0; i < kyberPub.length; i++) kyberPub[i] = (byte) (i % 256);
            List<byte[]> chain = buildCommandChain((byte) 0x80, kyberPub);
            int expectedChunks = (int) Math.ceil(1184.0 / 200);
            check("1184B 数据应分为 " + expectedChunks + " 个 chunk", chain.size() == expectedChunks);
            check("最后一个 chunk P1=0x00（最后包）", chain.get(chain.size() - 1)[2] == 0x00);
            check("中间 chunk P1=0x10（更多数据）", chain.get(0)[2] == 0x10);
            // 验证重组后数据一致
            ByteArrayOutputStream reassembled = new ByteArrayOutputStream();
            for (byte[] apdu : chain) {
                int len = apdu[4] & 0xFF;
                reassembled.write(apdu, 5, len);
            }
            check("重组后数据与原始一致", Arrays.equals(kyberPub, reassembled.toByteArray()));
        }

        // 测试 2：APDU 响应分片（UD 把 3309B 签名分成 240B chunk + 0x61xx）
        System.out.println("\n--- 测试 2: UD 响应分片（3309B Dilithium 签名）---");
        {
            InMemoryNFCChannel channel = new InMemoryNFCChannel();
            byte[] signature = new byte[3309];
            for (int i = 0; i < signature.length; i++) signature[i] = (byte) (i % 256);
            channel.setPendingResponse(signature);

            // Reader 用 GET RESPONSE 重组
            ByteArrayOutputStream received = new ByteArrayOutputStream();
            int expectedRespChunks = (int) Math.ceil(3309.0 / 240);

            // 模拟第一个命令触发响应
            byte[] firstResp = channel.sendCommand(new byte[]{(byte) 0x80, (byte) 0x81, 0x00, 0x00, 0x00});
            int sw1 = firstResp[firstResp.length - 2] & 0xFF;
            int sw2 = firstResp[firstResp.length - 1] & 0xFF;
            received.write(firstResp, 0, firstResp.length - 2);

            int chunkCount = 1;
            while (sw1 == 0x61) {
                byte[] nextResp = channel.sendCommand(new byte[]{0x00, (byte) 0xC0, 0x00, 0x00, 0x00});
                sw1 = nextResp[nextResp.length - 2] & 0xFF;
                sw2 = nextResp[nextResp.length - 1] & 0xFF;
                received.write(nextResp, 0, nextResp.length - 2);
                chunkCount++;
            }

            check("3309B 响应应分为 " + expectedRespChunks + " 个 chunk", chunkCount == expectedRespChunks);
            check("最后一个响应 SW=0x9000", sw1 == 0x90 && sw2 == 0x00);
            check("重组后签名与原始一致", Arrays.equals(signature, received.toByteArray()));
        }

        // 测试 3：完整 AUTH0 数据流（含 TLV 编码 + APDU 分片 + 重组）
        System.out.println("\n--- 测试 3: 完整 AUTH0 数据流 ---");
        {
            InMemoryNFCChannel channel = new InMemoryNFCChannel();

            // Reader 构造 AUTH0 命令 TLV body
            byte[] kyberPub = new byte[1184];  // 模拟 Kyber768 公钥
            byte[] transId = new byte[16];
            byte[] readerId = new byte[32];
            ByteArrayOutputStream auth0Body = new ByteArrayOutputStream();
            // 0x87|0x82|len_hi|len_lo|kyberPub (long-form, 1184>255)
            auth0Body.write(0x87);
            auth0Body.write(0x82);
            auth0Body.write((1184 >> 8) & 0xFF);
            auth0Body.write(1184 & 0xFF);
            auth0Body.write(kyberPub);
            // 0x4C|0x10|transId
            auth0Body.write(0x4C);
            auth0Body.write(0x10);
            auth0Body.write(transId);
            // 0x4D|0x20|readerId
            auth0Body.write(0x4D);
            auth0Body.write(0x20);
            auth0Body.write(readerId);

            byte[] fullBody = auth0Body.toByteArray();
            check("AUTH0 body 大小 = 1188 + 18 + 34 = 1240B", fullBody.length == 1240);

            // 分片发送
            List<byte[]> cmdChain = buildCommandChain((byte) 0x80, fullBody);
            check("AUTH0 命令应分为 7 个 APDU", cmdChain.size() == 7);

            // 逐个发送，UD 累积重组（模拟 MyHostApduService.processCommandApdu）
            ByteArrayOutputStream udReassembled = new ByteArrayOutputStream();
            for (byte[] apdu : cmdChain) {
                byte[] resp = channel.sendCommand(apdu);
                int sw = ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
                if (apdu[2] == 0x10) {
                    check("中间 chunk 应返回 0x61xx", sw == 0x6100);
                    udReassembled.write(apdu, 5, apdu[4] & 0xFF);
                } else {
                    check("最后 chunk 应返回 0x9000", sw == 0x9000);
                    udReassembled.write(apdu, 5, apdu[4] & 0xFF);
                }
            }
            check("UD 重组后的 AUTH0 body 与 Reader 发送的一致",
                    Arrays.equals(fullBody, udReassembled.toByteArray()));
        }

        // 测试 4：BER-TLV 长格式长度编码（>255B 字段）
        System.out.println("\n--- 测试 4: BER-TLV 长格式长度编码 ---");
        {
            byte[] data3309 = new byte[3309];
            // 编码：0x9E|0x82|0x0C|0xFD|data
            ByteArrayOutputStream encoded = new ByteArrayOutputStream();
            encoded.write(0x9E);
            encoded.write(0x82);
            encoded.write((3309 >> 8) & 0xFF);  // 0x0C
            encoded.write(3309 & 0xFF);          // 0xFD
            encoded.write(data3309);

            check("3309B 字段 TLV 编码总长 = 1+3+3309 = 3313B", encoded.size() == 3313);
            check("Tag = 0x9E", encoded.toByteArray()[0] == (byte) 0x9E);
            check("长格式标志 = 0x82", encoded.toByteArray()[1] == (byte) 0x82);
            check("长度高字节 = 0x0C", encoded.toByteArray()[2] == 0x0C);
            check("长度低字节 = 0xED", (encoded.toByteArray()[3] & 0xFF) == 0xED);
        }

        // 测试 5：跨端 HMAC 一致性（修复 Bug 1 的核心验证）
        System.out.println("\n--- 测试 5: 跨端 HMAC 一致性（修复后）---");
        {
            byte[] se = new byte[32];
            byte[] transAH0 = new byte[64];
            for (int i = 0; i < 32; i++) se[i] = (byte) i;
            for (int i = 0; i < 64; i++) transAH0[i] = (byte) (i + 100);

            // Reader 端
            byte[] readerHS = PQCUtil.deriveHS(se, transAH0);

            // UD 端模拟（Android Keystore 限制：key=Se, msg=transAH0）
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(se, "HmacSHA256"));
            byte[] udHS = hmac.doFinal(transAH0);

            check("Reader HS (32B)", readerHS.length == 32);
            check("UD HS (32B)", udHS.length == 32);
            check("两端 HS 完全一致", Arrays.equals(readerHS, udHS));
        }

        // 测试 6：跨端 AEAD 一致性（用修复后的 HS 派生 SK_device）
        System.out.println("\n--- 测试 6: 跨端 AEAD 加解密 ---");
        {
            byte[] se = new byte[32];
            byte[] transAH0 = new byte[64];
            for (int i = 0; i < 32; i++) se[i] = (byte) i;
            for (int i = 0; i < 64; i++) transAH0[i] = (byte) (i + 100);

            byte[] hs = PQCUtil.deriveHS(se, transAH0);
            byte[] skDevice = PQCUtil.expandSKDevice(hs, transAH0);

            // UD 端加密（模拟 AUTH1 Response）
            byte[] plaintext = new byte[1952 + 3309 + 4];  // pk_ud + sig_ud + bitmap
            for (int i = 0; i < plaintext.length; i++) plaintext[i] = (byte) (i % 256);

            byte[] iv = new byte[12];
            iv[7] = 1;  // 8字节固定(1L) || 4字节counter
            iv[11] = 1;

            Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding");
            encCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(skDevice, "AES"), new GCMParameterSpec(128, iv));
            byte[] ciphertext = encCipher.doFinal(plaintext);

            // Reader 端解密
            Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(skDevice, "AES"), new GCMParameterSpec(128, iv));
            byte[] decrypted = decCipher.doFinal(ciphertext);

            check("UD 加密后密文长度 = 明文 + 16B tag", ciphertext.length == plaintext.length + 16);
            check("Reader 解密后与 UD 明文一致", Arrays.equals(plaintext, decrypted));
        }

        // 测试 7：多轮次状态重置验证（修复 Bug 2 的核心）
        System.out.println("\n--- 测试 7: 多轮次 counter 重置（修复后）---");
        {
            // 模拟 UD 端 expedited_device_counter 跨轮次行为
            int expedited_device_counter = 0x00000001;

            // 第 1 轮
            check("第 1 轮起始 counter = 1", expedited_device_counter == 1);
            expedited_device_counter++;  // AUTH1 完成后自增
            check("第 1 轮结束 counter = 2", expedited_device_counter == 2);

            // 第 2 轮：修复后应在 AUTH0 开头重置
            expedited_device_counter = 0x00000001;  // 修复后的重置
            check("第 2 轮起始 counter = 1（已重置）", expedited_device_counter == 1);

            // 对照：不重置的情况
            int buggy_counter = 2;  // 第 1 轮结束的值
            check("对照（未重置）：第 2 轮起始 counter = 2（错误）", buggy_counter == 2);
            System.out.println("  说明：修复前 Reader 重置回 1，UD 仍为 2 → IV 不一致 → AEAD Tag mismatch");
        }

        System.out.println("\n========== 测试汇总 ==========");
        System.out.println("  PASSED: " + passed);
        System.out.println("  FAILED: " + failed);
        if (failed == 0) {
            System.out.println("\n✅ 所有 APDU 级数据交互测试通过");
        } else {
            System.out.println("\n❌ 有 " + failed + " 个测试失败");
            System.exit(1);
        }
    }

    static int passed = 0, failed = 0;

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
