package org.example;

import org.bouncycastle.util.Arrays;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PRNG {
    private byte[] seed;
    private long counter;

    public PRNG(byte[] seed) {
        this.seed = Arrays.copyOf(seed, seed.length);
        this.counter = 0;
    }

    /** ---------------- 基础方法 ---------------- **/

    // 将 long 转为 8 字节数组
    private byte[] longToBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }

    // SHA-256 哈希单次生成
    private byte[] hashNext() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(seed);
        digest.update(longToBytes(counter));
        counter++;
        return digest.digest();
    }

    /** ---------------- 生成方法 ---------------- **/

    // 生成指定长度的伪随机字节数组
    public byte[] nextBytes(int length) throws NoSuchAlgorithmException {
        byte[] output = new byte[length];
        int offset = 0;

        while (offset < length) {
            byte[] hash = hashNext();
            int copyLength = Math.min(hash.length, length - offset);
            System.arraycopy(hash, 0, output, offset, copyLength);
            offset += copyLength;
        }
        return output;
    }

    // 生成 0~2^32-1 的伪随机整数
    public int nextInt() throws NoSuchAlgorithmException {
        byte[] hash = hashNext();
        int value = 0;
        for (int i = 0; i < 4; i++) {
            value = (value << 8) | (hash[i] & 0xFF);
        }
        return value;
    }

    // 生成 0.0 ~ 1.0 的伪随机 double
    public double nextDouble() throws NoSuchAlgorithmException {
        // 使用 8 字节生成 long，再除以 2^64 转为 double
        byte[] hash = hashNext();
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (hash[i] & 0xFF);
        }
        return (value >>> 1) / (double)(Long.MAX_VALUE); // 保证在 [0,1)
    }

    // 将 byte 数组转 16 进制字符串
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
