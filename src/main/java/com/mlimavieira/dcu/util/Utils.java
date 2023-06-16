package com.mlimavieira.dcu.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public final class Utils {

    private Utils() {
    }

    public static long getLeftHalf(long x) {
        return x >> 32 & 0xFFFFFFFFL;
    }

    public static long getRightHalf(long x) {
        return x & 0xFFFFFFFFL;
    }

    public static long getCombinedHalves(long a, long b) {
        return ((a) << 32) | ((b) & 0xFFFFFFFFL);
    }

    public static byte[] longToBytes(long val) {
        return ByteBuffer.allocate(8).putLong(val).array();
    }

    public static long byteArrayToLong(byte[] b) {
        if (b == null || b.length == 0) {
            return 0;
        }
        return new BigInteger(1, b).longValue();
    }
}
