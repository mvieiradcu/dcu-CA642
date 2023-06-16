package com.mlimavieira.dcu;

/*
 * The FEAL cipher
 */

import com.mlimavieira.dcu.util.Utils;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class FEAL {

    static int rounds = 4;

    static byte rot2(byte x) {
        return (byte) (((x & 255) << 2) | ((x & 255) >>> 6));
    }

    static byte g0(byte a, byte b) {
        return rot2((byte) ((a + b) & 255));
    }

    static byte g1(byte a, byte b) {
        return rot2((byte) ((a + b + 1) & 255));
    }

    static int pack(byte[] b, int startindex) {
        /* pack 4 bytes into a 32-bit Word */
        return ((b[startindex + 3] & 255) | ((b[startindex + 2] & 255) << 8) | ((b[startindex + 1] & 255) << 16) | ((b[startindex] & 255) << 24));
    }

    static void unpack(int a, byte[] b, int startindex) {
        /* unpack bytes from a 32-bit word */

        b[startindex] = (byte) (a >>> 24);
        b[startindex + 1] = (byte) (a >>> 16);
        b[startindex + 2] = (byte) (a >>> 8);
        b[startindex + 3] = (byte) a;
    }

    static void unpack(Long a, byte[] b, int startindex) {
        /* unpack bytes from a 32-bit word */

        b[startindex] = (byte) (a >>> 24);
        b[startindex + 1] = (byte) (a >>> 16);
        b[startindex + 2] = (byte) (a >>> 8);
        b[startindex + 3] = a.byteValue();
    }

    static int f(int input) {
        byte[] x = new byte[4];
        byte[] y = new byte[4];

        unpack(input, x, 0);
        y[1] = g1((byte) ((x[0] ^ x[1]) & 255), (byte) ((x[2] ^ x[3]) & 255));
        y[0] = g0((byte) (x[0] & 255), (byte) (y[1] & 255));
        y[2] = g0((byte) (y[1] & 255), (byte) ((x[2] ^ x[3]) & 255));
        y[3] = g1((byte) (y[2] & 255), (byte) (x[3] & 255));
        return pack(y, 0);
    }

    public static long f(long input) {
        byte[] x = new byte[4];
        byte[] y = new byte[4];

        unpack(input, x, 0);
        y[1] = g1((byte) ((x[0] ^ x[1]) & 255), (byte) ((x[2] ^ x[3]) & 255));
        y[0] = g0((byte) (x[0] & 255), (byte) (y[1] & 255));
        y[2] = g0((byte) (y[1] & 255), (byte) ((x[2] ^ x[3]) & 255));
        y[3] = g1((byte) (y[2] & 255), (byte) (x[3] & 255));
        return Integer.toUnsignedLong(pack(y, 0));
    }

    ///
    static void encrypt(byte[] data, int[] key) {

        int left = pack(data, 0) ^ key[4];
        int right = left ^ pack(data, 4) ^ key[5];

        for (int i = 0; i < rounds; i++) {
            int temp = right;
            right = left ^ f(right ^ key[i]);
            left = temp;
        }

        left ^= right;

        unpack(right, data, 0);
        unpack(left, data, 4);
    }

    public static Long encrypt(Long data, int[] key) {
        byte[] bytes = ByteBuffer.allocate(8).putLong(data).array();
        encrypt(bytes, key);

        return new BigInteger(bytes).longValue();
    }

    static void decrypt(byte[] data, int[] key) {

        int right = pack(data, 0);
        int left = right ^ pack(data, 4);

        for (int i = 0; i < rounds; i++) {
            int temp = left;
            left = right ^ f(left ^ key[rounds - 1 - i]);
            right = temp;
        }

        right ^= left;

        left ^= key[4];
        right ^= key[5];
        unpack(left, data, 0);
        unpack(right, data, 4);
    }

    static Long decryptAsLong(Long data, int[] key) {
        byte[] bL = Utils.longToBytes(data);
        decrypt(bL, key);
        return Utils.byteArrayToLong(bL);
    }

    public static void main(String[] args) {
        byte[] data = new byte[8];

        /* Not the keys you are looking for!!! */
        int key[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

        if (args.length != 8) {
            System.out.println("command line error - input 8 bytes of plaintext in hex");
            System.out.println("For example:");
            System.out.println("java FEAL 01 23 45 67 89 ab cd ef");
            return;
        }
        for (int i = 0; i < 8; i++)
            data[i] = (byte) (Integer.parseInt(args[i], 16) & 255);

        System.out.print("Plaintext=  ");
        for (int i = 0; i < 8; i++) System.out.printf("%02x", data[i]);
        System.out.print("\n");

        encrypt(data, key);
        System.out.print("Ciphertext= ");
        for (int i = 0; i < 8; i++) System.out.printf("%02x", data[i]);
        System.out.print("\n");

        decrypt(data, key);
        System.out.print("Plaintext=  ");
        for (int i = 0; i < 8; i++) System.out.printf("%02x", data[i]);
        System.out.print("\n");

        return;
    }
}
