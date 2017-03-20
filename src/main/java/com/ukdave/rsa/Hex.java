package com.ukdave.rsa;

import java.math.BigInteger;

public class Hex {

    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    public static String encode(final BigInteger data) {
        return encode(data.toByteArray());
    }

    public static String encode(final byte[] data) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = HEX_DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = HEX_DIGITS[0x0F & data[i]];
        }
        return new String(out);
    }
}
