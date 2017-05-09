package com.ukdave.rsa;

import java.io.*;
import java.math.BigInteger;

public class IOUtils {

    /**
     * Reads a key (public or private) from a file.
     *
     * @param file the file
     * @return the key
     * @throws IOException if there is a problem writing the file
     */
    public static Key readKey(final File file) throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            BigInteger modulus = new BigInteger(in.readLine().trim());
            BigInteger exponent = new BigInteger(in.readLine().trim());
            return new Key(modulus, exponent);
        }
    }

    /**
     * Writes a key (public or private) to a file.
     *
     * @param key the key
     * @param file the file
     * @throws IOException if there is a problem writing the file
     */
    public static void writeKey(final Key key, final File file) throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            out.println(key.getModulus());
            out.println(key.getExponent());
        }
    }

    /**
     * Reads the contents of a file into a string.
     *
     * @param file the file
     * @return the contents of the file
     * @throws IOException if there is a problem reading the file
     */
    public static String readFile(final File file) throws IOException {
        StringBuffer str = new StringBuffer();
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            str.append(in.readLine());
        }
        return str.toString();
    }

    /**
     * Writes a string to a file.
     *
     * @param str the string
     * @param file the file
     * @throws IOException if there is a problem writing the file
     */
    public static void writeFile(final String str, final File file) throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            out.print(str);
            if (!str.endsWith("\n")) {
                out.println();
            }
        }
    }
}
