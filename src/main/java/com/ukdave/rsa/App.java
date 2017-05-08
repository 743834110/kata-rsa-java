package com.ukdave.rsa;

import java.io.*;
import java.math.BigInteger;

public class App {

    private static final int KEY_LENGTH = 128;
    private static final File KEY_PUB = new File("key.pub");
    private static final File KEY_PRV = new File("key.prv");
    private static final File MESSAGE_TXT = new File("message.txt");
    private static final File MESSAGE_DAT = new File("message.dat");

    private final RSA rsa = new RSA();

    public void generateKeyPair() throws IOException {
        KeyPair keyPair = rsa.generateKeyPair(KEY_LENGTH);
        writeKey(keyPair.getPrivateKey(), KEY_PRV);
        writeKey(keyPair.getPublicKey(), KEY_PUB);
    }

    public void encryptMessage() throws IOException {
        Key publicKey = readKey(KEY_PUB);
        String message = readFile(MESSAGE_TXT);
        String cipherText = new BigInteger(rsa.encrypt(message.getBytes(), publicKey)).toString();
        writeFile(cipherText, MESSAGE_DAT);
    }

    public void decryptMessage() throws IOException {
        Key privateKey = readKey(KEY_PRV);
        BigInteger cipherText = new BigInteger(readFile(MESSAGE_DAT).trim());
        String message = new String(rsa.decrypt(cipherText.toByteArray(), privateKey));
        writeFile(message, MESSAGE_TXT);
    }

    public void clean() {
        KEY_PUB.delete();
        KEY_PRV.delete();
        MESSAGE_TXT.delete();
        MESSAGE_DAT.delete();
    }

    private Key readKey(final File file) throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            BigInteger modulus = new BigInteger(in.readLine().trim());
            BigInteger exponent = new BigInteger(in.readLine().trim());
            return new Key(modulus, exponent);
        }
    }

    private void writeKey(final Key key, final File file) throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            out.println(key.getModulus());
            out.println(key.getExponent());
        }
    }

    private String readFile(final File file) throws IOException {
        StringBuffer str = new StringBuffer();
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            str.append(in.readLine());
        }
        return str.toString();
    }

    private void writeFile(final String str, final File file) throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter(file))) {
            out.print(str);
            if (!str.endsWith("\n")) {
                out.println();
            }
        }
    }

    public static void main(final String[] args) throws IOException {
        if (args.length != 1) {
            System.out.println("Usage: App <mode>");
            System.out.println("  Modes:");
            System.out.println("    1 - Generate key pair (key.pub, key.prv)");
            System.out.println("    2 - Encrypt message (in: message.txt, out: message.dat)");
            System.out.println("    3 - Decrypt message (in: message.dat, out: message.txt)");
            System.out.println("    4 - Clean (delete keys and messages)");
            System.exit(1);
        }
        App app = new App();
        switch (args[0]) {
            case "1":
                app.generateKeyPair();
                break;
            case "2":
                app.encryptMessage();
                break;
            case "3":
                app.decryptMessage();
                break;
            case "4":
                app.clean();
                break;
            default:
                System.out.println("Invalid mode");
                System.exit(1);
        }
    }
}
