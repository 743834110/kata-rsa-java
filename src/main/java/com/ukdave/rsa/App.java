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

    public void generateKeyPair() {
        System.out.println("Generating key pair...");
        KeyPair keyPair = rsa.generateKeyPair(KEY_LENGTH);
        System.out.println(keyPair);
        try {
            IOUtils.writeKey(keyPair.getPrivateKey(), KEY_PRV);
            IOUtils.writeKey(keyPair.getPublicKey(), KEY_PUB);
        } catch (IOException ex) {
            System.out.println("Error writing key pair: " + ex.getMessage());
        }
    }

    public void encryptMessage() {
        System.out.println("Encrypting message...");

        Key publicKey = null;
        try {
            publicKey = IOUtils.readKey(KEY_PUB);
        } catch (IOException ex) {
            System.out.println("Error loading public key: " + ex.getMessage());
            return;
        }

        String message = null;
        try {
            message = IOUtils.readFile(MESSAGE_TXT);
            System.out.println("Plain text: " + message);
        } catch (IOException ex) {
            System.out.println("Error reading message: " + ex.getMessage());
            return;
        }

        byte[] cipherData = rsa.encrypt(message.getBytes(), publicKey);
        String cipherText = new BigInteger(cipherData).toString();
        System.out.println("Cipher text: " + cipherText);
        try {
            IOUtils.writeFile(cipherText, MESSAGE_DAT);
        } catch (IOException ex) {
            System.out.println("Error writing encrypted message: " + ex.getMessage());
        }
    }

    public void decryptMessage() {
        System.out.println("Decrypting message...");

        Key privateKey = null;
        try {
            privateKey = IOUtils.readKey(KEY_PRV);
        } catch (IOException ex) {
            System.out.println("Error loading private key: " + ex.getMessage());
            return;
        }

        BigInteger cipherData = null;
        try {
            String cipherText = IOUtils.readFile(MESSAGE_DAT).trim();
            System.out.println("Cipher text: " + cipherText);
            cipherData = new BigInteger(cipherText);
        } catch (IOException ex) {
            System.out.println("Error reading encrypted message: " + ex.getMessage());
            return;
        }

        String message = new String(rsa.decrypt(cipherData.toByteArray(), privateKey));
        System.out.println("Plain text: " + message);
        try {
            IOUtils.writeFile(message, MESSAGE_TXT);
        } catch (IOException ex) {
            System.out.println("Error writing decrypted message: " + ex.getMessage());
        }
    }

    public static void main(final String[] args) throws IOException {
        App app = new App();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.println("Please select an option:");
            System.out.println("  1. Generate key pair (key.pub, key.prv)");
            System.out.println("  2. Encrypt message (in: message.txt, out: message.dat)");
            System.out.println("  3. Decrypt message (in: message.dat, out: message.txt)");
            System.out.println("  4. Exit");
            System.out.print(">");
            String choice = in.readLine();
            switch (choice) {
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
                    System.out.println("Bye!");
                    System.exit(0);
                default:
                    System.out.println("Invalid choice.");
            }
            System.out.println();
        }
    }
}
