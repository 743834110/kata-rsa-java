package com.ukdave.rsa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class Main {

    public static void main(final String[] args) throws IOException {
        RSA rsa = new RSA();
        int bitLength = 128;

        System.out.println("Generating " + bitLength + " bit RSA key pair...");
        KeyPair keyPair = rsa.generateKeyPair(bitLength);
        System.out.println("Public key:");
        System.out.println(" n = " + Hex.encode(keyPair.getPublicKey().getModulus()));
        System.out.println(" e = " + Hex.encode(keyPair.getPublicKey().getExponent()));
        System.out.println("Private key:");
        System.out.println(" n = " + Hex.encode(keyPair.getPrivateKey().getModulus()));
        System.out.println(" d = " + Hex.encode(keyPair.getPrivateKey().getExponent()));
        System.out.println();

        System.out.println("Please enter a message:");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String message = in.readLine();
        System.out.println();

        System.out.println("Encrypted message:");
        byte[] encrypted = rsa.encrypt(message.getBytes(StandardCharsets.UTF_8), keyPair.getPublicKey());
        System.out.println(Hex.encode(encrypted));
        System.out.println();

        System.out.println("Decrypted message:");
        byte[] decrypted = rsa.decrypt(encrypted, keyPair.getPrivateKey());
        System.out.println(new String(decrypted, StandardCharsets.UTF_8));
    }
}
