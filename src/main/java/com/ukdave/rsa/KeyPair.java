package com.ukdave.rsa;

import java.util.Objects;

/**
 * Represents an RSA key pair.
 */
public class KeyPair {

    private final Key publicKey;
    private final Key privateKey;

    public KeyPair(final Key publicKey, final Key privateKey) {
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey must not be null");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    }

    public Key getPublicKey() {
        return publicKey;
    }

    public Key getPrivateKey() {
        return privateKey;
    }

    @Override
    public String toString() {
        return "KeyPair{\n" +
                "  publicKey=" + publicKey + ",\n" +
                "  privateKey=" + privateKey + "\n" +
                '}';
    }
}
