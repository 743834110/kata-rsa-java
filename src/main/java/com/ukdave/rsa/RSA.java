package com.ukdave.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static java.math.BigInteger.ONE;

/**
 * Basic Java implementation of the RSA algorithm based on the steps
 * described here: https://simple.wikipedia.org/wiki/RSA_(algorithm)
 */
public class RSA {

    /**
     * Generate a key pair (public and private key).
     *
     * @param bitLength the bit length (e.g. 1024)
     * @return the key pair
     */
    public KeyPair generateKeyPair(final int bitLength) {
        if (bitLength < 8) {
            throw new IllegalArgumentException("bitLength must be >= 8");
        }

        // 1. Choose two different large random prime numbers p and q
        Random rnd = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength, rnd);
        BigInteger q = BigInteger.probablePrime(bitLength, rnd);

        // 2. Calculate {@code n = p q} (n is the modulus for the public key and the private keys)
        BigInteger n = p.multiply(q);

        // 3. Calculate the totient {@code phi(n) = (p-1)(q-1)}
        BigInteger phi = (p.subtract(ONE)).multiply(q.subtract(ONE));

        // 4. Choose an integer e (the public key exponent) such that {@code 1 < e < phi} and e is coprime to phi
        BigInteger e = BigInteger.valueOf(bitLength <= 8 ? 257 : 65537);
        assert e.compareTo(phi) <= 1;

        // 5. Compute d (the private key exponent) to satisfy congruence relation {@code de = 1 (mod phi(n))}
        BigInteger d = e.modInverse(phi);

        // The public key is made of the modulus n and the public (or encryption) exponent e.
        // The private key is made of the modulus n and the private (or decryption) exponent d which must be kept secret.
        Key publicKey = new Key(n, e);
        Key privateKey = new Key(n, d);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Encrypt a message using a public key.
     *
     * @param plain the message
     * @param publicKey the public key
     * @return the encrypted message
     */
    public byte[] encrypt(final byte[] plain, final Key publicKey) {
        // Turn M into a number m smaller than n
        BigInteger m = new BigInteger(plain);
        if (m.compareTo(publicKey.getModulus()) == 1) {
            throw new IllegalArgumentException("message too long - increase bitLength or split the message");
        }

        // Compute the ciphertext c using the public key e in the following procedure: {@code c = m^e mod n}
        BigInteger c = m.modPow(publicKey.getExponent(), publicKey.getModulus());
        return c.toByteArray();
    }

    /**
     * Decrypt a message using a private key.
     *
     * @param encrypted the encrypted message
     * @param privateKey the private key
     * @return the decrypted message
     */
    public byte[] decrypt(final byte[] encrypted, final Key privateKey) {
        // Recover m from c by using the private key d in the following procedure: {@code m = c^d mod n}
        BigInteger c = new BigInteger(encrypted);
        BigInteger m = c.modPow(privateKey.getExponent(), privateKey.getModulus());
        return m.toByteArray();
    }
}
