package com.ukdave.rsa;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents an RSA key (public or private).
 */
public class Key {

    private final BigInteger modulus;
    private final BigInteger exponent;

    public Key(final BigInteger modulus, final BigInteger exponent) {
        this.modulus = Objects.requireNonNull(modulus, "modulus must not be null");
        this.exponent = Objects.requireNonNull(exponent, "exponent must not be null");
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }
}
