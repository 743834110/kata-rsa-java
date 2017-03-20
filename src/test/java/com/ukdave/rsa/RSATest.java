package com.ukdave.rsa;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class RSATest {

    private RSA rsa;

    @Before
    public void setup() {
        rsa = new RSA();
    }

    @Test
    public void testEncryptDecrypt() {
        String message = "Hello world";
        KeyPair keyPair = rsa.generateKeyPair(128);
        byte[] encrypted = rsa.encrypt(message.getBytes(StandardCharsets.UTF_8), keyPair.getPublicKey());
        String decrypted = new String(rsa.decrypt(encrypted, keyPair.getPrivateKey()), StandardCharsets.UTF_8);
        assertThat(decrypted, is(equalTo(message)));
    }
}