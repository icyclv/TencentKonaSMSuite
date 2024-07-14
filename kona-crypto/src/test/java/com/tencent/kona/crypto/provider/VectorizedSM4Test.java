/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_TAG_LEN;

/**
 * The test for SM4 cipher.
 */
public class VectorizedSM4Test {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000000");
    private static final byte[] GCM_IV = toBytes("000000000000000000000000");
    private static final byte[] AAD = toBytes("616263");

    private static final byte[] MESSAGE = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testSpec() throws Exception {
        byte[] key = toBytes("0123456789abcdef0123456789abcdef");

        SecretKey secretKey = new SecretKeySpec(key, "SM4");
        Assertions.assertArrayEquals(key, secretKey.getEncoded());


        Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        Cipher.getInstance("VectorizedSM4/ECB/PKCS7Padding", PROVIDER);
    }


    @Test
    public void testKAT() throws Exception {
        byte[] message = toBytes("0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");
        byte[] expectedCiphertext = toBytes("681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246");

        SecretKey secretKey = new SecretKeySpec(key, "SM4");
        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(message);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);
        Assertions.assertArrayEquals(message, cleartext);

        // Without SM4 key factory
        secretKey = new SecretKeySpec(key, "SM4");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        ciphertext = cipher.doFinal(message);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cleartext = cipher.doFinal(ciphertext);
        Assertions.assertArrayEquals(message, cleartext);
    }

    @Test
    public void testKATWithByteBuffer() throws Exception {
        byte[] message = toBytes("0123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210");
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");
        byte[] expectedCiphertext = toBytes("681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246");

        SecretKey secretKey = new SecretKeySpec(key, "SM4");
        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        ByteBuffer plaintext = ByteBuffer.wrap(message);
        ByteBuffer ciphertext = ByteBuffer.allocate(message.length);

        cipher.doFinal(plaintext, ciphertext);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext.array());

        plaintext.flip();
        ciphertext.flip();
        ByteBuffer cleartext = ByteBuffer.allocate(message.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cipher.doFinal(ciphertext, cleartext);
        Assertions.assertArrayEquals(message, cleartext.array());

        // Without SM4 key factory
        secretKey = new SecretKeySpec(key, "SM4");

        plaintext.flip();
        ciphertext.flip();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        cipher.doFinal(plaintext, ciphertext);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext.array());

        ciphertext.flip();
        cleartext.flip();
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cipher.doFinal(ciphertext, cleartext);
        Assertions.assertArrayEquals(message, cleartext.array());
    }

    @Test
    public void testEmpty() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ciphertext = cipher.doFinal(TestUtils.EMPTY);
        Assertions.assertArrayEquals(TestUtils.EMPTY, ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] cleartext = cipher.doFinal(ciphertext);
        Assertions.assertArrayEquals(TestUtils.EMPTY, cleartext);
    }

    @Test
    public void testEmptyWithByteBuffer() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        ByteBuffer plaintext = ByteBuffer.allocate(0);
        ByteBuffer ciphertext = ByteBuffer.allocate(64);
        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        cipher.doFinal(plaintext, ciphertext);
        Assertions.assertEquals(0, ciphertext.position());

        ciphertext.flip();
        ByteBuffer cleartext = ByteBuffer.allocate(64);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        cipher.doFinal(plaintext, cleartext);
        Assertions.assertEquals(0, cleartext.position());
    }

    @Test
    public void testNull() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null));

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null));
    }

    @Test
    public void testNoSpace() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        ByteBuffer plaintext = ByteBuffer.wrap(MESSAGE);

        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Assertions.assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(plaintext, ByteBuffer.allocate(MESSAGE.length - 1)));

        ByteBuffer ciphertext = ByteBuffer.allocate(MESSAGE.length);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        Assertions.assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(ciphertext, ByteBuffer.allocate(MESSAGE.length - 1)));
    }

    @Test
    public void testNullWithByteBuffer() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null, null));

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null, null));
    }

    @Test
    public void testECBModeWithPadding() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/PKCS7Padding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testECBModeWithPaddingParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECBModeWithPadding();
            return null;
        });
    }

    @Test
    public void testECBModeWithPaddingSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECBModeWithPadding();
            return null;
        });
    }

    @Test
    public void testECBModeWithoutPadding() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance("VectorizedSM4/ECB/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testECBModeWithoutPaddingParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECBModeWithoutPadding();
            return null;
        });
    }

    @Test
    public void testECBModeWithoutPaddingSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECBModeWithoutPadding();
            return null;
        });
    }

    @Test
    public void testReInit() throws Exception {

        testReInit("VectorizedSM4/ECB/NoPadding", null);
        testReInit("VectorizedSM4/ECB/PKCS7Padding", null);
    }

    private void testReInit(String algorithm,
                            AlgorithmParameterSpec paramSpec) throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        SecretKey altSecretKey = new SecretKeySpec(
                toBytes("01234567012345670123456701234567"), "SM4");

        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);

        if (paramSpec != null) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            cipher.init(Cipher.ENCRYPT_MODE, altSecretKey, paramSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            cipher.init(Cipher.ENCRYPT_MODE, altSecretKey);
        }
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        if (paramSpec != null) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            cipher.init(Cipher.DECRYPT_MODE, altSecretKey, paramSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            cipher.init(Cipher.DECRYPT_MODE, altSecretKey);
        }
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testReuse() throws Exception {
        testReuse("VectorizedSM4/ECB/NoPadding", null);
        testReuse("VectorizedSM4/ECB/PKCS7Padding", null);
    }

    private void testReuse(String algorithm,
                           AlgorithmParameterSpec paramSpec) throws Exception {
        byte[] message1 = "0123456789abcdef".getBytes();
        byte[] message2 = "0123456789ABCDEF".getBytes();

        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");

        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);

        if (paramSpec != null) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        cipher.doFinal(message1);
        byte[] ciphertext2 = cipher.doFinal(message2);

        if (paramSpec != null) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        byte[] cleartext2 = cipher.doFinal(ciphertext2);

        Assertions.assertArrayEquals(message2, cleartext2);
    }

    @Test
    public void testUpdateData() throws Exception {

        testUpdateData("VectorizedSM4/ECB/NoPadding", null, true);
        testUpdateData("VectorizedSM4/ECB/NoPadding", null, false);

        testUpdateData("VectorizedSM4/ECB/PKCS7Padding", null, true);
        testUpdateData("VectorizedSM4/ECB/PKCS7Padding", null, false);
    }

    private void testUpdateData(String algorithm,
                                AlgorithmParameterSpec paramSpec,
                                boolean segmentedEnc) throws Exception {
        byte[] ciphertext = cipherData(algorithm, Cipher.ENCRYPT_MODE,
                paramSpec, MESSAGE, segmentedEnc);
        byte[] cleartext = cipherData(algorithm, Cipher.DECRYPT_MODE,
                paramSpec, ciphertext, !segmentedEnc);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    private byte[] cipherData(String algorithm, int opmode,
                              AlgorithmParameterSpec paramSpec,
                              byte[] data, boolean segmented)
            throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);
        if (paramSpec != null) {
            cipher.init(opmode, secretKey, paramSpec);
        } else {
            cipher.init(opmode, secretKey);
        }

        byte[] cipherData;
        if (segmented) {
            byte[] firstData = TestUtils.null2Empty(cipher.update(data, 0, data.length / 2));
            byte[] secondData = TestUtils.null2Empty(cipher.update(data, data.length / 2,
                    data.length - data.length / 2));
            byte[] finalData = TestUtils.null2Empty(cipher.doFinal());

            cipherData = new byte[firstData.length + secondData.length + finalData.length];
            if (firstData.length > 0) {
                System.arraycopy(
                        firstData, 0,
                        cipherData, 0,
                        firstData.length);
            }
            if (secondData.length > 0) {
                System.arraycopy(
                        secondData, 0,
                        cipherData, firstData.length,
                        secondData.length);
            }
            if (finalData.length > 0) {
                System.arraycopy(
                        finalData, 0,
                        cipherData, firstData.length + secondData.length,
                        finalData.length);
            }
        } else {
            cipherData = cipher.doFinal(data);
        }

        return cipherData;
    }

    @Test
    public void testKeyWrapping() throws Exception {
        testKeyWrapping("VectorizedSM4/ECB/NoPadding");
        testKeyWrapping("VectorizedSM4/ECB/PKCS7Padding");
    }

    private void testKeyWrapping(String algorithm) throws Exception {
        Cipher wrapper = Cipher.getInstance(algorithm, PROVIDER);
        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);

        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", PROVIDER);
        keyGen.init(128);

        // Generate two keys: secretKey and sessionKey
        SecretKey secretKey = keyGen.generateKey();
        SecretKey sessionKey = keyGen.generateKey();

        // Wrap and unwrap the session key make sure the unwrapped session key
        // can decrypt a message encrypted with the session key.
        wrapper.init(Cipher.WRAP_MODE, secretKey);
        byte[] wrappedKey = wrapper.wrap(sessionKey);

        wrapper.init(Cipher.UNWRAP_MODE, secretKey);
        SecretKey unwrappedSessionKey =
                (SecretKey) wrapper.unwrap(wrappedKey, "SM4", Cipher.SECRET_KEY);

        cipher.init(Cipher.ENCRYPT_MODE, unwrappedSessionKey);

        byte[] ciphertext = cipher.doFinal(MESSAGE);
        cipher.init(Cipher.DECRYPT_MODE, unwrappedSessionKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCipherStream() throws Exception {
        testCipherStream("SM4/ECB/NoPadding", null);
        testCipherStream("SM4/ECB/PKCS7Padding", null);
    }

    private void testCipherStream(String algorithm,
                                  AlgorithmParameterSpec paramSpec)
            throws Exception {
        Key key = new SecretKeySpec(KEY, "SM4");

        Cipher encrypter = Cipher.getInstance(algorithm, PROVIDER);
        if (paramSpec != null) {
            encrypter.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        } else {
            encrypter.init(Cipher.ENCRYPT_MODE, key);
        }

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        try (CipherOutputStream encryptOut = new CipherOutputStream(
                ciphertextOut, encrypter)) {
            for (int i = 0; i < MESSAGE.length / 2; i++) {
                encryptOut.write(MESSAGE[i]);
            }
            encryptOut.write(MESSAGE, MESSAGE.length / 2,
                    MESSAGE.length - MESSAGE.length / 2);
        }

        Cipher decrypter = Cipher.getInstance(algorithm, PROVIDER);
        if (paramSpec != null) {
            decrypter.init(Cipher.DECRYPT_MODE, key, paramSpec);
        } else {
            decrypter.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] cleartext = new byte[MESSAGE.length];
        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(
                ciphertextOut.toByteArray());
        try (CipherInputStream decryptIn = new CipherInputStream(
                ciphertextIn, decrypter)) {
            DataInputStream dataIn = new DataInputStream(decryptIn);
            for (int i = 0; i < MESSAGE.length / 2; i++) {
                cleartext[i] = (byte) dataIn.read();
            }
            dataIn.readFully(cleartext, MESSAGE.length / 2,
                    MESSAGE.length - MESSAGE.length / 2);
        }

        Assertions.assertArrayEquals(cleartext, MESSAGE);
    }

    @Test
    public void testGetOutputSize() throws Exception {
        SecretKey key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec ivParamSpec = new IvParameterSpec(IV);


        Cipher cipherECBNoPadding = Cipher.getInstance("VectorizedSM4/ECB/NoPadding",
                PROVIDER);
        cipherECBNoPadding.init(Cipher.ENCRYPT_MODE, key);
        Assertions.assertEquals(16, cipherECBNoPadding.getOutputSize(16));

        Cipher cipherECBPKCS7Padding = Cipher.getInstance("VectorizedSM4/ECB/PKCS7Padding",
                PROVIDER);
        cipherECBPKCS7Padding.init(Cipher.ENCRYPT_MODE, key);
        Assertions.assertEquals(16, cipherECBPKCS7Padding.getOutputSize(15));
        Assertions.assertEquals(32, cipherECBPKCS7Padding.getOutputSize(16));

    }
}
