package com.tencent.kona.crypto.provider;

import com.tencent.kona.sun.security.util.ArrayUtil;

import java.security.InvalidKeyException;
import java.security.ProviderException;

final class ParallelElectronicCodeBook extends ParallelFeedbackCipher {

    ParallelElectronicCodeBook(ParallelSymmetricCipher embeddedCipher) {

        super(embeddedCipher);
    }

    /**
     * Gets the name of the feedback mechanism
     *
     * @return the name of the feedback mechanism
     */
    String getFeedback() {
        return "ParallelECB";
    }

    /**
     * Resets the iv to its original value.
     * This is used when doFinal is called in the Cipher class, so that the
     * cipher can be reused (with its original iv).
     */
    void reset() {
        // empty
    }

    /**
     * Save the current content of this cipher.
     */
    void save() {
    }

    /**
     * Restores the content of this cipher to the previous saved one.
     */
    void restore() {
    }

    /**
     * Initializes the cipher in the specified mode with the given key
     * and iv.
     *
     * @param decrypting flag indicating encryption or decryption
     * @param algorithm  the algorithm name
     * @param key        the key
     * @param iv         the iv
     * @throws InvalidKeyException if the given key is inappropriate for
     *                             initializing this cipher
     */
    void init(boolean decrypting, String algorithm, byte[] key, byte[] iv)
            throws InvalidKeyException {
        if ((key == null) || (iv != null)) {
            throw new InvalidKeyException("Internal error");
        }
        embeddedCipher.init(decrypting, algorithm, key);
    }

    private int implECBEncrypt(byte[] in, int inOff, int len, byte[] out, int outOff) {
        int currentLen = len;
        while (currentLen >= walkSize) {
            embeddedCipher.parallelEncryptBlock(in, inOff, out, outOff);
            inOff += walkSize;
            outOff += walkSize;
            currentLen -= walkSize;
        }

        while (currentLen >= blockSize) {
            embeddedCipher.encryptBlock(in, inOff, out, outOff);
            inOff += blockSize;
            outOff += blockSize;
            currentLen -= blockSize;
        }

        return len;
    }

    /**
     * Performs encryption operation.
     *
     * <p>The input plain text <code>in</code>, starting at
     * <code>inOff</code> and ending at * <code>(inOff + len - 1)</code>,
     * is encrypted. The result is stored in <code>out</code>, starting at
     * <code>outOff</code>.
     *
     * @param in     the buffer with the input data to be encrypted
     * @param inOff  the offset in <code>plain</code>
     * @param len    the length of the input data
     * @param out    the buffer for the result
     * @param outOff the offset in <code>cipher</code>
     * @return the length of the encrypted data
     * @throws ProviderException if <code>len</code> is not
     *                           a multiple of the block size
     */
    int encrypt(byte[] in, int inOff, int len, byte[] out, int outOff) {
        ArrayUtil.blockSizeCheck(len, blockSize);
        ArrayUtil.nullAndBoundsCheck(in, inOff, len);
        ArrayUtil.nullAndBoundsCheck(out, outOff, len);
        return implECBEncrypt(in, inOff, len, out, outOff);
    }

    private int implECBDecrypt(byte[] in, int inOff, int len, byte[] out, int outOff) {
        for (int i = len; i >= walkSize; i -= walkSize) {
            embeddedCipher.decryptBlock(in, inOff, out, outOff);
            inOff += blockSize;
            outOff += blockSize;
        }
        return len;
    }

    /**
     * Performs decryption operation.
     *
     * <p>The input cipher text <code>in</code>, starting at
     * <code>inOff</code> and ending at * <code>(inOff + len - 1)</code>,
     * is decrypted.The result is stored in <code>out</code>, starting at
     * <code>outOff</code>.
     *
     * @param in     the buffer with the input data to be decrypted
     * @param inOff  the offset in <code>cipherOffset</code>
     * @param len    the length of the input data
     * @param out    the buffer for the result
     * @param outOff the offset in <code>plain</code>
     * @return the length of the decrypted data
     * @throws ProviderException if <code>len</code> is not
     *                           a multiple of the block size
     */
    int decrypt(byte[] in, int inOff, int len, byte[] out, int outOff) {
        ArrayUtil.blockSizeCheck(len, blockSize);
        ArrayUtil.nullAndBoundsCheck(in, inOff, len);
        ArrayUtil.nullAndBoundsCheck(out, outOff, len);
        return implECBDecrypt(in, inOff, len, out, outOff);
    }
}
