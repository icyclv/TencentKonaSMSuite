package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Constants;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * This class implements the SM4 algorithm in its various modes
 * (<code>ECB</code>) and padding schemes (<code>PKCS5Padding</code>,
 * <code>NoPadding</code>, <code>ISO10126Padding</code>).
 *
 * @author Valerie Peng
 * @see SM4Crypt
 */

class VectorizedSM4Cipher extends CipherSpi {
    public static final class General extends VectorizedSM4Cipher {
        public General() {
            super(-1);
        }
    }

    static class OidImpl extends VectorizedSM4Cipher {
        protected OidImpl(int keySize, String mode, String padding) {
            super(keySize);
            try {
                engineSetMode(mode);
                engineSetPadding(padding);
            } catch (GeneralSecurityException gse) {
                // internal error; re-throw as provider exception
                throw new ProviderException("Internal Error", gse);
            }
        }
    }


    // utility method used by SM4Cipher and SM4WrapCipher
    static void checkKeySize(Key key, int fixedKeySize)
            throws InvalidKeyException {
        if (fixedKeySize != -1) {
            if (key == null) {
                throw new InvalidKeyException("The key must not be null");
            }
            byte[] value = key.getEncoded();
            if (value == null) {
                throw new InvalidKeyException("Key encoding must not be null");
            } else {
                Arrays.fill(value, (byte) 0);
                if (value.length != fixedKeySize) {
                    throw new InvalidKeyException("The key must be " +
                            fixedKeySize + " bytes");
                }
            }
        }
    }

    /*
     * internal CipherCore object which does the real work.
     */
    private final CipherCore core;

    /*
     * needed to support SM4 oids which associates a fixed key size
     * to the cipher object.
     */
    private final int fixedKeySize; // in bytes, -1 if no restriction


    /**
     * Creates an instance of SM4 cipher with default ECB mode and
     * PKCS5Padding.
     */
    protected VectorizedSM4Cipher(int keySize) {
        core = new CipherCore(new SM4Crypt(), Constants.SM4_BLOCK_SIZE);
        fixedKeySize = keySize;
    }

    /**
     * Sets the mode of this cipher.
     *
     * @param mode the cipher mode
     * @throws NoSuchAlgorithmException if the requested cipher mode does
     *                                  not exist
     */
    @Override
    protected void engineSetMode(String mode)
            throws NoSuchAlgorithmException {
        core.setMode(mode);
    }

    /**
     * Sets the padding mechanism of this cipher.
     *
     * @param paddingScheme the padding mechanism
     * @throws NoSuchPaddingException if the requested padding mechanism
     *                                does not exist
     */
    @Override
    protected void engineSetPadding(String paddingScheme)
            throws NoSuchPaddingException {
        core.setPadding(paddingScheme);
    }

    /**
     * Returns the block size (in bytes).
     *
     * @return the block size (in bytes), or 0 if the underlying algorithm is
     * not a block cipher
     */
    @Override
    protected int engineGetBlockSize() {
        return Constants.SM4_BLOCK_SIZE;
    }

    /**
     * Returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next <code>update</code> or
     * <code>doFinal</code> operation, given the input length
     * <code>inputLen</code> (in bytes).
     *
     * <p>This call takes into account any unprocessed (buffered) data from a
     * previous <code>update</code> call, and padding.
     *
     * <p>The actual output length of the next <code>update</code> or
     * <code>doFinal</code> call may be smaller than the length returned by
     * this method.
     *
     * @param inputLen the input length (in bytes)
     * @return the required output buffer size (in bytes)
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        return core.getOutputSize(inputLen);
    }

    /**
     * Returns the initialization vector (IV) in a new buffer.
     *
     * <p>This is useful in the case where a random IV has been created
     * (see <a href = "#init">init</a>),
     * or in the context of password-based encryption or
     * decryption, where the IV is derived from a user-provided password.
     *
     * @return the initialization vector in a new buffer, or null if the
     * underlying algorithm does not use an IV, or if the IV has not yet
     * been set.
     */
    @Override
    protected byte[] engineGetIV() {
        return core.getIV();
    }

    /**
     * Returns the parameters used with this cipher.
     *
     * <p>The returned parameters may be the same that were used to initialize
     * this cipher, or may contain the default set of parameters or a set of
     * randomly generated parameters used by the underlying cipher
     * implementation (provided that the underlying cipher implementation
     * uses a default set of parameters or creates new parameters if it needs
     * parameters but was not initialized with any).
     *
     * @return the parameters used with this cipher, or null if this cipher
     * does not use any parameters.
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return core.getParameters("SM4");
    }

    /**
     * Initializes this cipher with a key and a source of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher requires an initialization vector (IV), it will get
     * it from <code>random</code>.
     * This behaviour should only be used in encryption or key wrapping
     * mode, however.
     * When initializing a cipher that requires an IV for decryption or
     * key unwrapping, the IV
     * (same IV that was used for encryption or key wrapping) must be provided
     * explicitly as a
     * parameter, in order to get the correct result.
     *
     * <p>This method also cleans existing buffer and other related state
     * information.
     *
     * @param opmode the operation mode of this cipher (this is one of
     *               the following:
     *               <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     *               <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key    the secret key
     * @param random the source of randomness
     * @throws InvalidKeyException if the given key is inappropriate for
     *                             initializing this cipher
     */
    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        checkKeySize(key, fixedKeySize);
        core.init(opmode, key, random);
    }

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes, it will get them from <code>random</code>.
     *
     * @param opmode the operation mode of this cipher (this is one of
     *               the following:
     *               <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     *               <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key    the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     * @throws InvalidKeyException                if the given key is inappropriate for
     *                                            initializing this cipher
     * @throws InvalidAlgorithmParameterException if the given algorithm
     *                                            parameters are inappropriate for this cipher
     */
    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        checkKeySize(key, fixedKeySize);
        core.init(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameters params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        checkKeySize(key, fixedKeySize);
        core.init(opmode, key, params, random);
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code>, are processed, and the
     * result is stored in a new buffer.
     *
     * @param input       the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     *                    starts
     * @param inputLen    the input length
     * @return the new buffer with the result
     * @throws IllegalStateException if this cipher is in a wrong state
     *                               (e.g., has not been initialized)
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset,
                                  int inputLen) {
        return core.update(input, inputOffset, inputLen);
    }

    /**
     * Continues a multiple-part encryption or decryption operation
     * (depending on how this cipher was initialized), processing another data
     * part.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code>, are processed, and the
     * result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code>.
     *
     * @param input        the input buffer
     * @param inputOffset  the offset in <code>input</code> where the input
     *                     starts
     * @param inputLen     the input length
     * @param output       the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     *                     is stored
     * @return the number of bytes stored in <code>output</code>
     * @throws ShortBufferException if the given output buffer is too small
     *                              to hold the result
     */
    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
            throws ShortBufferException {
        return core.update(input, inputOffset, inputLen, output,
                outputOffset);
    }


    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     * The data is encrypted or decrypted, depending on how this cipher was
     * initialized.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code>, and any input bytes that
     * may have been buffered during a previous <code>update</code> operation,
     * are processed, with padding (if requested) being applied.
     * The result is stored in a new buffer.
     *
     * <p>The cipher is reset to its initial state (uninitialized) after this
     * call.
     *
     * @param input       the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     *                    starts
     * @param inputLen    the input length
     * @return the new buffer with the result
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        return core.doFinal(input, inputOffset, inputLen);
    }

    /**
     * Encrypts or decrypts data in a single-part operation,
     * or finishes a multiple-part operation.
     * The data is encrypted or decrypted, depending on how this cipher was
     * initialized.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code>, and any input bytes that
     * may have been buffered during a previous <code>update</code> operation,
     * are processed, with padding (if requested) being applied.
     * The result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code>.
     *
     * <p>The cipher is reset to its initial state (uninitialized) after this
     * call.
     *
     * @param input        the input buffer
     * @param inputOffset  the offset in <code>input</code> where the input
     *                     starts
     * @param inputLen     the input length
     * @param output       the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     *                     is stored
     * @return the number of bytes stored in <code>output</code>
     * @throws IllegalBlockSizeException if this cipher is a block cipher,
     *                                   no padding has been requested (only in encryption mode), and the total
     *                                   input length of the data processed by this cipher is not a multiple of
     *                                   block size
     * @throws ShortBufferException      if the given output buffer is too small
     *                                   to hold the result
     * @throws BadPaddingException       if this cipher is in decryption mode,
     *                                   and (un)padding has been requested, but the decrypted data is not
     *                                   bounded by the appropriate padding bytes
     */
    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
            throws IllegalBlockSizeException, ShortBufferException,
            BadPaddingException {
        return core.doFinal(input, inputOffset, inputLen, output,
                outputOffset);
    }

    /**
     * Returns the key size of the given key object.
     *
     * @param key the key object.
     * @return the key size of the given key object.
     * @throws InvalidKeyException if <code>key</code> is invalid.
     */
    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        byte[] encoded = key.getEncoded();
        Arrays.fill(encoded, (byte) 0);
        if (encoded.length != Constants.SM4_KEY_SIZE) {
            throw new InvalidKeyException("Invalid SM4 key length: " +
                    encoded.length + " bytes");
        }
        return Math.multiplyExact(encoded.length, 8);
    }

    /**
     * Wrap a key.
     *
     * @param key the key to be wrapped.
     * @return the wrapped key.
     * @throws IllegalBlockSizeException if this cipher is a block
     *                                   cipher, no padding has been requested, and the length of the
     *                                   encoding of the key to be wrapped is not a
     *                                   multiple of the block size.
     * @throws InvalidKeyException       if it is impossible or unsafe to
     *                                   wrap the key with this cipher (e.g., a hardware protected key is
     *                                   being passed to a software only cipher).
     */
    @Override
    protected byte[] engineWrap(Key key)
            throws IllegalBlockSizeException, InvalidKeyException {
        return core.wrap(key);
    }

    /**
     * Unwrap a previously wrapped key.
     *
     * @param wrappedKey          the key to be unwrapped.
     * @param wrappedKeyAlgorithm the algorithm the wrapped key is for.
     * @param wrappedKeyType      the type of the wrapped key.
     *                            This is one of <code>Cipher.SECRET_KEY</code>,
     *                            <code>Cipher.PRIVATE_KEY</code>, or <code>Cipher.PUBLIC_KEY</code>.
     * @return the unwrapped key.
     * @throws NoSuchAlgorithmException if no installed providers
     *                                  can create keys of type <code>wrappedKeyType</code> for the
     *                                  <code>wrappedKeyAlgorithm</code>.
     * @throws InvalidKeyException      if <code>wrappedKey</code> does not
     *                                  represent a wrapped key of type <code>wrappedKeyType</code> for
     *                                  the <code>wrappedKeyAlgorithm</code>.
     */
    @Override
    protected Key engineUnwrap(byte[] wrappedKey,
                               String wrappedKeyAlgorithm,
                               int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        return core.unwrap(wrappedKey, wrappedKeyAlgorithm,
                wrappedKeyType);
    }
}
