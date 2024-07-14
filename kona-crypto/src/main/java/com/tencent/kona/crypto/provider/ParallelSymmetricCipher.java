package com.tencent.kona.crypto.provider;

import java.security.InvalidKeyException;

/**
 * This abstract class represents the core of all block ciphers. It allows to
 * initialize the cipher and parallel encrypt/decrypt blocks.
 */
abstract class ParallelSymmetricCipher extends SymmetricCipher {


    abstract void parallelEncryptBlock(byte[] plain, int plainOffset,
                                       byte[] cipher, int cipherOffset);

    abstract void parallelDecryptBlock(byte[] cipher, int cipherOffset, byte[] plain, int plainOffset);

    abstract int getWalkSize();
}
