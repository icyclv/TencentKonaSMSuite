package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Constants;

import java.security.InvalidKeyException;

class VectorizedSM4Crypt extends ParallelSymmetricCipher {

    private VectorizedSM4Engine engine;

    @Override
    int getBlockSize() {
        return Constants.SM4_BLOCK_SIZE;
    }

    @Override
    int getWalkSize() {
        return VectorizedSM4Engine.WALK_SIZE;
    }

    @Override
    void init(boolean decrypting, String algorithm, byte[] key)
            throws InvalidKeyException {
        if (!algorithm.equalsIgnoreCase("VectorizedSM4")) {
            throw new InvalidKeyException("The algorithm must be VectorizedSM4");
        }

        engine = new VectorizedSM4Engine(key, !decrypting);
    }

    @Override
    void encryptBlock(byte[] plain, int plainOffset,
                      byte[] cipher, int cipherOffset) {
        engine.processBlock(plain, plainOffset, cipher, cipherOffset);
    }

    @Override
    void decryptBlock(byte[] cipher, int cipherOffset,
                      byte[] plain, int plainOffset) {
        engine.processBlock(cipher, cipherOffset, plain, plainOffset);
    }

    @Override
    void parallelEncryptBlock(byte[] plain, int plainOffset, byte[] cipher, int cipherOffset) {
        engine.parallelProcessBlocks(plain, plainOffset, cipher, cipherOffset);
    }

    @Override
    void parallelDecryptBlock(byte[] cipher, int cipherOffset, byte[] plain, int plainOffset) {
        engine.parallelProcessBlocks(cipher, cipherOffset, plain, plainOffset);
    }
}
