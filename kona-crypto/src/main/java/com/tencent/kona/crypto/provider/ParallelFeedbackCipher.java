package com.tencent.kona.crypto.provider;


/**
 * This class represents a block cipher in one of its modes. It wraps
 * a ParallelSymmetricCipher maintaining the mode state and providing
 * the capability to encrypt amounts of data larger than a single block.
 */
abstract class ParallelFeedbackCipher extends FeedbackCipher {
    final int walkSize;
    final ParallelSymmetricCipher embeddedCipher;

    ParallelFeedbackCipher(ParallelSymmetricCipher embeddedCipher) {
        super(embeddedCipher);
        this.embeddedCipher = embeddedCipher;
        walkSize = embeddedCipher.getWalkSize();
    }
}
