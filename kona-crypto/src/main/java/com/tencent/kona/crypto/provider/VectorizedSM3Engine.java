/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.CryptoUtils;
import jdk.incubator.vector.IntVector;
import jdk.incubator.vector.VectorOperators;

import static com.tencent.kona.crypto.CryptoUtils.circularLeftShift;
import static com.tencent.kona.crypto.CryptoUtils.intsToBytes;
import static com.tencent.kona.crypto.util.Constants.SM3_DIGEST_LEN;

/**
 * SM3 engine in compliance with China's GB/T 32905-2016.
 * This implementation utilizes the Vector API
 */
public final class VectorizedSM3Engine implements Cloneable {

    // The initial value
    private static final int[] IV = {
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    // The constant table
    private static final int[] T = new int[]{
            0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
            0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
            0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
            0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,

            0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
            0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
            0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
            0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,

            0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53,
            0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
            0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4,
            0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,

            0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
            0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
            0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
            0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5
    };

    // A block is 512-bits or 16-ints.
    private static final int SM3_BLOCK_INT_SIZE = 16;

    private static final byte[][] TAILS = new byte[][]{
            new byte[]{(byte) 0x80, 0x00, 0x00, 0x00},
            new byte[]{(byte) 0x80, 0x00, 0x00},
            new byte[]{(byte) 0x80, 0x00},
            new byte[]{(byte) 0x80}};

    // Digest register
    private int[] v;

    // W0..W67
    private int[] w = new int[68];
    //W'0..W'63
    private int[] wPrime = new int[64];
    // A word is 4-bytes or 1-integer.
    private byte[] word = new byte[4];
    private int wordOffset;

    // A message block is 512-bits or 16-integers.
    private int[] block = new int[SM3_BLOCK_INT_SIZE];
    private int blockOffset;

    private long countOfBytes;

    public VectorizedSM3Engine() {
        reset();
    }

    public void reset() {
        v = IV.clone();
        wordOffset = 0;
        blockOffset = 0;
        countOfBytes = 0;
    }

    public void update(byte message) {
        word[wordOffset++] = message;

        if (wordOffset >= word.length) {
            processWord(this.word,0);
            this.wordOffset=0;
        }

        countOfBytes++;
    }

    public void update(byte[] message) {
        update(message, 0, message.length);
    }

    public void update(byte[] message, int offset, int length) {
        int consumed = 0;

        // Process the current word if any
        if (wordOffset != 0) {
            while (consumed < length) {
                word[wordOffset++] = message[offset + consumed++];
                if (wordOffset >= word.length) {
                    processWord(this.word,0);
                    this.wordOffset = 0;
                    break;
                }
            }
        }

        // Process one word in each iteration
        while (consumed < length - 3) {
            this.processWord(message,offset+consumed);
            consumed+=4;
        }

        // Process the remainder bytes if any
        while (consumed < length) {
            word[wordOffset++] = message[offset + consumed++];
        }

        countOfBytes += length;
    }

    public void doFinal(byte[] out) {
        doFinal(out, 0);
    }

    public void doFinal(byte[] out, int offset) {
        long messageLength = countOfBytes << 3;

        update(TAILS[wordOffset]);

        processLength(messageLength);
        processBlock();
        intsToBytes(v, 0, out, offset, v.length);

        reset();
    }

    public byte[] doFinal() {
        byte[] digest = new byte[SM3_DIGEST_LEN];
        doFinal(digest);
        return digest;
    }

    private void processWord(byte[] word,int offset) {
        block[blockOffset]
                = ((word[offset] & 0xFF) << 24)
                | ((word[offset+1] & 0xFF) << 16)
                | ((word[offset+2] & 0xFF) << 8)
                | ((word[offset+3] & 0xFF));
        blockOffset++;

        if (blockOffset >= SM3_BLOCK_INT_SIZE) {
            processBlock();
        }
    }

    private void processBlock() {
        expand();
        compress();
        blockOffset = 0;
    }

    // The length of message in bytes
    private void processLength(long messageLength) {
        if (blockOffset > SM3_BLOCK_INT_SIZE - 2) {
            block[blockOffset] = 0;
            blockOffset++;

            processBlock();
        }

        while (blockOffset < SM3_BLOCK_INT_SIZE - 2) {
            block[blockOffset] = 0;
            blockOffset++;
        }

        block[blockOffset++] = (int) (messageLength >>> 32);
        block[blockOffset++] = (int) messageLength;
    }

    // Block expansion.
    //  W[i] and W[i]' = W[i] ^ W[i+4]
    private void expand() {
//         W0..W15

        for (int i = 0; i < this.block.length; ++i) {
            this.w[i] = this.block[i];
        }

        IntVector v16, v13, v9, v6, v3, t0, t1; // w_i-16, w_i-13, w_i-9, w_i-6, w_i-3, t0, t1
        v16 = IntVector.fromArray(IntVector.SPECIES_128, w, 0);
        v9 = IntVector.fromArray(IntVector.SPECIES_128, w, 7);
        v6 = IntVector.fromArray(IntVector.SPECIES_128, w, 10);
        v3 = IntVector.fromArray(IntVector.SPECIES_128, w, 13);

        t0 = IntVector.fromArray(IntVector.SPECIES_128, w, 4); // calculate w'0~w'3
        t0.lanewise(VectorOperators.XOR, v16).intoArray(wPrime, 0);

        for (int i = 16; i < 65; i += 3) {
            v13 = IntVector.fromArray(IntVector.SPECIES_128, w, i - 13);

            t0 = v16.lanewise(VectorOperators.XOR, v9).lanewise(VectorOperators.XOR, v3.lanewise(VectorOperators.ROL, 15));
            t0 = t0.lanewise(VectorOperators.XOR, t0.lanewise(VectorOperators.ROL, 15)).lanewise(VectorOperators.XOR, t0.lanewise(VectorOperators.ROL, 23));
            t1 = v13.lanewise(VectorOperators.ROL, 7).lanewise(VectorOperators.XOR, v6);
            t0 = t1.lanewise(VectorOperators.XOR, t0);
            t0.intoArray(w, i);


            t1 = v13.lanewise(VectorOperators.XOR, v9);
            t1.intoArray(wPrime, i - 13);

            v16 = v13;
            v9 = v6;
            v6 = v3;
            v3 = t0;

        }
        w[67] = p1(w[67 - 16] ^ w[67 - 9] ^ CryptoUtils.circularLeftShift(w[67 - 3], 15)) ^ CryptoUtils.circularLeftShift(w[67 - 13], 7) ^ w[67 - 6];

        for (int i = 54; i < 62; i += 4) {
            t0 = IntVector.fromArray(IntVector.SPECIES_128, w, i);
            t1 = IntVector.fromArray(IntVector.SPECIES_128, w, i + 4);
            t0 = t0.lanewise(VectorOperators.XOR, t1);
            t0.intoArray(wPrime, i);
        }
        wPrime[63] = w[63] ^ w[67];
        wPrime[62] = w[62] ^ w[66];
    }

    // Compress function
    private void compress() {
        int a = v[0];
        int b = v[1];
        int c = v[2];
        int d = v[3];
        int e = v[4];
        int f = v[5];
        int g = v[6];
        int h = v[7];

        for (int i = 0; i < 16; i++) {
            int a12 = circularLeftShift(a, 12);
            int ss1 = circularLeftShift(a12 + e + T[i], 7);
            int ss2 = ss1 ^ a12;

            int tt1 = ff0(a, b, c) + d + ss2 + (wPrime[i]);
            int tt2 = gg0(e, f, g) + h + ss1 + w[i];

            d = c;
            c = circularLeftShift(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = circularLeftShift(f, 19);
            f = e;
            e = p0(tt2);
        }

        for (int i = 16; i < 64; i++) {
            int a12 = circularLeftShift(a, 12);
            int ss1 = circularLeftShift(a12 + e + T[i], 7);
            int ss2 = ss1 ^ a12;

            int tt1 = ff1(a, b, c) + d + ss2 + (wPrime[i]);
            int tt2 = gg1(e, f, g) + h + ss1 + w[i];

            d = c;
            c = circularLeftShift(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = circularLeftShift(f, 19);
            f = e;
            e = p0(tt2);
        }

        v[0] ^= a;
        v[1] ^= b;
        v[2] ^= c;
        v[3] ^= d;
        v[4] ^= e;
        v[5] ^= f;
        v[6] ^= g;
        v[7] ^= h;
    }

    public VectorizedSM3Engine clone() throws CloneNotSupportedException {
        VectorizedSM3Engine clone = (VectorizedSM3Engine) super.clone();
        clone.v = v.clone();
        clone.w = w.clone();
        clone.wPrime = wPrime.clone();
        clone.word = word.clone();
        clone.block = block.clone();
        return clone;
    }

    /* ***** Boolean functions ***** */

    // i = [0, 15]
    private static int ff0(int x, int y, int z) {
        return x ^ y ^ z;
    }

    // i = [16, 63]
    private static int ff1(int x, int y, int z) {
        return (x & y) | (x & z) | (y & z);
    }

    // i = [0, 15]
    private static int gg0(int x, int y, int z) {
        return ff0(x, y, z);
    }

    // i = [16, 63]
    private static int gg1(int x, int y, int z) {
        return (x & y) | ((~x) & z);
    }

    /* ***** Permutation functions ***** */


    private static int p0(final int x)
    {
        final int r9 = ((x << 9) | (x >>> (32 - 9)));
        final int r17 = ((x << 17) | (x >>> (32 - 17)));
        return (x ^ r9 ^ r17);
    }

    private  static int p1(final int x)
    {
        final int r15 = ((x << 15) | (x >>> (32 - 15)));
        final int r23 = ((x << 23) | (x >>> (32 - 23)));
        return (x ^ r15 ^ r23);
    }
}