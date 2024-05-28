/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * This file is generated by FieldGen.java. Do not modify it directly.
 */

package com.tencent.kona.sun.security.util.math.intpoly;

import java.math.BigInteger;
public final class IntegerPolynomial448 extends IntegerPolynomial {
    private static final int BITS_PER_LIMB = 28;
    private static final int NUM_LIMBS = 16;
    private static final int MAX_ADDS = 1;
    public static final BigInteger MODULUS = evaluateModulus();
    private static final long CARRY_ADD = 1 << 27;

    public static final IntegerPolynomial448 ONE = new IntegerPolynomial448();

    private IntegerPolynomial448() {

        super(BITS_PER_LIMB, NUM_LIMBS, MAX_ADDS, MODULUS);

    }
    //(224%nat,-1)::(0%nat,-1)::nil.
    private static BigInteger evaluateModulus() {
        BigInteger result = BigInteger.valueOf(2).pow(448);
        result = result.subtract(BigInteger.valueOf(1).shiftLeft(224));
        result = result.subtract(BigInteger.valueOf(1));
        return result;
    }
    @Override
    protected void reduceIn(long[] limbs, long v, int i) {
        limbs[i - 8] += v;
        limbs[i - 16] += v;
    }
    @Override
    protected void finalCarryReduceLast(long[] limbs) {
        long c = limbs[15] >> 28;
        limbs[15] -= c << 28;
        limbs[8] += c;
        limbs[0] += c;
    }
    private void carryReduce(long[] r, long c0, long c1, long c2, long c3, long c4, long c5, long c6, long c7, long c8, long c9, long c10, long c11, long c12, long c13, long c14, long c15, long c16, long c17, long c18, long c19, long c20, long c21, long c22, long c23, long c24, long c25, long c26, long c27, long c28, long c29, long c30) {
        long c31 = 0;
        //reduce from position 24
        c16 += c24;
        c8 += c24;
        //reduce from position 25
        c17 += c25;
        c9 += c25;
        //reduce from position 26
        c18 += c26;
        c10 += c26;
        //reduce from position 27
        c19 += c27;
        c11 += c27;
        //reduce from position 28
        c20 += c28;
        c12 += c28;
        //reduce from position 29
        c21 += c29;
        c13 += c29;
        //reduce from position 30
        c22 += c30;
        c14 += c30;
        //reduce from position 20
        c12 += c20;
        c4 += c20;
        //reduce from position 21
        c13 += c21;
        c5 += c21;
        //reduce from position 22
        c14 += c22;
        c6 += c22;
        //reduce from position 23
        c15 += c23;
        c7 += c23;

        carryReduce0(r, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31);
    }
    void carryReduce0(long[] r, long c0, long c1, long c2, long c3, long c4, long c5, long c6, long c7, long c8, long c9, long c10, long c11, long c12, long c13, long c14, long c15, long c16, long c17, long c18, long c19, long c20, long c21, long c22, long c23, long c24, long c25, long c26, long c27, long c28, long c29, long c30, long c31) {

        //carry from position 14
        long t0 = (c14 + CARRY_ADD) >> 28;
        c14 -= (t0 << 28);
        c15 += t0;
        //carry from position 15
        t0 = (c15 + CARRY_ADD) >> 28;
        c15 -= (t0 << 28);
        c16 += t0;
        //reduce from position 16
        c8 += c16;
        c0 += c16;
        //reduce from position 17
        c9 += c17;
        c1 += c17;
        //reduce from position 18
        c10 += c18;
        c2 += c18;
        //reduce from position 19
        c11 += c19;
        c3 += c19;
        //carry from position 0
        t0 = (c0 + CARRY_ADD) >> 28;
        c0 -= (t0 << 28);
        c1 += t0;
        //carry from position 1
        t0 = (c1 + CARRY_ADD) >> 28;
        c1 -= (t0 << 28);
        c2 += t0;
        //carry from position 2
        t0 = (c2 + CARRY_ADD) >> 28;
        c2 -= (t0 << 28);
        c3 += t0;
        //carry from position 3
        t0 = (c3 + CARRY_ADD) >> 28;
        c3 -= (t0 << 28);
        c4 += t0;
        //carry from position 4
        t0 = (c4 + CARRY_ADD) >> 28;
        c4 -= (t0 << 28);
        c5 += t0;
        //carry from position 5
        t0 = (c5 + CARRY_ADD) >> 28;
        c5 -= (t0 << 28);
        c6 += t0;
        //carry from position 6
        t0 = (c6 + CARRY_ADD) >> 28;
        c6 -= (t0 << 28);
        c7 += t0;
        //carry from position 7
        t0 = (c7 + CARRY_ADD) >> 28;
        c7 -= (t0 << 28);
        c8 += t0;
        //carry from position 8
        t0 = (c8 + CARRY_ADD) >> 28;
        c8 -= (t0 << 28);
        c9 += t0;
        //carry from position 9
        t0 = (c9 + CARRY_ADD) >> 28;
        c9 -= (t0 << 28);
        c10 += t0;
        //carry from position 10
        t0 = (c10 + CARRY_ADD) >> 28;
        c10 -= (t0 << 28);
        c11 += t0;
        //carry from position 11
        t0 = (c11 + CARRY_ADD) >> 28;
        c11 -= (t0 << 28);
        c12 += t0;
        //carry from position 12
        t0 = (c12 + CARRY_ADD) >> 28;
        c12 -= (t0 << 28);
        c13 += t0;
        //carry from position 13
        t0 = (c13 + CARRY_ADD) >> 28;
        c13 -= (t0 << 28);
        c14 += t0;
        //carry from position 14
        t0 = (c14 + CARRY_ADD) >> 28;
        c14 -= (t0 << 28);
        c15 += t0;

        r[0] = c0;
        r[1] = c1;
        r[2] = c2;
        r[3] = c3;
        r[4] = c4;
        r[5] = c5;
        r[6] = c6;
        r[7] = c7;
        r[8] = c8;
        r[9] = c9;
        r[10] = c10;
        r[11] = c11;
        r[12] = c12;
        r[13] = c13;
        r[14] = c14;
        r[15] = c15;
    }
    private void carryReduce(long[] r, long c0, long c1, long c2, long c3, long c4, long c5, long c6, long c7, long c8, long c9, long c10, long c11, long c12, long c13, long c14, long c15) {
        long c16 = 0;
        //carry from position 14
        long t0 = (c14 + CARRY_ADD) >> 28;
        c14 -= (t0 << 28);
        c15 += t0;
        //carry from position 15
        t0 = (c15 + CARRY_ADD) >> 28;
        c15 -= (t0 << 28);
        c16 += t0;
        //reduce from position 16
        c8 += c16;
        c0 += c16;
        //carry from position 0
        t0 = (c0 + CARRY_ADD) >> 28;
        c0 -= (t0 << 28);
        c1 += t0;
        //carry from position 1
        t0 = (c1 + CARRY_ADD) >> 28;
        c1 -= (t0 << 28);
        c2 += t0;
        //carry from position 2
        t0 = (c2 + CARRY_ADD) >> 28;
        c2 -= (t0 << 28);
        c3 += t0;
        //carry from position 3
        t0 = (c3 + CARRY_ADD) >> 28;
        c3 -= (t0 << 28);
        c4 += t0;
        //carry from position 4
        t0 = (c4 + CARRY_ADD) >> 28;
        c4 -= (t0 << 28);
        c5 += t0;
        //carry from position 5
        t0 = (c5 + CARRY_ADD) >> 28;
        c5 -= (t0 << 28);
        c6 += t0;
        //carry from position 6
        t0 = (c6 + CARRY_ADD) >> 28;
        c6 -= (t0 << 28);
        c7 += t0;
        //carry from position 7
        t0 = (c7 + CARRY_ADD) >> 28;
        c7 -= (t0 << 28);
        c8 += t0;
        //carry from position 8
        t0 = (c8 + CARRY_ADD) >> 28;
        c8 -= (t0 << 28);
        c9 += t0;
        //carry from position 9
        t0 = (c9 + CARRY_ADD) >> 28;
        c9 -= (t0 << 28);
        c10 += t0;
        //carry from position 10
        t0 = (c10 + CARRY_ADD) >> 28;
        c10 -= (t0 << 28);
        c11 += t0;
        //carry from position 11
        t0 = (c11 + CARRY_ADD) >> 28;
        c11 -= (t0 << 28);
        c12 += t0;
        //carry from position 12
        t0 = (c12 + CARRY_ADD) >> 28;
        c12 -= (t0 << 28);
        c13 += t0;
        //carry from position 13
        t0 = (c13 + CARRY_ADD) >> 28;
        c13 -= (t0 << 28);
        c14 += t0;
        //carry from position 14
        t0 = (c14 + CARRY_ADD) >> 28;
        c14 -= (t0 << 28);
        c15 += t0;

        r[0] = c0;
        r[1] = c1;
        r[2] = c2;
        r[3] = c3;
        r[4] = c4;
        r[5] = c5;
        r[6] = c6;
        r[7] = c7;
        r[8] = c8;
        r[9] = c9;
        r[10] = c10;
        r[11] = c11;
        r[12] = c12;
        r[13] = c13;
        r[14] = c14;
        r[15] = c15;
    }
    @Override
    protected int mult(long[] a, long[] b, long[] r) {
        long c0 = (a[0] * b[0]);
        long c1 = (a[0] * b[1]) + (a[1] * b[0]);
        long c2 = (a[0] * b[2]) + (a[1] * b[1]) + (a[2] * b[0]);
        long c3 = (a[0] * b[3]) + (a[1] * b[2]) + (a[2] * b[1]) + (a[3] * b[0]);
        long c4 = (a[0] * b[4]) + (a[1] * b[3]) + (a[2] * b[2]) + (a[3] * b[1]) + (a[4] * b[0]);
        long c5 = (a[0] * b[5]) + (a[1] * b[4]) + (a[2] * b[3]) + (a[3] * b[2]) + (a[4] * b[1]) + (a[5] * b[0]);
        long c6 = (a[0] * b[6]) + (a[1] * b[5]) + (a[2] * b[4]) + (a[3] * b[3]) + (a[4] * b[2]) + (a[5] * b[1]) + (a[6] * b[0]);
        long c7 = (a[0] * b[7]) + (a[1] * b[6]) + (a[2] * b[5]) + (a[3] * b[4]) + (a[4] * b[3]) + (a[5] * b[2]) + (a[6] * b[1]) + (a[7] * b[0]);
        long c8 = (a[0] * b[8]) + (a[1] * b[7]) + (a[2] * b[6]) + (a[3] * b[5]) + (a[4] * b[4]) + (a[5] * b[3]) + (a[6] * b[2]) + (a[7] * b[1]) + (a[8] * b[0]);
        long c9 = (a[0] * b[9]) + (a[1] * b[8]) + (a[2] * b[7]) + (a[3] * b[6]) + (a[4] * b[5]) + (a[5] * b[4]) + (a[6] * b[3]) + (a[7] * b[2]) + (a[8] * b[1]) + (a[9] * b[0]);
        long c10 = (a[0] * b[10]) + (a[1] * b[9]) + (a[2] * b[8]) + (a[3] * b[7]) + (a[4] * b[6]) + (a[5] * b[5]) + (a[6] * b[4]) + (a[7] * b[3]) + (a[8] * b[2]) + (a[9] * b[1]) + (a[10] * b[0]);
        long c11 = (a[0] * b[11]) + (a[1] * b[10]) + (a[2] * b[9]) + (a[3] * b[8]) + (a[4] * b[7]) + (a[5] * b[6]) + (a[6] * b[5]) + (a[7] * b[4]) + (a[8] * b[3]) + (a[9] * b[2]) + (a[10] * b[1]) + (a[11] * b[0]);
        long c12 = (a[0] * b[12]) + (a[1] * b[11]) + (a[2] * b[10]) + (a[3] * b[9]) + (a[4] * b[8]) + (a[5] * b[7]) + (a[6] * b[6]) + (a[7] * b[5]) + (a[8] * b[4]) + (a[9] * b[3]) + (a[10] * b[2]) + (a[11] * b[1]) + (a[12] * b[0]);
        long c13 = (a[0] * b[13]) + (a[1] * b[12]) + (a[2] * b[11]) + (a[3] * b[10]) + (a[4] * b[9]) + (a[5] * b[8]) + (a[6] * b[7]) + (a[7] * b[6]) + (a[8] * b[5]) + (a[9] * b[4]) + (a[10] * b[3]) + (a[11] * b[2]) + (a[12] * b[1]) + (a[13] * b[0]);
        long c14 = (a[0] * b[14]) + (a[1] * b[13]) + (a[2] * b[12]) + (a[3] * b[11]) + (a[4] * b[10]) + (a[5] * b[9]) + (a[6] * b[8]) + (a[7] * b[7]) + (a[8] * b[6]) + (a[9] * b[5]) + (a[10] * b[4]) + (a[11] * b[3]) + (a[12] * b[2]) + (a[13] * b[1]) + (a[14] * b[0]);
        long c15 = (a[0] * b[15]) + (a[1] * b[14]) + (a[2] * b[13]) + (a[3] * b[12]) + (a[4] * b[11]) + (a[5] * b[10]) + (a[6] * b[9]) + (a[7] * b[8]) + (a[8] * b[7]) + (a[9] * b[6]) + (a[10] * b[5]) + (a[11] * b[4]) + (a[12] * b[3]) + (a[13] * b[2]) + (a[14] * b[1]) + (a[15] * b[0]);
        long c16 = (a[1] * b[15]) + (a[2] * b[14]) + (a[3] * b[13]) + (a[4] * b[12]) + (a[5] * b[11]) + (a[6] * b[10]) + (a[7] * b[9]) + (a[8] * b[8]) + (a[9] * b[7]) + (a[10] * b[6]) + (a[11] * b[5]) + (a[12] * b[4]) + (a[13] * b[3]) + (a[14] * b[2]) + (a[15] * b[1]);
        long c17 = (a[2] * b[15]) + (a[3] * b[14]) + (a[4] * b[13]) + (a[5] * b[12]) + (a[6] * b[11]) + (a[7] * b[10]) + (a[8] * b[9]) + (a[9] * b[8]) + (a[10] * b[7]) + (a[11] * b[6]) + (a[12] * b[5]) + (a[13] * b[4]) + (a[14] * b[3]) + (a[15] * b[2]);
        long c18 = (a[3] * b[15]) + (a[4] * b[14]) + (a[5] * b[13]) + (a[6] * b[12]) + (a[7] * b[11]) + (a[8] * b[10]) + (a[9] * b[9]) + (a[10] * b[8]) + (a[11] * b[7]) + (a[12] * b[6]) + (a[13] * b[5]) + (a[14] * b[4]) + (a[15] * b[3]);
        long c19 = (a[4] * b[15]) + (a[5] * b[14]) + (a[6] * b[13]) + (a[7] * b[12]) + (a[8] * b[11]) + (a[9] * b[10]) + (a[10] * b[9]) + (a[11] * b[8]) + (a[12] * b[7]) + (a[13] * b[6]) + (a[14] * b[5]) + (a[15] * b[4]);
        long c20 = (a[5] * b[15]) + (a[6] * b[14]) + (a[7] * b[13]) + (a[8] * b[12]) + (a[9] * b[11]) + (a[10] * b[10]) + (a[11] * b[9]) + (a[12] * b[8]) + (a[13] * b[7]) + (a[14] * b[6]) + (a[15] * b[5]);
        long c21 = (a[6] * b[15]) + (a[7] * b[14]) + (a[8] * b[13]) + (a[9] * b[12]) + (a[10] * b[11]) + (a[11] * b[10]) + (a[12] * b[9]) + (a[13] * b[8]) + (a[14] * b[7]) + (a[15] * b[6]);
        long c22 = (a[7] * b[15]) + (a[8] * b[14]) + (a[9] * b[13]) + (a[10] * b[12]) + (a[11] * b[11]) + (a[12] * b[10]) + (a[13] * b[9]) + (a[14] * b[8]) + (a[15] * b[7]);
        long c23 = (a[8] * b[15]) + (a[9] * b[14]) + (a[10] * b[13]) + (a[11] * b[12]) + (a[12] * b[11]) + (a[13] * b[10]) + (a[14] * b[9]) + (a[15] * b[8]);
        long c24 = (a[9] * b[15]) + (a[10] * b[14]) + (a[11] * b[13]) + (a[12] * b[12]) + (a[13] * b[11]) + (a[14] * b[10]) + (a[15] * b[9]);
        long c25 = (a[10] * b[15]) + (a[11] * b[14]) + (a[12] * b[13]) + (a[13] * b[12]) + (a[14] * b[11]) + (a[15] * b[10]);
        long c26 = (a[11] * b[15]) + (a[12] * b[14]) + (a[13] * b[13]) + (a[14] * b[12]) + (a[15] * b[11]);
        long c27 = (a[12] * b[15]) + (a[13] * b[14]) + (a[14] * b[13]) + (a[15] * b[12]);
        long c28 = (a[13] * b[15]) + (a[14] * b[14]) + (a[15] * b[13]);
        long c29 = (a[14] * b[15]) + (a[15] * b[14]);
        long c30 = (a[15] * b[15]);

        carryReduce(r, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30);
        return 0;
    }
    @Override
    protected void reduce(long[] a) {
        carryReduce(a, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
    }
    @Override
    protected int square(long[] a, long[] r) {
        long c0 = (a[0] * a[0]);
        long c1 = 2 * ((a[0] * a[1]));
        long c2 = 2 * ((a[0] * a[2])) + (a[1] * a[1]);
        long c3 = 2 * ((a[0] * a[3]) + (a[1] * a[2]));
        long c4 = 2 * ((a[0] * a[4]) + (a[1] * a[3])) + (a[2] * a[2]);
        long c5 = 2 * ((a[0] * a[5]) + (a[1] * a[4]) + (a[2] * a[3]));
        long c6 = 2 * ((a[0] * a[6]) + (a[1] * a[5]) + (a[2] * a[4])) + (a[3] * a[3]);
        long c7 = 2 * ((a[0] * a[7]) + (a[1] * a[6]) + (a[2] * a[5]) + (a[3] * a[4]));
        long c8 = 2 * ((a[0] * a[8]) + (a[1] * a[7]) + (a[2] * a[6]) + (a[3] * a[5])) + (a[4] * a[4]);
        long c9 = 2 * ((a[0] * a[9]) + (a[1] * a[8]) + (a[2] * a[7]) + (a[3] * a[6]) + (a[4] * a[5]));
        long c10 = 2 * ((a[0] * a[10]) + (a[1] * a[9]) + (a[2] * a[8]) + (a[3] * a[7]) + (a[4] * a[6])) + (a[5] * a[5]);
        long c11 = 2 * ((a[0] * a[11]) + (a[1] * a[10]) + (a[2] * a[9]) + (a[3] * a[8]) + (a[4] * a[7]) + (a[5] * a[6]));
        long c12 = 2 * ((a[0] * a[12]) + (a[1] * a[11]) + (a[2] * a[10]) + (a[3] * a[9]) + (a[4] * a[8]) + (a[5] * a[7])) + (a[6] * a[6]);
        long c13 = 2 * ((a[0] * a[13]) + (a[1] * a[12]) + (a[2] * a[11]) + (a[3] * a[10]) + (a[4] * a[9]) + (a[5] * a[8]) + (a[6] * a[7]));
        long c14 = 2 * ((a[0] * a[14]) + (a[1] * a[13]) + (a[2] * a[12]) + (a[3] * a[11]) + (a[4] * a[10]) + (a[5] * a[9]) + (a[6] * a[8])) + (a[7] * a[7]);
        long c15 = 2 * ((a[0] * a[15]) + (a[1] * a[14]) + (a[2] * a[13]) + (a[3] * a[12]) + (a[4] * a[11]) + (a[5] * a[10]) + (a[6] * a[9]) + (a[7] * a[8]));
        long c16 = 2 * ((a[1] * a[15]) + (a[2] * a[14]) + (a[3] * a[13]) + (a[4] * a[12]) + (a[5] * a[11]) + (a[6] * a[10]) + (a[7] * a[9])) + (a[8] * a[8]);
        long c17 = 2 * ((a[2] * a[15]) + (a[3] * a[14]) + (a[4] * a[13]) + (a[5] * a[12]) + (a[6] * a[11]) + (a[7] * a[10]) + (a[8] * a[9]));
        long c18 = 2 * ((a[3] * a[15]) + (a[4] * a[14]) + (a[5] * a[13]) + (a[6] * a[12]) + (a[7] * a[11]) + (a[8] * a[10])) + (a[9] * a[9]);
        long c19 = 2 * ((a[4] * a[15]) + (a[5] * a[14]) + (a[6] * a[13]) + (a[7] * a[12]) + (a[8] * a[11]) + (a[9] * a[10]));
        long c20 = 2 * ((a[5] * a[15]) + (a[6] * a[14]) + (a[7] * a[13]) + (a[8] * a[12]) + (a[9] * a[11])) + (a[10] * a[10]);
        long c21 = 2 * ((a[6] * a[15]) + (a[7] * a[14]) + (a[8] * a[13]) + (a[9] * a[12]) + (a[10] * a[11]));
        long c22 = 2 * ((a[7] * a[15]) + (a[8] * a[14]) + (a[9] * a[13]) + (a[10] * a[12])) + (a[11] * a[11]);
        long c23 = 2 * ((a[8] * a[15]) + (a[9] * a[14]) + (a[10] * a[13]) + (a[11] * a[12]));
        long c24 = 2 * ((a[9] * a[15]) + (a[10] * a[14]) + (a[11] * a[13])) + (a[12] * a[12]);
        long c25 = 2 * ((a[10] * a[15]) + (a[11] * a[14]) + (a[12] * a[13]));
        long c26 = 2 * ((a[11] * a[15]) + (a[12] * a[14])) + (a[13] * a[13]);
        long c27 = 2 * ((a[12] * a[15]) + (a[13] * a[14]));
        long c28 = 2 * ((a[13] * a[15])) + (a[14] * a[14]);
        long c29 = 2 * ((a[14] * a[15]));
        long c30 = (a[15] * a[15]);

        carryReduce(r, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30);
        return 0;
    }
}
