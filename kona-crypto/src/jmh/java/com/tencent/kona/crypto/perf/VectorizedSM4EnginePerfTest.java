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

package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.provider.SM4Engine;
import com.tencent.kona.crypto.provider.VectorizedSM4Engine;
import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for SM4 engine.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class VectorizedSM4EnginePerfTest {

    private static final byte[] KEY = {
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,
            (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
            (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
    };

    private static final byte[] DATA = TestUtils.dataMB(1);

    @State(Scope.Benchmark)
    public static class EngineHolder {

        SM4Engine engine;

        byte[] ciphertext = new byte[1024 * 1024];

        static final int stepSize = 16;

        @Setup(Level.Invocation)
        public void setup() {
            engine = new SM4Engine(KEY, true);
        }
    }


    @State(Scope.Benchmark)
    public static class EngineHolderVector {

        VectorizedSM4Engine engine;

        byte[] ciphertext = new byte[1024 * 1024];

        static final int stepSize = VectorizedSM4Engine.WALK_SIZE;

        @Setup(Level.Invocation)
        public void setup() {
            engine = new VectorizedSM4Engine(KEY, true);
        }
    }

    @Benchmark
    public byte[] processBlock(EngineHolder holder) {
        for(int i=0; i<DATA.length; i+= EngineHolder.stepSize) {
            holder.engine.processBlock(DATA, i, holder.ciphertext, i);
        }
        return holder.ciphertext;
    }

    @Benchmark
    @Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC", "--add-modules", "jdk.incubator.vector"})
    public byte[] parallelProcessBlocks(EngineHolderVector holder) {
        for (int i = 0; i < DATA.length; i += EngineHolderVector.stepSize) {
            holder.engine.parallelProcessBlocks(DATA, i, holder.ciphertext, i);
        }
        return holder.ciphertext;
    }


}
