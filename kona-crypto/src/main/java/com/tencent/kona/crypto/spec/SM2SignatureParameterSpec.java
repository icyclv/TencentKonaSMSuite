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

package com.tencent.kona.crypto.spec;

import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

/**
 * The SM2 signature parameter specification.
 */
public class SM2SignatureParameterSpec implements AlgorithmParameterSpec {

    private byte[] id = "1234567812345678".getBytes();

    private final ECPublicKey publicKey;

    public SM2SignatureParameterSpec(byte[] id, ECPublicKey publicKey) {
        Objects.requireNonNull(publicKey);

        if (id != null) {
            if (id.length >= 8192) {
                throw new IllegalArgumentException(
                        "The length of ID must be less than 8192-bytes");
            }

            this.id = id.clone();
        }

        this.publicKey = publicKey;
    }

    public SM2SignatureParameterSpec(ECPublicKey publicKey) {
        this(null, publicKey);
    }

    public byte[] getId() {
        return id.clone();
    }

    public ECPublicKey getPublicKey() {
        return publicKey;
    }
}
