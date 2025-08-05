/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.wultra.security.powerauth.app.server.service.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collections;
import java.util.Set;

/**
 * MAC provider that enforces algorithm HS384.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public abstract class MACProviderHS384 extends BaseJWSProvider {
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;
    private final byte[] secret;

    protected static String getJCAAlgorithmName(JWSAlgorithm alg) throws JOSEException {
        if (alg.equals(JWSAlgorithm.HS384)) {
            return "HMACSHA384";
        }
        throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, SUPPORTED_ALGORITHMS));
    }

    protected MACProviderHS384(byte[] secret, Set<JWSAlgorithm> supportedAlgs) {
        super(supportedAlgs);
        this.secret = secret;
    }

    public SecretKey getSecretKey() {
        if (this.secret != null) {
            return new SecretKeySpec(this.secret, "MAC");
        }
        throw new IllegalStateException("Unexpected state");
    }

    public byte[] getSecret() {
        if (this.secret != null) {
            return this.secret;
        }
        throw new IllegalStateException("Unexpected state");
    }

    static {
        SUPPORTED_ALGORITHMS = Collections.singleton(JWSAlgorithm.HS384);
    }

}