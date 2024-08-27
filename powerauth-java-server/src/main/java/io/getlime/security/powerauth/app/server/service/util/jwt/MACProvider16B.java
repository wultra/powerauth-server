/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.service.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * MAC provider that allows shorter secret key size of 16 bytes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public abstract class MACProvider16B extends BaseJWSProvider {
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;
    private final byte[] secret;
    private final SecretKey secretKey;

    protected static String getJCAAlgorithmName(JWSAlgorithm alg) throws JOSEException {
        if (alg.equals(JWSAlgorithm.HS256)) {
            return "HMACSHA256";
        } else if (alg.equals(JWSAlgorithm.HS384)) {
            return "HMACSHA384";
        } else if (alg.equals(JWSAlgorithm.HS512)) {
            return "HMACSHA512";
        } else {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }
    }

    protected MACProvider16B(byte[] secret, Set<JWSAlgorithm> supportedAlgs) throws KeyLengthException {
        super(supportedAlgs);
        if (secret.length < 16) {
            throw new KeyLengthException("The secret length must be at least 128 bits");
        } else {
            this.secret = secret;
            this.secretKey = null;
        }
    }

    public SecretKey getSecretKey() {
        if (this.secretKey != null) {
            return this.secretKey;
        } else if (this.secret != null) {
            return new SecretKeySpec(this.secret, "MAC");
        } else {
            throw new IllegalStateException("Unexpected state");
        }
    }

    public byte[] getSecret() {
        if (this.secretKey != null) {
            return this.secretKey.getEncoded();
        } else if (this.secret != null) {
            return this.secret;
        } else {
            throw new IllegalStateException("Unexpected state");
        }
    }

    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet();
        algs.add(JWSAlgorithm.HS256);
        algs.add(JWSAlgorithm.HS384);
        algs.add(JWSAlgorithm.HS512);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }
}