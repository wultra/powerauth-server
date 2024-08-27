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

import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.HMAC;
import com.nimbusds.jose.crypto.utils.ConstantTimeUtils;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import java.util.Set;

/**
 * MAC verifier that allows shorter secret key size of 16 bytes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@ThreadSafe
public class MACVerifier16B extends MACProvider16B implements JWSVerifier, CriticalHeaderParamsAware {
    private final CriticalHeaderParamsDeferral critPolicy;

    public MACVerifier16B(byte[] secret) throws JOSEException {
        super(secret, SUPPORTED_ALGORITHMS);
        this.critPolicy = new CriticalHeaderParamsDeferral();
        this.critPolicy.setDeferredCriticalHeaderParams(null);
    }

    public Set<String> getProcessedCriticalHeaderParams() {
        return this.critPolicy.getProcessedCriticalHeaderParams();
    }

    public Set<String> getDeferredCriticalHeaderParams() {
        return this.critPolicy.getProcessedCriticalHeaderParams();
    }

    public boolean verify(JWSHeader header, byte[] signedContent, Base64URL signature) throws JOSEException {
        if (!this.critPolicy.headerPasses(header)) {
            return false;
        } else {
            final String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
            final byte[] expectedHMAC = HMAC.compute(jcaAlg, this.getSecretKey(), signedContent, this.getJCAContext().getProvider());
            return ConstantTimeUtils.areEqual(expectedHMAC, signature.decode());
        }
    }
}
