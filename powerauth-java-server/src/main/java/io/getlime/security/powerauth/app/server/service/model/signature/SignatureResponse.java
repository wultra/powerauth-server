/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.model.signature;

import com.wultra.security.powerauth.client.v3.SignatureType;

/**
 * Verify signature response.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SignatureResponse {

    private boolean signatureValid;
    private long ctrNext;
    private byte[] ctrDataNext;
    private Integer forcedSignatureVersion;
    private SignatureType usedSignatureType;

    /**
     * Default constructor.
     */
    public SignatureResponse() {
    }

    /**
     * Verify signature response constructor.
     * @param signatureValid Whether signature is valid.
     * @param ctrNext Next numeric counter value in case signature is valid.
     * @param ctrDataNext Next hash based counter data in case signature is valid.
     * @param forcedSignatureVersion Signature version which may differ from activation version during upgrade.
     * @param usedSignatureType Signature type which was used during verification of the signature.
     */
    public SignatureResponse(boolean signatureValid, long ctrNext, byte[] ctrDataNext, Integer forcedSignatureVersion, SignatureType usedSignatureType) {
        this.signatureValid = signatureValid;
        this.ctrNext = ctrNext;
        this.ctrDataNext = ctrDataNext;
        this.forcedSignatureVersion = forcedSignatureVersion;
        this.usedSignatureType = usedSignatureType;
    }

    /**
     * Get whether signature is valid.
     * @return Whether signature is valid.
     */
    public boolean isSignatureValid() {
        return signatureValid;
    }

    /**
     * Get next numeric counter value in case signature is valid.
     * @return Next numeric counter value.
     */
    public long getCtrNext() {
        return ctrNext;
    }

    /**
     * Get next hash based counter value in case signature is valid.
     * @return Next hash based counter value.
     */
    public byte[] getCtrDataNext() {
        return ctrDataNext;
    }

    /**
     * Get signature version.
     * @return Signature version.
     */
    public Integer getForcedSignatureVersion() {
        return forcedSignatureVersion;
    }

    /**
     * Get signature type which was used during signature validation.
     * @return Signature type which was used during signature validation.
     */
    public SignatureType getUsedSignatureType() {
        return usedSignatureType;
    }
}
