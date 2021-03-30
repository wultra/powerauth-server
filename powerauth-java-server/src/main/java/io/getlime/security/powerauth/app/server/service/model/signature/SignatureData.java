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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;

import java.util.Map;

/**
 * Data related to both online and offline signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SignatureData {

    private byte[] data;
    private String signature;
    private String signatureVersion;
    private PowerAuthSignatureFormat signatureFormat;
    private Map<String, Object> additionalInfo;
    private Integer forcedSignatureVersion;

    /**
     * Default constructor.
     */
    public SignatureData() {
    }

    /**
     * Signature data constructur.
     * @param data Signed data.
     * @param signature Data signature.
     * @param signatureFormat Format of signature
     * @param signatureVersion Version of requested signature
     * @param additionalInfo Additional information related to the signature.
     * @param forcedSignatureVersion Forced signature version during upgrade.
     */
    public SignatureData(byte[] data, String signature, PowerAuthSignatureFormat signatureFormat, String signatureVersion, Map<String, Object> additionalInfo, Integer forcedSignatureVersion) {
        this.data = data;
        this.signature = signature;
        this.signatureVersion = signatureVersion;
        this.signatureFormat = signatureFormat;
        this.additionalInfo = additionalInfo;
        this.forcedSignatureVersion = forcedSignatureVersion;
    }

    /**
     * Get signed data.
     * @return Signed data.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Get data signature.
     * @return Data signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Get requested signature version.
     * @return Signature version.
     */
    public String getSignatureVersion() {
        return signatureVersion;
    }

    /**
     * Get signature format.
     * @return Signature format.
     */
    public PowerAuthSignatureFormat getSignatureFormat() {
        return signatureFormat;
    }

    /**
     * Get additional information related to the signature.
     * @return Additional information related to the signature.
     */
    public Map<String, Object> getAdditionalInfo() {
        return additionalInfo;
    }

    /**
     * Get forced signature version.
     * @return Forced signature version.
     */
    public Integer getForcedSignatureVersion() {
        return forcedSignatureVersion;
    }
}
