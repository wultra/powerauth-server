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

import com.wultra.security.powerauth.client.v3.KeyValueMap;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;

/**
 * Data related to both online and offline signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SignatureData {

    private byte[] data;
    private SignatureRequestData requestData;
    private String signature;
    private String signatureVersion;
    private SignatureConfiguration signatureConfiguration;
    private KeyValueMap additionalInfo;
    private Integer forcedSignatureVersion;

    /**
     * Default constructor.
     */
    public SignatureData() {
    }

    /**
     * Signature data constructor.
     * @param data Signed data.
     * @param signature Data signature.
     * @param signatureConfiguration Format of signature with associated parameters.
     * @param signatureVersion Version of requested signature
     * @param additionalInfo Additional information related to the signature.
     * @param forcedSignatureVersion Forced signature version during upgrade.
     */
    public SignatureData(byte[] data, String signature, SignatureConfiguration signatureConfiguration, String signatureVersion, KeyValueMap additionalInfo, Integer forcedSignatureVersion) {
        this.data = data;
        this.signature = signature;
        this.signatureVersion = signatureVersion;
        this.signatureConfiguration = signatureConfiguration;
        this.additionalInfo = additionalInfo;
        this.forcedSignatureVersion = forcedSignatureVersion;
        this.requestData = SignatureDataParser.parseRequestData(data);
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
     * Get signature configuration.
     * @return Signature configuration.
     */
    public SignatureConfiguration getSignatureConfiguration() {
        return signatureConfiguration;
    }

    /**
     * Get additional information related to the signature.
     * @return Additional information related to the signature.
     */
    public KeyValueMap getAdditionalInfo() {
        return additionalInfo;
    }

    /**
     * Get forced signature version.
     * @return Forced signature version.
     */
    public Integer getForcedSignatureVersion() {
        return forcedSignatureVersion;
    }

    /**
     * Get parsed method from request data.
     * @return Method from request data.
     */
    public String getRequestMethod() {
        if (requestData == null) {
            return null;
        }
        return requestData.getMethod();
    }

    /**
     * Get parsed URI identifier from request data.
     * @return URI identifier from request data.
     */
    public String getRequestUriId() {
        if (requestData == null) {
            return null;
        }
        return requestData.getUriIdentifier();
    }

    /**
     * Get parsed request body from request data.
     * @return Request body from request data.
     */
    public String getRequestBody() {
        if (requestData == null) {
            return null;
        }
        return requestData.getBody();
    }

}
