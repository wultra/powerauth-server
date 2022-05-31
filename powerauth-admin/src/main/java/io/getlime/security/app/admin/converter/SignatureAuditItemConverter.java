/*
 * Copyright 2019 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.app.admin.converter;

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.v3.SignatureAuditResponse;
import io.getlime.security.app.admin.model.SignatureAuditItem;

import java.nio.charset.StandardCharsets;

/**
 * Converter for signature audit items.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SignatureAuditItemConverter {

    private final SignatureDataConverter signatureDataConverter = new SignatureDataConverter();

    /**
     * Convert SignatureAuditResponse.Items class generated from XSD model to SignatureAuditItem.
     * @param signatureAuditItem Signature audit item generated from XSD model.
     * @return Converted signature audit item.
     */
    public SignatureAuditItem fromSignatureAuditResponseItem(SignatureAuditResponse.Items signatureAuditItem) {
        if (signatureAuditItem == null) {
            return null;
        }
        SignatureAuditItem result = new SignatureAuditItem();
        result.setId(signatureAuditItem.getId());
        result.setUserId(signatureAuditItem.getUserId());
        result.setApplicationId(signatureAuditItem.getApplicationId());
        result.setActivationId(signatureAuditItem.getActivationId());
        result.setActivationCounter(signatureAuditItem.getActivationCounter());
        result.setActivationStatus(signatureAuditItem.getActivationStatus());
        result.setAdditionalInfo(signatureAuditItem.getAdditionalInfo());
        result.setSignatureType(signatureAuditItem.getSignatureType());
        result.setSignatureVersion(signatureAuditItem.getSignatureVersion());
        result.setSignature(signatureAuditItem.getSignature());
        result.setNote(signatureAuditItem.getNote());
        result.setValid(signatureAuditItem.isValid());
        result.setVersion((int) signatureAuditItem.getVersion());
        result.setTimestampCreated(signatureAuditItem.getTimestampCreated().toGregorianCalendar().getTime());

        // Special handling for base-64 encoded signature data - data needs to be decoded.
        result.setData(new String(BaseEncoding.base64().decode(signatureAuditItem.getDataBase64()), StandardCharsets.UTF_8));
        // Unstructured signature data is decoded and set as structured signature data.
        result.setSignatureData(signatureDataConverter.fromSignatureDataBase64(result.getData()));

        return result;
    }

}
