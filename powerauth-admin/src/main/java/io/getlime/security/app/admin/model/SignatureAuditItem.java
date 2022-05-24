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

package io.getlime.security.app.admin.model;

import com.wultra.security.powerauth.client.v3.ActivationStatus;
import com.wultra.security.powerauth.client.v3.KeyValueMap;
import com.wultra.security.powerauth.client.v3.SignatureType;

import java.util.Date;

/**
 * Signature audit item.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SignatureAuditItem {

    private long id;
    private String userId;
    private String applicationId;
    private String activationId;
    private long activationCounter;
    private ActivationStatus activationStatus;
    private KeyValueMap additionalInfo;
    private String data;
    private SignatureType signatureType;
    private String signatureVersion;
    private String signature;
    private String note;
    private boolean valid;
    private Integer version;
    private Date timestampCreated;
    private SignatureData signatureData;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public String getActivationId() {
        return activationId;
    }

    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    public long getActivationCounter() {
        return activationCounter;
    }

    public void setActivationCounter(long activationCounter) {
        this.activationCounter = activationCounter;
    }

    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    public KeyValueMap getAdditionalInfo() {
        return additionalInfo;
    }

    public void setAdditionalInfo(KeyValueMap additionalInfo) {
        this.additionalInfo = additionalInfo;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public SignatureType getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(SignatureType signatureType) {
        this.signatureType = signatureType;
    }

    public String getSignatureVersion() {
        return signatureVersion;
    }

    public void setSignatureVersion(String signatureVersion) {
        this.signatureVersion = signatureVersion;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public Date getTimestampCreated() {
        return timestampCreated;
    }

    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    public SignatureData getSignatureData() {
        return signatureData;
    }

    public void setSignatureData(SignatureData signatureData) {
        this.signatureData = signatureData;
    }
}
