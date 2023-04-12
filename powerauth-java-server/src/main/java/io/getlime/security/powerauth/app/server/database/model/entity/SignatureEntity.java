/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.database.model.entity;

import io.getlime.security.powerauth.app.server.database.model.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import jakarta.persistence.*;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Entity representing a single signature audit log.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_signature_audit")
public class SignatureEntity implements Serializable {

    private static final long serialVersionUID = 1930424474990335368L;

    @Id
    @SequenceGenerator(name = "pa_signature_audit", sequenceName = "pa_signature_audit_seq")
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_signature_audit")
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", updatable = false)
    private ActivationRecordEntity activation;

    @Column(name = "activation_counter", nullable = false)
    private Long activationCounter;

    @Column(name = "activation_ctr_data")
    private String activationCtrDataBase64;

    @Column(name = "activation_status")
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    @Column(name = "additional_info")
    private String additionalInfo;

    @Column(name = "data_base64", updatable = false)
    private String dataBase64;

    @Column(name = "signature_version", updatable = false)
    private String signatureVersion;

    @Column(name = "signature_type", nullable = false, updatable = false)
    private String signatureType;

    @Column(name = "signature", nullable = false, updatable = false)
    private String signature;

    @Column(name = "signature_data_method", updatable = false)
    private String signatureDataMethod;

    @Column(name = "signature_data_uri_id", updatable = false)
    private String signatureDataUriId;

    @Column(name = "signature_data_body", updatable = false)
    private String signatureDataBody;

    @Column(name = "note", updatable = false)
    private String note;

    @Column(name = "valid", nullable = false, updatable = false)
    private Boolean valid;

    @Column(name = "version", nullable = false)
    private Integer version;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    /**
     * Default constructor.
     */
    public SignatureEntity() {
    }

    /**
     * Constructor with all properties.
     *
     * @param id                      Signature audit item record ID.
     * @param activation              Associated activation, or null of no related activation was found.
     * @param activationCounter       Activation counter at the time of signature computation attempt, or 0 if activation is null.
     * @param activationCtrDataBase64 Activation counter data at the time of signature computation attempt, or null if only numeric counter is used.
     * @param activationStatus        Activation status at the time of signature computation attempt.
     * @param dataBase64              Data that were sent alongside the signature.
     * @param signatureVersion        Requested signature version.
     * @param signatureType           Requested signature type.
     * @param signature               Signature value.
     * @param signatureDataMethod     Signature data method.
     * @param signatureDataUriId      Signature data URI identifier.
     * @param signatureDataBody       Signature data body.
     * @param additionalInfo          Additional information related to this signature.
     * @param note                    Signature audit log note, with more information about the log reason.
     * @param valid                   True if the signature was valid, false otherwise.
     * @param timestampCreated        Created timestapm.
     */
    public SignatureEntity(
            Long id,
            ActivationRecordEntity activation,
            Long activationCounter,
            String activationCtrDataBase64,
            ActivationStatus activationStatus,
            String dataBase64,
            String signatureVersion,
            String signatureType,
            String signature,
            String signatureDataMethod,
            String signatureDataUriId,
            String signatureDataBody,
            String additionalInfo,
            String note,
            Boolean valid,
            Date timestampCreated,
            Integer version) {
        super();
        this.id = id;
        this.activation = activation;
        this.activationCounter = activationCounter;
        this.activationCtrDataBase64 = activationCtrDataBase64;
        this.activationStatus = activationStatus;
        this.dataBase64 = dataBase64;
        this.signatureVersion = signatureVersion;
        this.signatureType = signatureType;
        this.signature = signature;
        this.signatureDataMethod = signatureDataMethod;
        this.signatureDataUriId = signatureDataUriId;
        this.signatureDataBody = signatureDataBody;
        this.additionalInfo = additionalInfo;
        this.note = note;
        this.valid = valid;
        this.version = version;
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get record ID.
     *
     * @return Record ID.
     */
    public Long getId() {
        return id;
    }

    /**
     * Set record ID.
     *
     * @param id Record ID.
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get related activation.
     *
     * @return Related activation.
     */
    public ActivationRecordEntity getActivation() {
        return activation;
    }

    /**
     * Set related activation.
     *
     * @param activation Related activation.
     */
    public void setActivation(ActivationRecordEntity activation) {
        this.activation = activation;
    }

    /**
     * Get activation counter value.
     *
     * @return Activation counter value.
     */
    public Long getActivationCounter() {
        return activationCounter;
    }

    /**
     * Set activation counter value.
     *
     * @param activationCounter Activation counter value.
     */
    public void setActivationCounter(Long activationCounter) {
        this.activationCounter = activationCounter;
    }

    /**
     * Get Base64 encoded activation counter data.
     * @return Activation counter data.
     */
    public String getActivationCtrDataBase64() {
        return activationCtrDataBase64;
    }

    /**
     * Set Base64 encoded activation counter data.
     * @param activationCtrDataBase64 Activation counter data.
     */
    public void setActivationCtrDataBase64(String activationCtrDataBase64) {
        this.activationCtrDataBase64 = activationCtrDataBase64;
    }

    /**
     * Get activation status.
     *
     * @return Activation status.
     */
    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    /**
     * Set activation status.
     *
     * @param activationStatus Activation status.
     */
    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    /**
     * Get Base64 encoded data that entered the signature.
     *
     * @return Base64 encoded data that entered the signature.
     */
    public String getDataBase64() {
        return dataBase64;
    }

    /**
     * Set Base64 encoded data that entered the signature.
     *
     * @param dataBase64 Base64 encoded data that entered the signature.
     */
    public void setDataBase64(String dataBase64) {
        this.dataBase64 = dataBase64;
    }

    /**
     * Get signature audit record note.
     *
     * @return Signature audit record note.
     */
    public String getNote() {
        return note;
    }

    /**
     * Set signature audit record note.
     *
     * @param note Signature audit record note.
     */
    public void setNote(String note) {
        this.note = note;
    }

    /**
     * Get requested signature version.
     *
     * @return Requested signature version.
     */
    public String getSignatureVersion() {
        return this.signatureVersion;
    }

    /**
     * Set requested signature version.
     *
     * @param signatureVersion Requested signature version.
     */
    public void setSignatureVersion(String signatureVersion) {
        this.signatureVersion = signatureVersion;
    }

    /**
     * Get signature type.
     *
     * @return Signature type.
     */
    public String getSignatureType() {
        return signatureType;
    }

    /**
     * Set signature type.
     *
     * @param signatureType Signature type.
     */
    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Get signature.
     *
     * @return Signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Set signature.
     *
     * @param signature Signature.
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Get signature data HTTP method.
     *
     * @return Signature data HTTP method.
     */
    public String getSignatureDataMethod() {
        return signatureDataMethod;
    }

    /**
     * Set signature data HTTP method.
     *
     * @param signatureDataMethod Signature data HTTP method.
     */
    public void setSignatureDataMethod(String signatureDataMethod) {
        this.signatureDataMethod = signatureDataMethod;
    }

    /**
     * Get signature data resource URI identifier.
     *
     * @return Signature data resource URI identifier.
     */
    public String getSignatureDataUriId() {
        return signatureDataUriId;
    }

    /**
     * Set signature data resource URI identifier.
     *
     * @param signatureDataUriId Signature data URI identifier.
     */
    public void setSignatureDataUriId(String signatureDataUriId) {
        this.signatureDataUriId = signatureDataUriId;
    }

    /**
     * Get signature data body.
     *
     * @return Signature data body.
     */
    public String getSignatureDataBody() {
        return signatureDataBody;
    }

    /**
     * Set signature data body.
     *
     * @param signatureDataBody Signature data body.
     */
    public void setSignatureDataBody(String signatureDataBody) {
        this.signatureDataBody = signatureDataBody;
    }

    /**
     * Get additional information related to this signature.
     * @return Additional information.
     */
    public String getAdditionalInfo() {
        return additionalInfo;
    }

    /**
     * Set additional information related to this signature.
     * @param additionalInfo Additional information.
     */
    public void setAdditionalInfo(String additionalInfo) {
        this.additionalInfo = additionalInfo;
    }

    /**
     * Get if the signature was valid or not.
     *
     * @return Signature evaluation result.
     */
    public Boolean getValid() {
        return valid;
    }

    /**
     * Set value based on if the signature was valid or not.
     *
     * @param valid Signature evaluation result.
     */
    public void setValid(Boolean valid) {
        this.valid = valid;
    }

    /**
     * Get signature version.
     * @return Signature version.
     */
    public Integer getVersion() {
        return version;
    }

    /**
     * Set signature version.
     * @param version Signature version.
     */
    public void setVersion(Integer version) {
        this.version = version;
    }

    /**
     * Get created timestamp.
     *
     * @return Created timestamp.
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set created timestamp.
     *
     * @param timestampCreated Created timestamp.
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 23 * hash + Objects.hashCode(this.activation);
        hash = 23 * hash + Objects.hashCode(this.activationCounter);
        hash = 23 * hash + Objects.hashCode(this.activationCtrDataBase64);
        hash = 23 * hash + Objects.hashCode(this.activationStatus);
        hash = 23 * hash + Objects.hashCode(this.dataBase64);
        hash = 23 * hash + Objects.hashCode(this.signatureType);
        hash = 23 * hash + Objects.hashCode(this.signature);
        hash = 23 * hash + Objects.hashCode(this.signatureDataMethod);
        hash = 23 * hash + Objects.hashCode(this.signatureDataUriId);
        hash = 23 * hash + Objects.hashCode(this.signatureDataBody);
        hash = 23 * hash + Objects.hashCode(this.additionalInfo);
        hash = 23 * hash + Objects.hashCode(this.note);
        hash = 23 * hash + Objects.hashCode(this.valid);
        hash = 23 * hash + Objects.hashCode(this.version);
        hash = 23 * hash + Objects.hashCode(this.timestampCreated);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final SignatureEntity other = (SignatureEntity) obj;
        if (!Objects.equals(this.dataBase64, other.dataBase64)) {
            return false;
        }
        if (!Objects.equals(this.signatureType, other.signatureType)) {
            return false;
        }
        if (!Objects.equals(this.signature, other.signature)) {
            return false;
        }
        if (!Objects.equals(this.signatureDataMethod, other.signatureDataMethod)) {
            return false;
        }
        if (!Objects.equals(this.signatureDataUriId, other.signatureDataUriId)) {
            return false;
        }
        if (!Objects.equals(this.signatureDataBody, other.signatureDataBody)) {
            return false;
        }
        if (!Objects.equals(this.additionalInfo, other.additionalInfo)) {
            return false;
        }
        if (!Objects.equals(this.activation, other.activation)) {
            return false;
        }
        if (!Objects.equals(this.activationCounter, other.activationCounter)) {
            return false;
        }
        if (!Objects.equals(this.activationCtrDataBase64, other.activationCtrDataBase64)) {
            return false;
        }
        if (!Objects.equals(this.activationStatus, other.activationStatus)) {
            return false;
        }
        if (!Objects.equals(this.valid, other.valid)) {
            return false;
        }
        if (!Objects.equals(this.version, other.version)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        return Objects.equals(this.note, other.note);
    }

    @Override
    public String toString() {
        return "SignatureEntity{" + "id=" + id + ", activation=" + activation + ", activationCounter=" + activationCounter + ", activationCtrDataBase64=" + activationCtrDataBase64 + ", activationStatus=" + activationStatus + ", dataBase64=" + dataBase64 + ", signatureType=" + signatureType + ", signature=" + signature + ", additionalInfo= " + additionalInfo + ", valid=" + valid + ", version=" + version + ", note=" + note + ", timestampCreated=" + timestampCreated + "}";
    }

}
