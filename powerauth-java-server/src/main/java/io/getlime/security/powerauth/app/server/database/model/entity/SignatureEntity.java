/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatusConverter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Entity representing a single signature audit log.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Entity(name = "pa_signature_audit")
public class SignatureEntity implements Serializable {

    private static final long serialVersionUID = 1930424474990335368L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", nullable = true, updatable = false)
    private ActivationRecordEntity activation;

    @Column(name = "activation_counter", nullable = false)
    private Long activationCounter;

    @Column(name = "activation_status", nullable = true)
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    @Column(name = "additional_info", nullable = true)
    private String additionalInfo;

    @Column(name = "data_base64", updatable = false)
    private String dataBase64;

    @Column(name = "signature_type", nullable = false, updatable = false)
    private String signatureType;

    @Column(name = "signature", nullable = false, updatable = false)
    private String signature;

    @Column(name = "note", updatable = false)
    private String note;

    @Column(name = "valid", nullable = false, updatable = false)
    private Boolean valid;

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
     * @param id                Signature audit item record ID.
     * @param activation        Associated activation, or null of no related activation was found.
     * @param activationCounter Activation counter at the time of signature computation attempt, or 0 if activation is null.
     * @param activationStatus  Activation status at the time of signature computation attempt.
     * @param dataBase64        Data that were sent alongside the signature.
     * @param signatureType     Requested signature type.
     * @param signature         Signature value.
     * @param additionalInfo    Additional information related to this signature.
     * @param note              Signature audit log note, with more information about the log reason.
     * @param valid             True if the signature was valid, false otherwise.
     * @param timestampCreated  Created timestapm.
     */
    public SignatureEntity(Long id, ActivationRecordEntity activation, Long activationCounter, ActivationStatus activationStatus, String dataBase64, String signatureType, String signature, String additionalInfo, String note, Boolean valid, Date timestampCreated) {
        super();
        this.id = id;
        this.activation = activation;
        this.activationCounter = activationCounter;
        this.activationStatus = activationStatus;
        this.dataBase64 = dataBase64;
        this.signatureType = signatureType;
        this.signature = signature;
        this.additionalInfo = additionalInfo;
        this.note = note;
        this.valid = valid;
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
        hash = 23 * hash + Objects.hashCode(this.id);
        hash = 23 * hash + Objects.hashCode(this.activation);
        hash = 23 * hash + Objects.hashCode(this.activationCounter);
        hash = 23 * hash + Objects.hashCode(this.activationStatus);
        hash = 23 * hash + Objects.hashCode(this.dataBase64);
        hash = 23 * hash + Objects.hashCode(this.signatureType);
        hash = 23 * hash + Objects.hashCode(this.signature);
        hash = 23 * hash + Objects.hashCode(this.additionalInfo);
        hash = 23 * hash + Objects.hashCode(this.note);
        hash = 23 * hash + Objects.hashCode(this.valid);
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
        if (!Objects.equals(this.additionalInfo, other.additionalInfo)) {
            return false;
        }
        if (!Objects.equals(this.id, other.id)) {
            return false;
        }
        if (!Objects.equals(this.activation, other.activation)) {
            return false;
        }
        if (!Objects.equals(this.activationCounter, other.activationCounter)) {
            return false;
        }
        if (!Objects.equals(this.activationStatus, other.activationStatus)) {
            return false;
        }
        if (!Objects.equals(this.valid, other.valid)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        if (!Objects.equals(this.note, other.note)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "SignatureEntity{" + "id=" + id + ", activation=" + activation + ", activationCounter=" + activationCounter + ", activationStatus=" + activationStatus + ", dataBase64=" + dataBase64 + ", signatureType=" + signatureType + ", signature=" + signature + ", additionalInfo= " + additionalInfo + ", valid=" + valid + ", note=" + note + ", timestampCreated=" + timestampCreated + '}';
    }

}
