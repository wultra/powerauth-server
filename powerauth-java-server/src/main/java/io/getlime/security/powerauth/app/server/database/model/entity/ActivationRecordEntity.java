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

import io.getlime.security.powerauth.app.server.database.model.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Database entity for an "activation" objects.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_activation")
public class ActivationRecordEntity implements Serializable {

    private static final long serialVersionUID = 7512286634644851705L;

    @Id
    @Column(name = "activation_id", length = 37)
    private String activationId;

    @Column(name = "activation_code", nullable = false, updatable = false)
    private String activationCode;

    @Column(name = "activation_otp_validation", nullable = false)
    @Convert(converter = ActivationOtpValidationConverter.class)
    private ActivationOtpValidation activationOtpValidation;

    @Column(name = "activation_otp")
    private String activationOtp;

    @Column(name = "user_id", nullable = false, updatable = false)
    private String userId;

    @Column(name = "activation_name")
    private String activationName;

    @Column(name = "extras")
    private String extras;

    @Column(name = "platform")
    private String platform;

    @Column(name = "device_info")
    private String deviceInfo;

    @Column(name = "server_private_key_base64", nullable = false)
    private String serverPrivateKeyBase64;

    @Column(name = "server_public_key_base64", nullable = false)
    private String serverPublicKeyBase64;

    @Column(name = "device_public_key_base64")
    private String devicePublicKeyBase64;

    @Column(name = "counter", nullable = false)
    private Long counter;

    @Column(name = "ctr_data")
    private String ctrDataBase64;

    @Column(name = "failed_attempts", nullable = false)
    private Long failedAttempts;

    @Column(name = "max_failed_attempts", nullable = false)
    private Long maxFailedAttempts;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    @Column(name = "timestamp_activation_expire", nullable = false)
    private Date timestampActivationExpire;

    @Column(name = "timestamp_last_used", nullable = false)
    private Date timestampLastUsed;

    @Column(name = "timestamp_last_change")
    private Date timestampLastChange;

    @Column(name = "activation_status", nullable = false)
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    @Column(name = "blocked_reason")
    private String blockedReason;

    @Column(name = "server_private_key_encryption", nullable = false)
    @Enumerated
    private EncryptionMode serverPrivateKeyEncryption;

    // Version must be nullable, it is not known yet during init activation step
    @Column(name = "version")
    private Integer version;

    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false)
    private ApplicationEntity application;

    @ManyToOne
    @JoinColumn(name = "master_keypair_id", referencedColumnName = "id", nullable = false)
    private MasterKeyPairEntity masterKeyPair;

    @OneToMany(mappedBy = "activation", cascade = CascadeType.ALL)
    @OrderBy("timestamp_created")
    private final List<ActivationHistoryEntity> activationHistory = new ArrayList<>();

    /**
     * Default constructor.
     */
    public ActivationRecordEntity() {
    }

    /**
     * Constructor with all parameters.
     *
     * @param activationId               Activation ID.
     * @param activationCode             Activation code.
     * @param activationOtpValidation    Activation OTP validation mode.
     * @param activationOtp              Activation OTP value.
     * @param userId                     User Id.
     * @param activationName             Activation name.
     * @param extras                     Extra parameters.
     * @param platform                   User device platform.
     * @param deviceInfo                 User device information.
     * @param serverPrivateKeyBase64     Server private key encoded as Base64.
     * @param serverPublicKeyBase64      Server public key encoded as Base64.
     * @param devicePublicKeyBase64      Device public key encoded as Base64.
     * @param counter                    Counter.
     * @param failedAttempts             Current failed attempt count.
     * @param maxFailedAttempts          Maximum allowed failed attempt count.
     * @param timestampCreated           Created timestamp.
     * @param timestampActivationExpire  Activation completion expiration timestamp.
     * @param timestampLastUsed          Last signature timestamp.
     * @param activationStatus           Activation status.
     * @param blockedReason              Reason why activation is blocked.
     * @param serverPrivateKeyEncryption Mode of server private key encryption (0 = NO_ENCRYPTION, 1 = AES_HMAC).
     * @param masterKeyPair              Associated master keypair.
     * @param application                Associated application.
     */
    public ActivationRecordEntity(String activationId,
                                  String activationCode,
                                  ActivationOtpValidation activationOtpValidation,
                                  String activationOtp,
                                  String userId,
                                  String activationName,
                                  String extras,
                                  String platform,
                                  String deviceInfo,
                                  String serverPrivateKeyBase64,
                                  String serverPublicKeyBase64,
                                  String devicePublicKeyBase64,
                                  Long counter,
                                  String ctrDataBase64,
                                  Long failedAttempts,
                                  Long maxFailedAttempts,
                                  Date timestampCreated,
                                  Date timestampActivationExpire,
                                  Date timestampLastUsed,
                                  Date timestampLastChange,
                                  ActivationStatus activationStatus,
                                  String blockedReason,
                                  EncryptionMode serverPrivateKeyEncryption,
                                  Integer version,
                                  MasterKeyPairEntity masterKeyPair,
                                  ApplicationEntity application) {
        super();
        this.activationId = activationId;
        this.activationCode = activationCode;
        this.activationOtpValidation = activationOtpValidation;
        this.activationOtp = activationOtp;
        this.userId = userId;
        this.activationName = activationName;
        this.extras = extras;
        this.deviceInfo = deviceInfo;
        this.platform = platform;
        this.serverPrivateKeyBase64 = serverPrivateKeyBase64;
        this.serverPublicKeyBase64 = serverPublicKeyBase64;
        this.devicePublicKeyBase64 = devicePublicKeyBase64;
        this.counter = counter;
        this.ctrDataBase64 = ctrDataBase64;
        this.failedAttempts = failedAttempts;
        this.maxFailedAttempts = maxFailedAttempts;
        this.timestampCreated = timestampCreated;
        this.timestampActivationExpire = timestampActivationExpire;
        this.timestampLastUsed = timestampLastUsed;
        this.timestampLastChange = timestampLastChange;
        this.activationStatus = activationStatus;
        this.blockedReason = blockedReason;
        this.serverPrivateKeyEncryption = serverPrivateKeyEncryption;
        this.version = version;
        this.masterKeyPair = masterKeyPair;
        this.application = application;
    }

    /**
     * Get activation ID.
     *
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     *
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get activation code.
     *
     * @return Activation code.
     */
    public String getActivationCode() {
        return activationCode;
    }

    /**
     * Set activation code.
     *
     * @param activationCode Activation code.
     */
    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

    /**
     * Get activation OTP validation.
     *
     * @return Activation OTP validation.
     */
    public ActivationOtpValidation getActivationOtpValidation() {
        return activationOtpValidation;
    }

    /**
     * Set activation OTP validation.
     *
     * @param activationOtpValidation Activation OTP validation.
     */
    public void setActivationOtpValidation(ActivationOtpValidation activationOtpValidation) {
        this.activationOtpValidation = activationOtpValidation;
    }

    /**
     * Get activation OTP.
     *
     * @return Activation OTP.
     */
    public String getActivationOtp() {
        return activationOtp;
    }

    /**
     * Set activation OTP.
     *
     * @param activationOtp Activation OTP.
     */
    public void setActivationOtp(String activationOtp) {
        this.activationOtp = activationOtp;
    }

    /**
     * Get user ID
     *
     * @return User ID
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID
     *
     * @param userId User ID
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get activation name
     *
     * @return Activation name
     */
    public String getActivationName() {
        return activationName;
    }

    /**
     * Set activation name
     *
     * @param activationName Activation name
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Get extra parameter
     *
     * @return Extra parameter
     */
    public String getExtras() {
        return extras;
    }

    /**
     * Set extra parameter
     *
     * @param extras Extra parameter
     */
    public void setExtras(String extras) {
        this.extras = extras;
    }

    /**
     * Get user device platform.
     * @return User device platform.
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Set user device platform.
     * @param platform User device platform.
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Get user device information.
     * @return User device information.
     */
    public String getDeviceInfo() {
        return deviceInfo;
    }

    /**
     * Set user device information.
     * @param deviceInfo User device information.
     */
    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    /**
     * Get Base64 encoded server private key
     *
     * @return Base64 encoded server private key
     */
    public String getServerPrivateKeyBase64() {
        return serverPrivateKeyBase64;
    }

    /**
     * Set Base64 encoded server private key.
     *
     * @param serverPrivateKeyBase64 Base64 encoded server private key.
     */
    public void setServerPrivateKeyBase64(String serverPrivateKeyBase64) {
        this.serverPrivateKeyBase64 = serverPrivateKeyBase64;
    }

    /**
     * Get Base64 encoded server public key
     *
     * @return Base64 encoded server public key
     */
    public String getServerPublicKeyBase64() {
        return serverPublicKeyBase64;
    }

    /**
     * Set Base64 encoded server public key
     *
     * @param serverPublicKeyBase64 Base64 encoded server public key
     */
    public void setServerPublicKeyBase64(String serverPublicKeyBase64) {
        this.serverPublicKeyBase64 = serverPublicKeyBase64;
    }

    /**
     * Get Base64 encoded device public key
     *
     * @return Base64 encoded device public key
     */
    public String getDevicePublicKeyBase64() {
        return devicePublicKeyBase64;
    }

    /**
     * Set Base64 encoded device public key
     *
     * @param devicePublicKeyBase64 Base64 encoded device public key
     */
    public void setDevicePublicKeyBase64(String devicePublicKeyBase64) {
        this.devicePublicKeyBase64 = devicePublicKeyBase64;
    }

    /**
     * Get counter value
     *
     * @return Counter
     */
    public Long getCounter() {
        return counter;
    }

    /**
     * Set counter value
     *
     * @param counter Counter
     */
    public void setCounter(Long counter) {
        this.counter = counter;
    }

    /**
     * Get Base64 encoded counter data.
     *
     * @return Counter data.
     */
    public String getCtrDataBase64() {
        return ctrDataBase64;
    }

    /**
     * Set Base64 encoded counter data.
     *
     * @param ctrDataBase64 Counter data.
     */
    public void setCtrDataBase64(String ctrDataBase64) {
        this.ctrDataBase64 = ctrDataBase64;
    }

    /**
     * Get current number of failed attempts
     *
     * @return Failed attempts
     */
    public Long getFailedAttempts() {
        return failedAttempts;
    }

    /**
     * Set current number of failed attempts
     *
     * @param failedAttempts Failed attempts
     */
    public void setFailedAttempts(Long failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    /**
     * Get maximum allowed number of failed attempts
     *
     * @return Max. amount of allowed failed attempts
     */
    public Long getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    /**
     * Set maximum allowed number of failed attempts
     *
     * @param maxFailedAttempts Max. amount of allowed failed attempts
     */
    public void setMaxFailedAttempts(Long maxFailedAttempts) {
        this.maxFailedAttempts = maxFailedAttempts;
    }

    /**
     * Get created timestamp
     *
     * @return Created timestamp
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set created timestamp
     *
     * @param timestampCreated Created timestamp
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get timestamp of activation completion expiration - application must turn
     * from CREATED to ACTIVE state before this moment, or else it will turn REMOVED
     * on next access.
     *
     * @return Timestamp of activation completion expiration.
     */
    public Date getTimestampActivationExpire() {
        return timestampActivationExpire;
    }

    /**
     * Set timestamp of activation completion expiration - application must turn
     * from CREATED to ACTIVE state before this moment, or else it will turn REMOVED
     * on next access.
     *
     * @param timestampActivationExpire Timestamp of activation completion expiration.
     */
    public void setTimestampActivationExpire(Date timestampActivationExpire) {
        this.timestampActivationExpire = timestampActivationExpire;
    }

    /**
     * Get timestamp of the last signature calculation
     *
     * @return Timestamp of the last signature calculation
     */
    public Date getTimestampLastUsed() {
        return timestampLastUsed;
    }

    /**
     * Set timestamp of the last signature calculation
     *
     * @param timestampLastUsed timestamp of the last signature calculation
     */
    public void setTimestampLastUsed(Date timestampLastUsed) {
        this.timestampLastUsed = timestampLastUsed;
    }

    /**
     * Get timestamp of the last activation status change
     * @return Timestamp of the last activation status change
     */
    public Date getTimestampLastChange() {
        return timestampLastChange;
    }

    /**
     * Set timestamp of the last activation status change
     * @param timestampLastChange Timestamp of the last activation status change
     */
    public void setTimestampLastChange(Date timestampLastChange) {
        this.timestampLastChange = timestampLastChange;
    }

    /**
     * Get activation status.
     *
     * @return Activation status, value of {@link ActivationStatus}
     */
    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    /**
     * Set activation status.
     *
     * @param activationStatus Activation status, value of {@link ActivationStatus}
     */
    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    /**
     * Get reason why activation is blocked.
     * @return Reason why activation is blocked.
     */
    public String getBlockedReason() {
        return blockedReason;
    }

    /**
     * Set reason why activation is blocked.
     * @param blockedReason Reason why activation is blocked.
     */
    public void setBlockedReason(String blockedReason) {
        this.blockedReason = blockedReason;
    }

    /**
     * Get mode of server private key encryption (0 = NO_ENCRYPTION, 1 = AES_HMAC).
     * @return Mode of server private key encryption.
     */
    public EncryptionMode getServerPrivateKeyEncryption() {
        return serverPrivateKeyEncryption;
    }

    /**
     * Set mode of server private key encryption (0 = NO_ENCRYPTION, 1 = AES_HMAC).
     * @param serverPrivateKeyEncryption Mode of server private key encryption.
     */
    public void setServerPrivateKeyEncryption(EncryptionMode serverPrivateKeyEncryption) {
        this.serverPrivateKeyEncryption = serverPrivateKeyEncryption;
    }

    /**
     * Get PowerAuth protocol major version for activation.
     * @return PowerAuth protocol major version.
     */
    public Integer getVersion() {
        return version;
    }

    /**
     * Set PowerAuth protocol major version for activation.
     * @param version PowerAuth protocol major version.
     */
    public void setVersion(Integer version) {
        this.version = version;
    }

    /**
     * Get associated application instance. Each activation is strongly associated with
     * a single application.
     *
     * @return Associated application, instance of {@link ApplicationEntity}
     */
    public ApplicationEntity getApplication() {
        return application;
    }

    /**
     * Set associated application instance. Each activation is strongly associated with
     * a single application.
     *
     * @param application Associated application, instance of {@link ApplicationEntity}
     */
    public void setApplication(ApplicationEntity application) {
        this.application = application;
    }

    /**
     * Get associated master key pair. While master key pair is associated with an application
     * by default, it must also be associated with an activation when a new activation is
     * created so that it is strongly bound with the activation.
     *
     * @return Master Key Pair.
     */
    public MasterKeyPairEntity getMasterKeyPair() {
        return masterKeyPair;
    }

    /**
     * Set associated master key pair. While master key pair is associated with an application
     * by default, it must also be associated with an activation when a new activation is
     * created so that it is strongly bound with the activation.
     *
     * @param masterKeyPair Master Key Pair.
     */
    public void setMasterKeyPair(MasterKeyPairEntity masterKeyPair) {
        this.masterKeyPair = masterKeyPair;
    }

    /**
     * Get activation history.
     * @return Activation history.
     */
    public List<ActivationHistoryEntity> getActivationHistory() {
        return activationHistory;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.activationId);
        hash = 71 * hash + Objects.hashCode(this.activationCode);
        hash = 71 * hash + Objects.hashCode(this.activationOtpValidation);
        hash = 71 * hash + Objects.hashCode(this.activationOtp);
        hash = 71 * hash + Objects.hashCode(this.userId);
        hash = 71 * hash + Objects.hashCode(this.activationName);
        hash = 71 * hash + Objects.hashCode(this.extras);
        hash = 71 * hash + Objects.hashCode(this.platform);
        hash = 71 * hash + Objects.hashCode(this.deviceInfo);
        hash = 71 * hash + Objects.hashCode(this.serverPrivateKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.serverPublicKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.devicePublicKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.counter);
        hash = 71 * hash + Objects.hashCode(this.ctrDataBase64);
        hash = 71 * hash + Objects.hashCode(this.failedAttempts);
        hash = 71 * hash + Objects.hashCode(this.maxFailedAttempts);
        hash = 71 * hash + Objects.hashCode(this.timestampCreated);
        hash = 71 * hash + Objects.hashCode(this.timestampActivationExpire);
        hash = 71 * hash + Objects.hashCode(this.timestampLastUsed);
        hash = 71 * hash + Objects.hashCode(this.timestampLastChange);
        hash = 71 * hash + Objects.hashCode(this.activationStatus);
        hash = 71 * hash + Objects.hashCode(this.blockedReason);
        hash = 71 * hash + Objects.hashCode(this.serverPrivateKeyEncryption);
        hash = 71 * hash + Objects.hashCode(this.application);
        hash = 71 * hash + Objects.hashCode(this.masterKeyPair);
        hash = 71 * hash + Objects.hashCode(this.version);
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
        final ActivationRecordEntity other = (ActivationRecordEntity) obj;
        if (!Objects.equals(this.activationCode, other.activationCode)) {
            return false;
        }
        if (this.activationOtpValidation != other.activationOtpValidation) {
            return false;
        }
        if (!Objects.equals(this.activationOtp, other.activationOtp)) {
            return false;
        }
        if (!Objects.equals(this.userId, other.userId)) {
            return false;
        }
        if (!Objects.equals(this.activationName, other.activationName)) {
            return false;
        }
        if (!Objects.equals(this.extras, other.extras)) {
            return false;
        }
        if (!Objects.equals(this.platform, other.platform)) {
            return false;
        }
        if (!Objects.equals(this.deviceInfo, other.deviceInfo)) {
            return false;
        }
        if (!Objects.equals(this.activationId, other.activationId)) {
            return false;
        }
        if (!Objects.equals(this.serverPrivateKeyBase64, other.serverPrivateKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.serverPublicKeyBase64, other.serverPublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.devicePublicKeyBase64, other.devicePublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.counter, other.counter)) {
            return false;
        }
        if (!Objects.equals(this.ctrDataBase64, other.ctrDataBase64)) {
            return false;
        }
        if (!Objects.equals(this.failedAttempts, other.failedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.maxFailedAttempts, other.maxFailedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        if (!Objects.equals(this.timestampActivationExpire, other.timestampActivationExpire)) {
            return false;
        }
        if (!Objects.equals(this.timestampLastUsed, other.timestampLastUsed)) {
            return false;
        }
        if (!Objects.equals(this.timestampLastChange, other.timestampLastChange)) {
            return false;
        }
        if (this.activationStatus != other.activationStatus) {
            return false;
        }
        if (!Objects.equals(this.blockedReason, other.blockedReason)) {
            return false;
        }
        if (!Objects.equals(this.serverPrivateKeyEncryption, other.serverPrivateKeyEncryption)) {
            return false;
        }
        if (!Objects.equals(this.application, other.application)) {
            return false;
        }
        if (!Objects.equals(this.masterKeyPair, other.masterKeyPair)) {
            return false;
        }
        return Objects.equals(this.version, other.version);
    }

    @Override
    public String toString() {
        return "ActivationRecordEntity{"
                + "activationId=" + activationId
                + ", activationCode=" + activationCode
                + ", activationOtpValidation=" + activationOtpValidation
                + ", activationOtp=" + activationOtp
                + ", userId=" + userId
                + ", activationName=" + activationName
                + ", extras=" + extras
                + ", platform=" +platform
                + ", deviceInfo=" +deviceInfo
                + ", serverPublicKeyBase64=" + serverPublicKeyBase64
                + ", devicePublicKeyBase64=" + devicePublicKeyBase64
                + ", counter=" + counter
                + ", ctrDataBase64=" + ctrDataBase64
                + ", failedAttempts=" + failedAttempts
                + ", maxFailedAttempts=" + maxFailedAttempts
                + ", timestampCreated=" + timestampCreated
                + ", timestampActivationExpire=" + timestampActivationExpire
                + ", timestampLastUsed=" + timestampLastUsed
                + ", timestampLastChange=" + timestampLastChange
                + ", status=" + activationStatus
                + ", blockedReason=" + blockedReason
                + ", masterKeyPair=" + masterKeyPair
                + ", version=" + version
                + ", application=" + application
                + '}';
    }
}
