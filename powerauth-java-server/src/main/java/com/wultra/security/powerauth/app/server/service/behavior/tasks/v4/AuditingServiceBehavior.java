/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.core.audit.base.Audit;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.converter.KeyValueMapConverter;
import com.wultra.security.powerauth.app.server.database.model.PowerAuthAuthenticationCodeMetadata;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.SignatureEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.database.repository.SignatureAuditRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.AuditType;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.AuthenticationData;
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.SignatureAuditRequest;
import com.wultra.security.powerauth.client.model.response.SignatureAuditResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthAuthenticationCodeFormat;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Behavior class associated with process of a server auditing. Every time server attempts to compute an authentication code,
 * a log record is created. This class separates logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service("auditingServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class AuditingServiceBehavior {

    private static final String POWERAUTH_ALGORITHM_V4 = "PowerAuth-V4";
    private static final String ASYMMETRIC_SIGNATURE_TYPE = "ASYMMETRIC";

    private final SignatureAuditRepository signatureAuditRepository;

    private final ActivationRepository activationRepository;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    private final KeyValueMapConverter keyValueMapConverter;

    // Generic auditing capability
    private final Audit audit;
    private final LocalizationProvider localizationProvider;

    /**
     * Log information with specified level, message, audit details, and message args.
     * @param level Level
     * @param message Message
     * @param auditDetail Audit detail
     * @param args Arguments
     */
    public void log(AuditLevel level, String message, AuditDetail auditDetail,  Object... args) {
        audit.log(message, level, auditDetail, args);
    }

    /**
     * Log information with specified level, message, audit details, and message args.
     * @param level Level
     * @param message Message
     * @param args Arguments
     */
    public void log(AuditLevel level, String message, Object... args) {
        audit.log(message, level, args);
    }

    /**
     * List records from the authentication audit log for given user
     *
     * @param request Request with authentication audit log query.
     * @return Response with log items.
     */
    @Transactional(readOnly = true)
    public SignatureAuditResponse getAuditLog(SignatureAuditRequest request) throws GenericServiceException {
        // TODO - update model classes and DB table for auditing for v4

        try {
            final String userId = request.getUserId();
            final String applicationId = request.getApplicationId();
            final Date timestampFrom = request.getTimestampFrom();
            final Date timestampTo = request.getTimestampTo();

            List<SignatureEntity> signatureAuditEntityList;
            if (applicationId == null) {
                signatureAuditEntityList = signatureAuditRepository.findSignatureAuditRecordsForUser(userId, timestampFrom, timestampTo);
            } else {
                signatureAuditEntityList = signatureAuditRepository.findSignatureAuditRecordsForApplicationAndUser(applicationId, userId, timestampFrom, timestampTo);
            }

            final SignatureAuditResponse response = new SignatureAuditResponse();
            if (signatureAuditEntityList != null) {
                for (SignatureEntity signatureEntity : signatureAuditEntityList) {

                    final SignatureAuditItem item = new SignatureAuditItem();

                    item.setId(signatureEntity.getId());
                    item.setApplicationId(signatureEntity.getActivation().getApplication().getId());
                    item.setActivationCounter(signatureEntity.getActivationCounter());
                    item.setActivationCtrData(signatureEntity.getActivationCtrDataBase64());
                    item.setActivationStatus(activationStatusConverter.convert(signatureEntity.getActivationStatus()));
                    item.setAdditionalInfo(keyValueMapConverter.fromString(signatureEntity.getAdditionalInfo()));
                    item.setActivationId(signatureEntity.getActivation().getActivationId());
                    item.setDataBase64(signatureEntity.getDataBase64());
                    item.setSignatureVersion(signatureEntity.getSignatureVersion());
                    item.setSignature(signatureEntity.getSignature());
                    item.setSignatureType(signatureEntity.getSignatureType());
                    item.setSignatureAlgorithm(signatureEntity.getSignatureAlgorithm());
                    item.setSignatureFormat(signatureEntity.getSignatureFormat());
                    item.setValid(signatureEntity.getValid());
                    item.setVersion(signatureEntity.getVersion());
                    item.setTimestampCreated(signatureEntity.getTimestampCreated());
                    item.setNote(signatureEntity.getNote());
                    item.setUserId(signatureEntity.getActivation().getUserId());

                    response.getItems().add(item);
                }
            }
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Log a record in a signature audit log.
     *
     * @param activation       Activation used for the signature calculation.
     * @param authenticationData    Data related to the signature.
     * @param authenticationCodeType    Requested signature type.
     * @param valid            Flag indicating if the signature was valid.
     * @param version          Signature version.
     * @param note             Record additional info (for example, reason for signature validation failure).
     * @param currentTimestamp Record timestamp.
     */
    public void logAuthenticationAuditRecord(ActivationRecordDto activation, AuthenticationData authenticationData, AuthenticationCodeType authenticationCodeType, boolean valid, Integer version, String note, Date currentTimestamp) throws GenericServiceException {
        final String additionalInfo = keyValueMapConverter.toString(authenticationData.getAdditionalInfo());
        final String data = Base64.getEncoder().encodeToString(authenticationData.getData());

        // Audit the signature
        final SignatureEntity signatureAuditRecord = new SignatureEntity();
        final PowerAuthAuthenticationCodeMetadata authMetadata = new PowerAuthAuthenticationCodeMetadata(authenticationData.getRequestMethod(), authenticationData.getRequestUriId());
        signatureAuditRecord.setActivation(activationRepository.getReferenceById(activation.getActivationId()));
        signatureAuditRecord.setActivationCounter(activation.getCounter());
        signatureAuditRecord.setActivationCtrDataBase64(activation.getCtrDataBase64());
        signatureAuditRecord.setActivationStatus(activation.getActivationStatus());
        signatureAuditRecord.setAdditionalInfo(additionalInfo);
        signatureAuditRecord.setDataBase64(data);
        signatureAuditRecord.setSignature(authenticationData.getAuthenticationCode());
        signatureAuditRecord.setSignatureMetadata(authMetadata);
        signatureAuditRecord.setSignatureDataBody(authenticationData.getRequestBody());
        signatureAuditRecord.setSignatureType(authenticationCodeType.name());
        signatureAuditRecord.setSignatureAlgorithm(POWERAUTH_ALGORITHM_V4);
        signatureAuditRecord.setSignatureVersion(authenticationData.getAuthenticationVersion());
        try {
            signatureAuditRecord.setSignatureFormat(PowerAuthAuthenticationCodeFormat.getFormatForVersion(authenticationData.getAuthenticationVersion()).toString());
        } catch (GenericCryptoException e) {
            logger.error("Unsupported protocol version", e);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        signatureAuditRecord.setValid(valid);
        signatureAuditRecord.setVersion(version);
        signatureAuditRecord.setNote(note);
        signatureAuditRecord.setTimestampCreated(currentTimestamp);
        signatureAuditRepository.save(signatureAuditRecord);

        // Store additional audit log
        final AuditDetail auditDetail = AuditDetail.builder()
                .param("activationId", activation.getActivationId())
                .param("applicationId", activation.getApplicationId())
                .param("userId", activation.getUserId())
                .param("valid", valid)
                .param("counter", activation.getCounter())
                .param("counterData", activation.getCtrDataBase64())
                .param("activationStatus", activation.getActivationStatus())
                .param("additionalInfo", additionalInfo)
                .param("data", data)
                .param("authenticationCode", authenticationData.getAuthenticationCode())
                .param("authenticationMetadata", authMetadata)
                .param("authenticationDataBody", authenticationData.getRequestBody())
                .param("authenticationCodeType", authenticationCodeType.name())
                .param("authenticationVersion", authenticationData.getAuthenticationVersion())
                .param("activationVersion", version)
                .param("note", note)
                .param("timestamp", currentTimestamp)
                .type(AuditType.AUTHENTICATION.getCode())
                .subjectId(activation.getUserId())
                .build();
        audit.log("Authentication validation completed: {}, activation ID: {}, user ID: {}", AuditLevel.INFO, auditDetail,
                (valid ? "SUCCESS" : "FAILURE (" + note + ")"),
                activation.getActivationId(),
                activation.getUserId()
        );
    }

    /**
     * Log a record for an asymmetric signature verification (ECDSA, ML-DSA) in the signature audit log.
     * <p>
     * Asymmetric signatures do not advance the activation counter. The {@code signature_format} column is populated
     * with the format used during verification (e.g. {@code DER}, {@code JOSE}).
     *
     * @param activation        Activation associated with the signature verification.
     * @param dataBase64        Base64-encoded data over which the signature was verified.
     * @param signatureBase64   Base64-encoded signature value as provided by the caller (in the original format).
     * @param signatureAlgorithm Signature algorithm used for verification (e.g. {@code ECDSA_P384} or {@code MLDSA_65}).
     * @param signatureFormat   Signature format used for verification (e.g. {@code DER}, {@code JOSE}).
     * @param valid             Flag indicating whether the signature was valid.
     * @param note              Additional information (for example, reason for verification failure).
     * @param currentTimestamp  Verification timestamp.
     */
    public void logAsymmetricSignatureAuditRecord(ActivationRecordEntity activation, String dataBase64, String signatureBase64,
                                                  String signatureAlgorithm, String signatureFormat,
                                                  boolean valid, String note, Date currentTimestamp) {
        // Audit the asymmetric signature into the database
        final SignatureEntity signatureAuditRecord = new SignatureEntity();
        signatureAuditRecord.setActivation(activationRepository.getReferenceById(activation.getActivationId()));
        signatureAuditRecord.setActivationStatus(activation.getActivationStatus());
        signatureAuditRecord.setActivationCounter(activation.getCounter());
        signatureAuditRecord.setActivationCtrDataBase64(activation.getCtrDataBase64());
        signatureAuditRecord.setDataBase64(dataBase64);
        signatureAuditRecord.setSignature(signatureBase64);
        signatureAuditRecord.setSignatureType(ASYMMETRIC_SIGNATURE_TYPE);
        signatureAuditRecord.setSignatureAlgorithm(signatureAlgorithm);
        signatureAuditRecord.setSignatureFormat(signatureFormat);
        signatureAuditRecord.setSignatureVersion(activation.getVersion().toString());
        signatureAuditRecord.setValid(valid);
        signatureAuditRecord.setVersion(activation.getVersion());
        signatureAuditRecord.setNote(note);
        signatureAuditRecord.setTimestampCreated(currentTimestamp);
        signatureAuditRepository.save(signatureAuditRecord);

        // Store additional audit log
        final AuditDetail auditDetail = AuditDetail.builder()
                .param("activationId", activation.getActivationId())
                .param("applicationId", activation.getApplication().getId())
                .param("userId", activation.getUserId())
                .param("valid", valid)
                .param("activationStatus", activation.getActivationStatus())
                .param("data", dataBase64)
                .param("signature", signatureBase64)
                .param("signatureType", ASYMMETRIC_SIGNATURE_TYPE)
                .param("signatureAlgorithm", signatureAlgorithm)
                .param("signatureFormat", signatureFormat)
                .param("activationVersion", activation.getVersion())
                .param("note", note)
                .param("timestamp", currentTimestamp)
                .type(AuditType.ASYMMETRIC_SIGNATURE.getCode())
                .subjectId(activation.getUserId())
                .build();
        audit.log("Asymmetric signature verification completed: {}, activation ID: {}, user ID: {}", AuditLevel.INFO, auditDetail,
                (valid ? "SUCCESS" : "FAILURE (" + note + ")"),
                activation.getActivationId(),
                activation.getUserId()
        );
    }

    /**
     * DTO for {@link ActivationRecordEntity}.
     */
    @Getter
    @Builder
    public static class ActivationRecordDto {
        @lombok.NonNull private String activationId;
        @lombok.NonNull private String applicationId;
        @lombok.NonNull private Long counter;
        @lombok.NonNull private String userId;
        @lombok.NonNull private String ctrDataBase64;
        @lombok.NonNull private ActivationStatus activationStatus;
    }

}
