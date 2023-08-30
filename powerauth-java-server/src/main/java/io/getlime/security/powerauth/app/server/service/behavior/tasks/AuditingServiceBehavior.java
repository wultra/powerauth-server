/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.core.audit.base.Audit;
import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.response.SignatureAuditResponse;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.KeyValueMapConverter;
import io.getlime.security.powerauth.app.server.converter.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.database.model.PowerAuthSignatureMetadata;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.SignatureEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.SignatureAuditRepository;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import lombok.Builder;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Behavior class associated with process of a server auditing. Every time server attempts to compute a signature,
 * a log record is created. This class separates logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class AuditingServiceBehavior {

    private final SignatureAuditRepository signatureAuditRepository;

    private final ActivationRepository activationRepository;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();
    private final KeyValueMapConverter keyValueMapConverter;

    // Generic auditing capability
    private final Audit audit;

    @Autowired
    public AuditingServiceBehavior(SignatureAuditRepository signatureAuditRepository, ActivationRepository activationRepository, KeyValueMapConverter keyValueMapConverter, Audit audit) {
        this.signatureAuditRepository = signatureAuditRepository;
        this.activationRepository = activationRepository;
        this.keyValueMapConverter = keyValueMapConverter;
        this.audit = audit;
    }

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
     * List records from the signature audit log for given user
     *
     * @param userId        User ID
     * @param applicationId Application ID. If null is provided, all applications are checked.
     * @param startingDate  Since when should the log be displayed.
     * @param endingDate    Until when should the log be displayed.
     * @return Response with log items.
     */
    public SignatureAuditResponse getSignatureAuditLog(String userId, String applicationId, Date startingDate, Date endingDate) {

        List<SignatureEntity> signatureAuditEntityList;
        if (applicationId == null) {
            signatureAuditEntityList = signatureAuditRepository.findSignatureAuditRecordsForUser(userId, startingDate, endingDate);
        } else {
            signatureAuditEntityList = signatureAuditRepository.findSignatureAuditRecordsForApplicationAndUser(applicationId, userId, startingDate, endingDate);
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
                item.setSignatureType(signatureTypeConverter.convertFrom(signatureEntity.getSignatureType()));
                item.setValid(signatureEntity.getValid());
                item.setVersion(signatureEntity.getVersion());
                item.setTimestampCreated(signatureEntity.getTimestampCreated());
                item.setNote(signatureEntity.getNote());
                item.setUserId(signatureEntity.getActivation().getUserId());

                response.getItems().add(item);
            }
        }

        return response;
    }

    /**
     * Log a record in a signature audit log.
     *
     * @param activation       Activation used for the signature calculation.
     * @param signatureData    Data related to the signature.
     * @param signatureType    Requested signature type.
     * @param valid            Flag indicating if the signature was valid.
     * @param version          Signature version.
     * @param note             Record additional info (for example, reason for signature validation failure).
     * @param currentTimestamp Record timestamp.
     */
    public void logSignatureAuditRecord(ActivationRecordDto activation, SignatureData signatureData, SignatureType signatureType, boolean valid, Integer version, String note, Date currentTimestamp) {

        final String additionalInfo = keyValueMapConverter.toString(signatureData.getAdditionalInfo());
        final String data = Base64.getEncoder().encodeToString(signatureData.getData());

        // Audit the signature
        final SignatureEntity signatureAuditRecord = new SignatureEntity();
        final PowerAuthSignatureMetadata signatureMetadata = new PowerAuthSignatureMetadata(signatureData.getRequestMethod(), signatureData.getRequestUriId());
        signatureAuditRecord.setActivation(activationRepository.getReferenceById(activation.getActivationId()));
        signatureAuditRecord.setActivationCounter(activation.getCounter());
        signatureAuditRecord.setActivationCtrDataBase64(activation.getCtrDataBase64());
        signatureAuditRecord.setActivationStatus(activation.getActivationStatus());
        signatureAuditRecord.setAdditionalInfo(additionalInfo);
        signatureAuditRecord.setDataBase64(data);
        signatureAuditRecord.setSignature(signatureData.getSignature());
        signatureAuditRecord.setSignatureMetadata(signatureMetadata);
        signatureAuditRecord.setSignatureDataBody(signatureData.getRequestBody());
        signatureAuditRecord.setSignatureType(signatureType.name());
        signatureAuditRecord.setSignatureVersion(signatureData.getSignatureVersion());
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
                .param("signature", signatureData.getSignature())
                .param("signatureDataMethod", signatureData.getRequestMethod())
                .param("signatureDataUriId", signatureData.getRequestUriId())
                .param("signatureDataBody", signatureData.getRequestBody())
                .param("signatureType", signatureType.name())
                .param("signatureVersion", signatureData.getSignatureVersion())
                .param("activationVersion", version)
                .param("note", note)
                .param("timestamp", currentTimestamp)
                .type(AuditType.SIGNATURE.getCode())
                .build();
        audit.log("Signature validation completed: {}, activation ID: {}, user ID: {}", AuditLevel.INFO, auditDetail,
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
