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
package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.v3.SignatureAuditResponse;
import com.wultra.security.powerauth.client.v3.SignatureType;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.KeyValueMapConverter;
import io.getlime.security.powerauth.app.server.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.converter.v3.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.SignatureEntity;
import io.getlime.security.powerauth.app.server.database.repository.SignatureAuditRepository;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.xml.datatype.DatatypeConfigurationException;
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

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();
    private final KeyValueMapConverter keyValueMapConverter;

    @Autowired
    public AuditingServiceBehavior(SignatureAuditRepository signatureAuditRepository, KeyValueMapConverter keyValueMapConverter) {
        this.signatureAuditRepository = signatureAuditRepository;
        this.keyValueMapConverter = keyValueMapConverter;
    }

    /**
     * List records from the signature audit log for given user
     *
     * @param userId        User ID
     * @param applicationId Application ID. If null is provided, all applications are checked.
     * @param startingDate  Since when should the log be displayed.
     * @param endingDate    Until when should the log be displayed.
     * @return Response with log items.
     * @throws DatatypeConfigurationException In case date cannot be converted.
     */
    public SignatureAuditResponse getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws DatatypeConfigurationException {

        List<SignatureEntity> signatureAuditEntityList;
        if (applicationId == null) {
            signatureAuditEntityList = signatureAuditRepository.findSignatureAuditRecordsForUser(userId, startingDate, endingDate);
        } else {
            signatureAuditEntityList = signatureAuditRepository.findSignatureAuditRecordsForApplicationAndUser(applicationId, userId, startingDate, endingDate);
        }

        SignatureAuditResponse response = new SignatureAuditResponse();
        if (signatureAuditEntityList != null) {
            for (SignatureEntity signatureEntity : signatureAuditEntityList) {

                SignatureAuditResponse.Items item = new SignatureAuditResponse.Items();

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
                item.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(signatureEntity.getTimestampCreated()));
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
    public void logSignatureAuditRecord(ActivationRecordEntity activation, SignatureData signatureData, SignatureType signatureType, Boolean valid, Integer version, String note, Date currentTimestamp) {
        // Audit the signature
        SignatureEntity signatureAuditRecord = new SignatureEntity();
        signatureAuditRecord.setActivation(activation);
        signatureAuditRecord.setActivationCounter(activation.getCounter());
        signatureAuditRecord.setActivationCtrDataBase64(activation.getCtrDataBase64());
        signatureAuditRecord.setActivationStatus(activation.getActivationStatus());
        signatureAuditRecord.setAdditionalInfo(keyValueMapConverter.toString(signatureData.getAdditionalInfo()));
        signatureAuditRecord.setDataBase64(BaseEncoding.base64().encode(signatureData.getData()));
        signatureAuditRecord.setSignature(signatureData.getSignature());
        signatureAuditRecord.setSignatureType(signatureType.value());
        signatureAuditRecord.setSignatureVersion(signatureData.getSignatureVersion());
        signatureAuditRecord.setValid(valid);
        signatureAuditRecord.setVersion(version);
        signatureAuditRecord.setNote(note);
        signatureAuditRecord.setTimestampCreated(currentTimestamp);
        signatureAuditRepository.save(signatureAuditRecord);
    }

}
