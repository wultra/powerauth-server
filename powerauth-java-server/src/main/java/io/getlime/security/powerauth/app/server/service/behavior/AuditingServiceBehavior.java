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

package io.getlime.security.powerauth.app.server.service.behavior;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.SignatureAuditResponse;
import io.getlime.security.powerauth.app.server.repository.SignatureAuditRepository;
import io.getlime.security.powerauth.app.server.repository.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.repository.model.entity.SignatureEntity;
import io.getlime.security.powerauth.app.server.service.util.ModelUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.xml.datatype.DatatypeConfigurationException;
import java.util.Date;
import java.util.List;

/**
 * Behavior class associated with process of a server auditing. Every time server attempts to compute a signature,
 * a log record is created. This class separates logic from the main service class.
 *
 * @author Petr Dvorak
 */
@Component
public class AuditingServiceBehavior {

    private SignatureAuditRepository signatureAuditRepository;

    @Autowired
    public AuditingServiceBehavior(SignatureAuditRepository signatureAuditRepository) {
        this.signatureAuditRepository = signatureAuditRepository;
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
            signatureAuditEntityList = signatureAuditRepository.findByActivation_UserIdAndTimestampCreatedBetweenOrderByTimestampCreatedDesc(userId, startingDate, endingDate);
        } else {
            signatureAuditEntityList = signatureAuditRepository.findByActivation_ApplicationIdAndActivation_UserIdAndTimestampCreatedBetweenOrderByTimestampCreatedDesc(applicationId, userId, startingDate, endingDate);
        }

        SignatureAuditResponse response = new SignatureAuditResponse();
        if (signatureAuditEntityList != null) {
            for (SignatureEntity signatureEntity : signatureAuditEntityList) {

                SignatureAuditResponse.Items item = new SignatureAuditResponse.Items();

                item.setId(signatureEntity.getId());
                item.setApplicationId(signatureEntity.getActivation().getApplication().getId());
                item.setActivationCounter(signatureEntity.getActivationCounter());
                item.setActivationStatus(ModelUtil.toServiceStatus(signatureEntity.getActivationStatus()));
                item.setActivationId(signatureEntity.getActivation().getActivationId());
                item.setDataBase64(signatureEntity.getDataBase64());
                item.setSignature(signatureEntity.getSignature());
                item.setSignatureType(signatureEntity.getSignatureType());
                item.setValid(signatureEntity.getValid());
                item.setTimestampCreated(ModelUtil.calendarWithDate(signatureEntity.getTimestampCreated()));
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
     * @param signatureType    Requested signature type
     * @param signature        Provided signature.
     * @param data             Provided data.
     * @param valid            Flag indicating if the signature was valid
     * @param note             Record additional info (for example, reason for signature validation failure)
     * @param currentTimestamp Record timestamp
     */
    void logSignatureAuditRecord(ActivationRecordEntity activation, String signatureType, String signature, byte[] data, Boolean valid, String note, Date currentTimestamp) {
        // Audit the signature
        SignatureEntity signatureAuditRecord = new SignatureEntity();
        signatureAuditRecord.setActivation(activation);
        signatureAuditRecord.setActivationCounter(activation.getCounter());
        signatureAuditRecord.setActivationStatus(activation.getActivationStatus());
        signatureAuditRecord.setDataBase64(BaseEncoding.base64().encode(data));
        signatureAuditRecord.setSignature(signature);
        signatureAuditRecord.setSignatureType(signatureType);
        signatureAuditRecord.setValid(valid);
        signatureAuditRecord.setNote(note);
        signatureAuditRecord.setTimestampCreated(currentTimestamp);
        signatureAuditRepository.save(signatureAuditRecord);
    }

}
