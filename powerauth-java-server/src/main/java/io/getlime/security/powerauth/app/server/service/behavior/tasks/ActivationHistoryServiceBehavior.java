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

package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import io.getlime.security.powerauth.ActivationHistoryResponse;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.converter.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationHistoryEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationHistoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.xml.datatype.DatatypeConfigurationException;
import java.util.Date;
import java.util.List;

/**
 * Behavior class used for storing and retrieving activation history which includes activation status change log.
 *
 * @author Roman Strobl, roman.strobl@lime-company.eu
 */
@Component
public class ActivationHistoryServiceBehavior {

    private final ActivationHistoryRepository activationHistoryRepository;

    // Prepare converters
    private ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();

    @Autowired
    public ActivationHistoryServiceBehavior(ActivationHistoryRepository activationHistoryRepository) {
        this.activationHistoryRepository = activationHistoryRepository;
    }

    /**
     * Log activation status change into activation history.
     *
     * @param activation Activation.
     */
    public void logActivationStatusChange(ActivationRecordEntity activation) {
        ActivationHistoryEntity activationHistoryEntity = new ActivationHistoryEntity();
        activationHistoryEntity.setActivation(activation);
        activationHistoryEntity.setActivationStatus(activation.getActivationStatus());
        activationHistoryEntity.setTimestampCreated(new Date());
        activationHistoryRepository.save(activationHistoryEntity);
    }

    /**
     * List status changes for given activation.
     * @param activationId Activation ID.
     * @param startingDate Since when should the changes be displayed.
     * @param endingDate Until when should the changes be displayed.
     * @return Response with activation changes.
     * @throws DatatypeConfigurationException In case date cannot be converted.
     */
    public ActivationHistoryResponse getActivationHistory(String activationId, Date startingDate, Date endingDate) throws DatatypeConfigurationException {

        List<ActivationHistoryEntity> activationHistoryEntityList = activationHistoryRepository.findByActivation_ActivationIdAndTimestampCreatedBetweenOrderByTimestampCreatedDesc(activationId, startingDate, endingDate);

        ActivationHistoryResponse response = new ActivationHistoryResponse();
        if (activationHistoryEntityList != null) {
            for (ActivationHistoryEntity activationHistoryEntity : activationHistoryEntityList) {

                ActivationHistoryResponse.Items item = new ActivationHistoryResponse.Items();

                item.setId(activationHistoryEntity.getId());
                item.setActivationId(activationHistoryEntity.getActivation().getActivationId());
                item.setActivationStatus(activationStatusConverter.convert(activationHistoryEntity.getActivationStatus()));
                item.setTimestampCreated(XMLGregorianCalendarConverter.convertFrom(activationHistoryEntity.getTimestampCreated()));

                response.getItems().add(item);
            }
        }

        return response;
    }

}
