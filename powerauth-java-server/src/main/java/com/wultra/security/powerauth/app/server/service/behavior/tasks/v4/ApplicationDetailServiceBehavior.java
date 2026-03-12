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
 */
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.AbstractApplicationDetailServiceBehavior;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Behavior class implementing application detail endpoint.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("applicationDetailServiceBehaviorV4")
public class ApplicationDetailServiceBehavior extends AbstractApplicationDetailServiceBehavior {

    /**
     * Get application details by ID.
     *
     * @param request Request with application ID
     * @return Response with application details
     * @throws GenericServiceException Thrown when application does not exist.
     */
    @Transactional
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final ApplicationEntity application = findApplicationById(applicationId);
            return createApplicationDetailResponse(application);
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    private GetApplicationDetailResponse createApplicationDetailResponse(ApplicationEntity application) throws GenericServiceException {
        final String applicationId = application.getId();
        final GetApplicationDetailResponse response = new GetApplicationDetailResponse();
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(application.getRoles());

        final List<SharedSecretAlgorithm> supportedAlgorithms = supportedAlgorithms(application);
        response.getSupportedAlgorithms().addAll(supportedAlgorithms.stream().map(SharedSecretAlgorithm::name).toList());

        final Result publicKeys = getPublicKeys(applicationId, supportedAlgorithms);
        final List<ApplicationVersion> versions = versions(applicationId, supportedAlgorithms, publicKeys);
        response.setVersions(versions);

        return response;
    }
}
