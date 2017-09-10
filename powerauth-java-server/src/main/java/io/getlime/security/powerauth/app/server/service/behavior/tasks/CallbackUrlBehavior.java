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

import io.getlime.security.powerauth.*;
import io.getlime.security.powerauth.app.server.database.repository.CallbackUrlRepository;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.AsyncRestTemplate;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Class that manages the service logic related to callback URL management.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class CallbackUrlBehavior {

    private CallbackUrlRepository callbackUrlRepository;

    private LocalizationProvider localizationProvider;

    @Autowired
    public CallbackUrlBehavior(CallbackUrlRepository callbackUrlRepository) {
        this.callbackUrlRepository = callbackUrlRepository;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    /**
     * Creates a new callback URL record for application with given ID.
     * @param request Instance specifying parameters of the callback URL.
     * @return Newly created callback URL record.
     */
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws GenericServiceException {

        // Check the URL format
        try {
            new URL(request.getCallbackUrl());
        } catch (MalformedURLException e) {
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_URL_FORMAT);
        }

        CallbackUrlEntity entity = new CallbackUrlEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setApplicationId(request.getApplicationId());
        entity.setName(request.getName());
        entity.setCallbackUrl(request.getCallbackUrl());
        callbackUrlRepository.save(entity);
        CreateCallbackUrlResponse response = new CreateCallbackUrlResponse();
        response.setId(entity.getId());
        response.setApplicationId(entity.getApplicationId());
        response.setName(entity.getName());
        response.setCallbackUrl(entity.getCallbackUrl());
        return response;
    }

    /**
     * Get the list of all current callback URLs for given application.
     * @param request Request with application ID to fetch the callback URL agains.
     * @return List of all current callback URLs.
     */
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) {
        final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdOrderByName(request.getApplicationId());
        GetCallbackUrlListResponse response = new GetCallbackUrlListResponse();
        for (CallbackUrlEntity callbackUrl: callbackUrlEntities) {
            GetCallbackUrlListResponse.CallbackUrlList item = new GetCallbackUrlListResponse.CallbackUrlList();
            item.setId(callbackUrl.getId());
            item.setApplicationId(callbackUrl.getApplicationId());
            item.setName(callbackUrl.getName());
            item.setCallbackUrl(callbackUrl.getCallbackUrl());
            response.getCallbackUrlList().add(item);
        }
        return response;
    }

    /**
     * Remove callback URL with given ID.
     * @param request Request specifying the callback URL to be removed.
     * @return Information about removal status.
     */
    public RemoveCallbackUrlResponse removeIntegration(RemoveCallbackUrlRequest request) {
        RemoveCallbackUrlResponse response = new RemoveCallbackUrlResponse();
        response.setId(request.getId());
        if (callbackUrlRepository.findOne(request.getId()) != null) {
            response.setRemoved(true);
        } else {
            response.setRemoved(false);
        }
        callbackUrlRepository.delete(request.getId());
        return response;
    }

    /**
     * Tries to asynchronously notify all callbacks that are registered for given application.
     * @param applicationId Application for the callbacks to be used.
     * @param activationId Activation ID to be notified about.
     */
    public void notifyCallbackListeners(Long applicationId, String activationId) {
        final Iterable<CallbackUrlEntity> callbackUrlEntities = callbackUrlRepository.findByApplicationIdOrderByName(applicationId);
        Map<String, String> callbackData = new HashMap<>();
        callbackData.put("activationId", activationId);
        AsyncRestTemplate template = new AsyncRestTemplate();
        for (CallbackUrlEntity callbackUrl: callbackUrlEntities) {
            HttpEntity<Map<String,String>> request = new HttpEntity<>(callbackData);
            template.postForEntity(callbackUrl.getCallbackUrl(), request, Map.class, new HashMap<>());
        }
    }

}
