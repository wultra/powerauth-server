/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.ConfigStoreServiceBehavior;
import com.wultra.security.powerauth.client.model.request.v4.CreateConfigItemRequest;
import com.wultra.security.powerauth.client.model.request.v4.FetchConfigRequest;
import com.wultra.security.powerauth.client.model.request.v4.GetConfigItemsRequest;
import com.wultra.security.powerauth.client.model.request.v4.RemoveConfigItemRequest;
import com.wultra.security.powerauth.client.model.response.v4.CreateConfigItemResponse;
import com.wultra.security.powerauth.client.model.response.v4.FetchConfigResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetConfigItemsResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for v4 {@link ConfigStoreController}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ConfigStoreItemControllerTest {

    @Mock
    private ConfigStoreServiceBehavior service;

    @InjectMocks
    private ConfigStoreController configStoreController;

    @Test
    void createConfigItem_shouldReturnWrappedResponse_whenServiceSucceeds() throws Exception {
        final CreateConfigItemRequest req = new CreateConfigItemRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<CreateConfigItemRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        final CreateConfigItemResponse serviceResponse = new CreateConfigItemResponse();
        when(service.createConfigItem(req)).thenReturn(serviceResponse);

        final ObjectResponse<CreateConfigItemResponse> response = configStoreController.createConfigItem(request);

        assertNotNull(response);
        assertSame(serviceResponse, response.getResponseObject());
    }

    @Test
    void createConfigItem_shouldPropagateException_whenServiceFails() throws Exception {
        final CreateConfigItemRequest req = new CreateConfigItemRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<CreateConfigItemRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        when(service.createConfigItem(req)).thenThrow(new RuntimeException("failure"));

        assertThrows(RuntimeException.class, () -> configStoreController.createConfigItem(request));
    }

    @Test
    void createConfigItem_shouldThrowNullPointerException_whenRequestObjectIsNull() {
        final ObjectRequest<CreateConfigItemRequest> request = new ObjectRequest<>();

        assertThrows(NullPointerException.class, () -> configStoreController.createConfigItem(request));
    }

    @Test
    void listConfigItems_shouldReturnWrappedResponse_whenServiceSucceeds() throws Exception {
        final GetConfigItemsRequest req = new GetConfigItemsRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<GetConfigItemsRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        final GetConfigItemsResponse serviceResponse = new GetConfigItemsResponse();
        when(service.getConfigItems(req)).thenReturn(serviceResponse);

        final ObjectResponse<GetConfigItemsResponse> response = configStoreController.listConfigItems(request);

        assertNotNull(response);
        assertSame(serviceResponse, response.getResponseObject());
    }

    @Test
    void listConfigItems_shouldPropagateException_whenServiceFails() throws Exception {
        final GetConfigItemsRequest req = new GetConfigItemsRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<GetConfigItemsRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        when(service.getConfigItems(req)).thenThrow(new RuntimeException("failure"));

        assertThrows(RuntimeException.class, () -> configStoreController.listConfigItems(request));
    }

    @Test
    void removeConfigItem_shouldReturnResponseAndDelegate_whenServiceSucceeds() throws Exception {
        final RemoveConfigItemRequest req = new RemoveConfigItemRequest();
        req.setApplicationId("app-1");
        req.setKey("base_url");
        final ObjectRequest<RemoveConfigItemRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        final Response response = configStoreController.removeConfigItem(request);

        assertNotNull(response);
        verify(service).removeConfigItem(req);
    }

    @Test
    void removeConfigItem_shouldPropagateException_whenServiceFails() throws Exception {
        final RemoveConfigItemRequest req = new RemoveConfigItemRequest();
        req.setApplicationId("app-1");
        req.setKey("base_url");
        final ObjectRequest<RemoveConfigItemRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        doThrow(new RuntimeException("failure")).when(service).removeConfigItem(req);

        assertThrows(RuntimeException.class, () -> configStoreController.removeConfigItem(request));
    }


    @Test
    void removeConfigItem_shouldThrowNullPointerException_whenRequestObjectIsNull() {
        final ObjectRequest<RemoveConfigItemRequest> request = new ObjectRequest<>();

        assertThrows(NullPointerException.class, () -> configStoreController.removeConfigItem(request));
    }

    @Test
    void fetchConfigItems_shouldReturnWrappedResponse_whenServiceSucceeds() throws Exception {
        final FetchConfigRequest req = new FetchConfigRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<FetchConfigRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        final FetchConfigResponse serviceResponse = new FetchConfigResponse();
        when(service.fetchConfig(req)).thenReturn(serviceResponse);

        final ObjectResponse<FetchConfigResponse> response = configStoreController.fetchConfigItems(request);

        assertNotNull(response);
        assertSame(serviceResponse, response.getResponseObject());
    }

    @Test
    void fetchConfigItems_shouldPropagateException_whenServiceFails() throws Exception {
        final FetchConfigRequest req = new FetchConfigRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<FetchConfigRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        when(service.fetchConfig(req)).thenThrow(new RuntimeException("failure"));

        assertThrows(RuntimeException.class, () -> configStoreController.fetchConfigItems(request));
    }
}
