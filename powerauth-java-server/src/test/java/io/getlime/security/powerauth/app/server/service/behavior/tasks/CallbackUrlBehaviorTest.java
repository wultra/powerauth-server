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

import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.request.CreateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.GetCallbackUrlListRequest;
import com.wultra.security.powerauth.client.model.request.RemoveCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.UpdateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthCallbacksConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEventEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.service.callbacks.CallbackUrlEventService;
import io.getlime.security.powerauth.app.server.service.callbacks.model.CallbackUrlConvertor;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.task.CleaningTask;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Test for {@link CallbackUrlBehavior}.
 *
 * @author Jan Pesek, janpesek@outlook.com
 */
@SpringBootTest
@Sql
@Transactional
@ActiveProfiles("test")
class CallbackUrlBehaviorTest {

    @Autowired
    private CallbackUrlBehavior tested;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PowerAuthCallbacksConfiguration powerAuthCallbacksConfiguration;

    @MockBean
    private CallbackUrlEventService callbackUrlEventService;

    /**
     * Mock CleaningTask to avoid running scheduled job when mocking CallbackUrlEventService
     */
    @MockBean
    private CleaningTask cleaningTask;

    @Test
    void testCreateCallbackUrl() throws Exception {
        final CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
        request.setApplicationId("PA_Tests");
        request.setCallbackUrl("http://localhost:8080");
        request.setAuthentication(null);
        request.setName("callbackName");
        request.setType(CallbackUrlType.OPERATION_STATUS_CHANGE);

        final CreateCallbackUrlResponse response = tested.createCallbackUrl(request);
        assertEquals(powerAuthCallbacksConfiguration.getDefaultRetentionPeriod(), response.getRetentionPeriod());
        assertEquals(powerAuthCallbacksConfiguration.getDefaultInitialBackoff(), response.getInitialBackoff());
        assertEquals(powerAuthCallbacksConfiguration.getDefaultMaxAttempts(), response.getMaxAttempts());

        final CallbackUrlEntity entity = entityManager.find(CallbackUrlEntity.class, response.getId());
        assertEquals("PA_Tests", entity.getApplication().getId());
        assertEquals("callbackName", entity.getName());
        assertNull(entity.getRetentionPeriod());
        assertNull(entity.getInitialBackoff());
        assertNull(entity.getMaxAttempts());
        assertTrue(entity.isEnabled());
    }

    @Test
    void updateCallbackUrlTest() throws Exception {
        final CallbackUrlEntity callbackUrl = entityManager.find(CallbackUrlEntity.class, "cafec169-28a6-490c-a1d5-c012b9e3c044");
        assertEquals("PA_Tests", callbackUrl.getApplication().getId());
        assertEquals("test-callback", callbackUrl.getName());

        final UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setApplicationId("PA_Tests");
        request.setId("cafec169-28a6-490c-a1d5-c012b9e3c044");
        request.setCallbackUrl("http://localhost:8080");
        request.setAuthentication(null);
        request.setName("new-name");
        request.setType(CallbackUrlType.OPERATION_STATUS_CHANGE);
        tested.updateCallbackUrl(request);

        final CallbackUrlEntity updated = entityManager.find(CallbackUrlEntity.class, "cafec169-28a6-490c-a1d5-c012b9e3c044");
        assertEquals("PA_Tests", updated.getApplication().getId());
        assertEquals("new-name", updated.getName());
    }

    @Test
    void updateCallbackUrlInvalidCallbackId() throws Exception {
        final CallbackUrlEntity callbackUrl = entityManager.find(CallbackUrlEntity.class, "cafec169-28a6-490c-a1d5-c012b9e3c044");
        assertEquals("PA_Tests", callbackUrl.getApplication().getId());
        assertEquals("test-callback", callbackUrl.getName());

        final UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setApplicationId(callbackUrl.getApplication().getId());
        request.setCallbackUrl(callbackUrl.getCallbackUrl());
        request.setAuthentication(null);
        request.setName("new-name");
        request.setId(UUID.randomUUID().toString());

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> tested.updateCallbackUrl(request));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void testUpdateCallbackUrl_callbackDisabled() {
        final UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setId("c3d5083a-ce9f-467c-af2c-0c950c197bba");
        request.setType(CallbackUrlType.ACTIVATION_STATUS_CHANGE);
        request.setApplicationId("PA_Tests");
        request.setCallbackUrl("http://localhost:8080");
        request.setName("new-name");

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> tested.updateCallbackUrl(request));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void updateCallbackUrlInvalidApplicationId() {
        final CallbackUrlEntity callbackUrl = entityManager.find(CallbackUrlEntity.class, "cafec169-28a6-490c-a1d5-c012b9e3c044");
        assertEquals("PA_Tests", callbackUrl.getApplication().getId());
        assertEquals("test-callback", callbackUrl.getName());

        final UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setId(callbackUrl.getId());
        request.setCallbackUrl(callbackUrl.getCallbackUrl());
        request.setAuthentication(null);
        request.setName("new-name");
        request.setApplicationId("Unknown-App");

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () -> tested.updateCallbackUrl(request));
        assertEquals(ServiceError.INVALID_REQUEST, exception.getCode());
    }

    @Test
    void testGetCallbackUrlList() throws Exception {
        final GetCallbackUrlListRequest request = new GetCallbackUrlListRequest();
        request.setApplicationId("PA_Tests");

        final GetCallbackUrlListResponse response = tested.getCallbackUrlList(request);
        assertEquals(1, response.getCallbackUrlList().size());
        assertEquals("cafec169-28a6-490c-a1d5-c012b9e3c044", response.getCallbackUrlList().get(0).getId());
    }

    @Sql
    @Test
    void testNotifyCallbackListenersOnOperationChange() {

        when(callbackUrlEventService.obtainMaxAttempts(any()))
                .thenReturn(1);
        when(callbackUrlEventService.failureThresholdReached(any()))
                .thenReturn(false);

        final OperationEntity operation = entityManager.find(OperationEntity.class, "07e927af-689a-43ac-bd21-291179801912");
        try (var mockedCallbackConvertor = mockStatic(CallbackUrlConvertor.class)) {
            tested.notifyCallbackListenersOnOperationChange(operation);
        }

        final CallbackUrlEntity enabledCallback = entityManager.find(CallbackUrlEntity.class, "cba5f7aa-889e-4846-b97a-b6ba1bd51ad5");
        final CallbackUrlEntity disabledCallback = entityManager.find(CallbackUrlEntity.class, "b5446f8f-a994-447e-b637-e7cd171a24b5");
        final CallbackUrlEntity activationCallback = entityManager.find(CallbackUrlEntity.class, "be335b28-8474-41a6-82c8-19ff8b7e82d2");
        final Map<String, Object> callbackData = Map.of("operationId", "07e927af-689a-43ac-bd21-291179801912", "type", "OPERATION");

        verify(callbackUrlEventService)
                .createAndSaveEventForProcessing(enabledCallback, callbackData);
        verify(callbackUrlEventService, never())
                .createAndSaveEventForProcessing(disabledCallback, callbackData);
        verify(callbackUrlEventService, never())
                .createAndSaveEventForProcessing(activationCallback, callbackData);
    }

    @Sql
    @Test
    void testNotifyCallbackListenersOnActivationChange() {
        when(callbackUrlEventService.obtainMaxAttempts(any()))
                .thenReturn(1);
        when(callbackUrlEventService.failureThresholdReached(any()))
                .thenReturn(false);

        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");
        try (var mockedCallbackConvertor = mockStatic(CallbackUrlConvertor.class)) {
            tested.notifyCallbackListenersOnActivationChange(activation);
        }

        final CallbackUrlEntity enabledCallback = entityManager.find(CallbackUrlEntity.class, "cba5f7aa-889e-4846-b97a-b6ba1bd51ad5");
        final CallbackUrlEntity disabledCallback = entityManager.find(CallbackUrlEntity.class, "b5446f8f-a994-447e-b637-e7cd171a24b5");
        final CallbackUrlEntity activationCallback = entityManager.find(CallbackUrlEntity.class, "be335b28-8474-41a6-82c8-19ff8b7e82d2");
        final Map<String, Object> callbackData = Map.of("activationId", "e43a5dec-afea-4a10-a80b-b2183399f16b", "type", "ACTIVATION");

        verify(callbackUrlEventService)
                .createAndSaveEventForProcessing(enabledCallback, callbackData);
        verify(callbackUrlEventService, never())
                .createAndSaveEventForProcessing(disabledCallback, callbackData);
        verify(callbackUrlEventService, never())
                .createAndSaveEventForProcessing(activationCallback, callbackData);
    }

    @Test
    void testRemoveCallbackUrl() throws Exception {
        final CallbackUrlEntity callbackUrlEntity = entityManager.find(CallbackUrlEntity.class, "cafec169-28a6-490c-a1d5-c012b9e3c044");
        assertTrue(callbackUrlEntity.isEnabled());

        final CallbackUrlEventEntity callbackUrlEventEntity = entityManager.find(CallbackUrlEventEntity.class, 1);
        assertNotNull(callbackUrlEventEntity);
        assertEquals(callbackUrlEventEntity.getCallbackUrlEntity().getId(), callbackUrlEntity.getId());

        final RemoveCallbackUrlRequest request = new RemoveCallbackUrlRequest();
        request.setId(callbackUrlEntity.getId());

        final RemoveCallbackUrlResponse response = tested.removeCallbackUrl(request);
        entityManager.flush();
    }

}
