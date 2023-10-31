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

import com.wultra.security.powerauth.client.model.request.UpdateCallbackUrlRequest;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for {@link CallbackUrlBehavior}.
 *
 * @author Jan Pesek, janpesek@outlook.com
 */
@SpringBootTest
@Sql
@Transactional
class CallbackUrlBehaviorTest {

    @Autowired
    private CallbackUrlBehavior tested;

    @Autowired
    private EntityManager entityManager;

    @Test
    void updateCallbackUrlTest() throws Exception {
        CallbackUrlEntity callbackUrl = entityManager.find(CallbackUrlEntity.class, "cafec169-28a6-490c-a1d5-c012b9e3c044");
        assertEquals("PA_Tests", callbackUrl.getApplication().getId());
        assertEquals("test-callback", callbackUrl.getName());

        final UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setApplicationId("PA_Tests");
        request.setId("cafec169-28a6-490c-a1d5-c012b9e3c044");
        request.setCallbackUrl("http://localhost:8080");
        request.setAuthentication(null);
        request.setName("new-name");
        tested.updateCallbackUrl(request);

        callbackUrl = entityManager.find(CallbackUrlEntity.class, "cafec169-28a6-490c-a1d5-c012b9e3c044");
        assertEquals("PA_Tests", callbackUrl.getApplication().getId());
        assertEquals("new-name", callbackUrl.getName());
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

}
