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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.ApplicationDetailServiceBehavior;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.v3.GetApplicationDetailResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApplicationDetailServiceBehaviorV3Test {

    private static final String MASTER_PUBLIC_KEY = "masterPublicKeyBase64==";

    @Spy
    private ApplicationDetailServiceBehavior tested;

    @Test
    void getApplicationDetail_shouldReturnMappedResponse() throws Exception {
        final String applicationId = "DEMO-APPLICATION-NAME-" + System.currentTimeMillis();

        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);

        final ApplicationEntity application = mock(ApplicationEntity.class);
        when(application.getId()).thenReturn(applicationId);
        doReturn(List.of("ROLE_1", "ROLE_2")).when(application).getRoles();

        final List<SharedSecretAlgorithm> algorithms = List.of(SharedSecretAlgorithm.EC_P384);
        final ApplicationVersion v1 = new ApplicationVersion();
        final List<ApplicationVersion> versions = List.of(v1);

        doReturn(application).when(tested).findApplicationById(applicationId);
        doReturn(algorithms).when(tested).supportedAlgorithms(application);
        final AbstractApplicationServiceBehavior.Result publicKeys =
                new AbstractApplicationServiceBehavior.Result(MASTER_PUBLIC_KEY, null, null, null);
        doReturn(publicKeys).when(tested).getPublicKeys(applicationId, algorithms);
        doReturn(versions).when(tested).versions(applicationId, algorithms, publicKeys);

        final GetApplicationDetailResponse response = tested.getApplicationDetail(request);

        assertNotNull(response);
        assertEquals(applicationId, response.getApplicationId());
        assertTrue(response.getApplicationRoles().contains("ROLE_1"));
        assertTrue(response.getApplicationRoles().contains("ROLE_2"));
        assertEquals(versions, response.getVersions());
        assertEquals(MASTER_PUBLIC_KEY, response.getMasterPublicKey());
    }

    @Test
    void getApplicationDetail_shouldReturnEmptyRolesWhenApplicationHasNone() throws Exception {
        final String applicationId = "app-no-roles";
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);

        final ApplicationEntity application = mock(ApplicationEntity.class);
        when(application.getId()).thenReturn(applicationId);
        doReturn(List.of()).when(application).getRoles();

        final List<SharedSecretAlgorithm> algorithms = List.of(SharedSecretAlgorithm.EC_P384);
        doReturn(application).when(tested).findApplicationById(applicationId);
        doReturn(algorithms).when(tested).supportedAlgorithms(application);
        final AbstractApplicationServiceBehavior.Result publicKeys =
                new AbstractApplicationServiceBehavior.Result(MASTER_PUBLIC_KEY, null, null, null);
        doReturn(publicKeys).when(tested).getPublicKeys(applicationId, algorithms);
        doReturn(List.of()).when(tested).versions(applicationId, algorithms, publicKeys);

        final GetApplicationDetailResponse response = tested.getApplicationDetail(request);

        assertNotNull(response);
        assertTrue(response.getApplicationRoles().isEmpty());
    }

    @Test
    void getApplicationDetail_shouldReturnNullMasterPublicKeyWhenP256NotPresent() throws Exception {
        final String applicationId = "app-no-p256";
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);

        final ApplicationEntity application = mock(ApplicationEntity.class);
        when(application.getId()).thenReturn(applicationId);
        doReturn(List.of()).when(application).getRoles();

        final List<SharedSecretAlgorithm> algorithms = List.of(SharedSecretAlgorithm.EC_P384_ML_L3);
        doReturn(application).when(tested).findApplicationById(applicationId);
        doReturn(algorithms).when(tested).supportedAlgorithms(application);
        final AbstractApplicationServiceBehavior.Result publicKeys =
                new AbstractApplicationServiceBehavior.Result(null, null, null, null);
        doReturn(publicKeys).when(tested).getPublicKeys(applicationId, algorithms);
        doReturn(List.of()).when(tested).versions(applicationId, algorithms, publicKeys);

        final GetApplicationDetailResponse response = tested.getApplicationDetail(request);

        assertNotNull(response);
        assertNull(response.getMasterPublicKey());
    }

    @Test
    void getApplicationDetail_shouldRethrowGenericServiceException() throws Exception {
        final String applicationId = "missing-app";
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);

        final GenericServiceException expected =
                new GenericServiceException(ServiceError.INVALID_REQUEST, "Application not found");

        doThrow(expected).when(tested).findApplicationById(applicationId);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.getApplicationDetail(request)
        );
        assertSame(expected, thrown);
    }

    @Test
    void getApplicationDetail_shouldRethrowRuntimeException() throws Exception {
        final String applicationId = "app-runtime";
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);

        final RuntimeException expected = new RuntimeException("DB runtime failure");
        doThrow(expected).when(tested).findApplicationById(applicationId);

        final RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> tested.getApplicationDetail(request)
        );
        assertSame(expected, thrown);
    }

    @Test
    void getApplicationDetail_shouldWrapUnknownCheckedExceptionInGenericServiceException() throws Exception {
        final String applicationId = "app-unknown-error";
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);

        doAnswer(invocation -> {
            throw new Exception("unexpected checked exception");
        }).when(tested).findApplicationById(applicationId);

        final GenericServiceException thrown = assertThrows(
                GenericServiceException.class,
                () -> tested.getApplicationDetail(request)
        );
        assertEquals(ServiceError.UNKNOWN_ERROR, thrown.getCode());
    }
}
