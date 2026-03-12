package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.ApplicationDetailServiceBehavior;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.entity.ApplicationVersion;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApplicationDetailServiceBehaviorV4Test {

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

        final List<SharedSecretAlgorithm> algorithms = List.of(
                SharedSecretAlgorithm.EC_P256,
                SharedSecretAlgorithm.EC_P384,
                SharedSecretAlgorithm.EC_P384_ML_L3,
                SharedSecretAlgorithm.EC_P384_ML_L5);

        final ApplicationVersion v1 = new ApplicationVersion();
        final ApplicationVersion v2 = new ApplicationVersion();
        final List<ApplicationVersion> versions = List.of(v1, v2);

        doReturn(application).when(tested).findApplicationById(applicationId);
        doReturn(algorithms).when(tested).supportedAlgorithms(application);
        final AbstractApplicationServiceBehavior.Result publicKeys =
                new AbstractApplicationServiceBehavior.Result(null, null, null, null);
        doReturn(publicKeys).when(tested).getPublicKeys(applicationId, algorithms);
        doReturn(versions).when(tested).versions(applicationId, algorithms, publicKeys);

        final GetApplicationDetailResponse response = tested.getApplicationDetail(request);

        assertNotNull(response);
        assertEquals(applicationId, response.getApplicationId());
        assertTrue(response.getApplicationRoles().contains("ROLE_1"));
        assertTrue(response.getApplicationRoles().contains("ROLE_2"));
        assertEquals(
                List.of(
                        SharedSecretAlgorithm.EC_P256.name(),
                        SharedSecretAlgorithm.EC_P384.name(),
                        SharedSecretAlgorithm.EC_P384_ML_L3.name(),
                        SharedSecretAlgorithm.EC_P384_ML_L5.name()
                ),
                response.getSupportedAlgorithms()
        );
        assertEquals(versions, response.getVersions());

        verify(tested).findApplicationById(applicationId);
        verify(tested).supportedAlgorithms(application);
        verify(tested).getPublicKeys(applicationId, algorithms);
        verify(tested).versions(applicationId, algorithms, publicKeys);
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
}
