package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.ApplicationDetailServiceBehavior;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApplicationControllerTest {

    @Mock
    private ApplicationServiceBehavior applicationService;

    @Mock
    private ApplicationDetailServiceBehavior applicationDetailService;

    @InjectMocks
    private ApplicationController applicationController;

    @Test
    void createApplication_ReturnsWrappedResponseWhenServiceSucceeds() throws Exception {
        final CreateApplicationRequest req = new CreateApplicationRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<CreateApplicationRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        final CreateApplicationResponse serviceResponse = new CreateApplicationResponse();
        when(applicationService.createApplication(req)).thenReturn(serviceResponse);

        final ObjectResponse<CreateApplicationResponse> response = applicationController.createApplication(request);

        assertNotNull(response);
        assertSame(serviceResponse, response.getResponseObject());
    }

    @Test
    void createApplication_PropagatesExceptionWhenServiceFails() throws Exception {
        final CreateApplicationRequest req = new CreateApplicationRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<CreateApplicationRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        when(applicationService.createApplication(req)).thenThrow(new RuntimeException("failure"));

        assertThrows(RuntimeException.class, () -> applicationController.createApplication(request));
    }

    @Test
    void createApplication_ThrowsNullPointerExceptionWhenRequestObjectIsNull() {
        final ObjectRequest<CreateApplicationRequest> request = new ObjectRequest<>();

        assertThrows(NullPointerException.class, () -> applicationController.createApplication(request));
    }

    @Test
    void getApplicationDetail_ReturnsWrappedResponseWhenServiceSucceeds() throws Exception {
        final GetApplicationDetailRequest req = new GetApplicationDetailRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<GetApplicationDetailRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        final GetApplicationDetailResponse serviceResponse = new GetApplicationDetailResponse();
        when(applicationDetailService.getApplicationDetail(req)).thenReturn(serviceResponse);

        final ObjectResponse<GetApplicationDetailResponse> response = applicationController.getApplicationDetail(request);

        assertNotNull(response);
        assertSame(serviceResponse, response.getResponseObject());
    }

    @Test
    void getApplicationDetail_PropagatesExceptionWhenServiceFails() throws Exception {
        final GetApplicationDetailRequest req = new GetApplicationDetailRequest();
        req.setApplicationId("app-1");
        final ObjectRequest<GetApplicationDetailRequest> request = new ObjectRequest<>();
        request.setRequestObject(req);

        when(applicationDetailService.getApplicationDetail(req)).thenThrow(new RuntimeException("failure"));

        assertThrows(RuntimeException.class, () -> applicationController.getApplicationDetail(request));
    }

    @Test
    void getApplicationDetail_ThrowsNullPointerExceptionWhenRequestObjectIsNull() {
        final ObjectRequest<GetApplicationDetailRequest> request = new ObjectRequest<>();

        assertThrows(NullPointerException.class, () -> applicationController.getApplicationDetail(request));
    }
}