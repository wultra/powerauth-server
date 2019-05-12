package io.getlime.security.powerauth.app.server;

import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.v3.PowerAuthService;
import io.getlime.security.powerauth.v3.CreateApplicationRequest;
import io.getlime.security.powerauth.v3.CreateApplicationResponse;
import io.getlime.security.powerauth.v3.GetApplicationDetailRequest;
import io.getlime.security.powerauth.v3.GetApplicationDetailResponse;
import org.assertj.core.util.Lists;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
public class GetApplicationDetailTest {

    private PowerAuthService powerAuthService;

    @Autowired
    public void setPowerAuthService(PowerAuthService powerAuthService) {
        this.powerAuthService = powerAuthService;
    }

    @Test
    public void testGetApplicationDetailByExistingId() throws Exception {
        ApplicationEntity application = createApplication();
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(application.getId());

        GetApplicationDetailResponse response = powerAuthService.getApplicationDetail(request);
        assertEquals(application.getId(), Long.valueOf(response.getApplicationId()));
        assertEquals(application.getName(), response.getApplicationName());
    }

    @Test
    public void testGetApplicationDetailByNotExistingId() {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(Long.MAX_VALUE);
        assertThrows(GenericServiceException.class, ()-> powerAuthService.getApplicationDetail(request));
    }

    @Test
    public void testGetApplicationDetailByExistingName() throws Exception {
        ApplicationEntity application = createApplication();
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName(application.getName());

        GetApplicationDetailResponse response = powerAuthService.getApplicationDetail(request);
        assertEquals(application.getId(), Long.valueOf(response.getApplicationId()));
        assertEquals(application.getName(), response.getApplicationName());
    }

    @Test
    public void testGetApplicationDetailByNotExistingName() {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName("NOT_EXISTING_NAME");
        assertThrows(GenericServiceException.class, ()-> powerAuthService.getApplicationDetail(request));
    }

    @Test
    public void testGetApplicationDetailInvalidRequest() throws Exception {
        ApplicationEntity application = createApplication();
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(application.getId());
        request.setApplicationName(application.getName());
        assertThrows(GenericServiceException.class, ()-> powerAuthService.getApplicationDetail(request));
    }

    @Test
    public void testGetApplicationDetailByNameWhenSameName() throws Exception {
        ApplicationEntity application1 = createApplication();
        ApplicationEntity application2 = createApplication(application1.getName());

        assertNotEquals(application1.getId(), application2.getId());
        assertEquals(application1.getName(), application2.getName());

        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName(application1.getName());
        GetApplicationDetailResponse response = powerAuthService.getApplicationDetail(request);
        assertEquals(application1.getId(), Long.valueOf(response.getApplicationId()));
    }

    private ApplicationEntity createApplication() throws Exception {
        return createApplication("GetApplicationDetailTest-" + System.currentTimeMillis());
    }

    private ApplicationEntity createApplication(String applicationName) throws Exception {
        CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(applicationName);
        CreateApplicationResponse response = powerAuthService.createApplication(request);
        return new ApplicationEntity(response.getApplicationId(), response.getApplicationName(), Lists.emptyList());
    }

}
