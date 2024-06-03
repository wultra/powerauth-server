/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.controller.api;

import com.wultra.security.powerauth.client.model.request.SignECDSARequest;
import com.wultra.security.powerauth.client.model.request.VerifyECDSASignatureRequest;
import com.wultra.security.powerauth.client.model.response.SignECDSAResponse;
import com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.AsymmetricSignatureServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("ecdsaSignatureController")
@RequestMapping("/rest/v3/signature/ecdsa")
@Tag(name = "PowerAuth ECDSA Signature Controller (V3)")
@Slf4j
public class EcdsaSignatureController {

    private final AsymmetricSignatureServiceBehavior asymmetricSignatureService;

    @Autowired
    public EcdsaSignatureController(AsymmetricSignatureServiceBehavior asymmetricSignatureService) {
        this.asymmetricSignatureService = asymmetricSignatureService;
    }

    /**
     * Calculate ECDSA signature.
     *
     * @param request Calculate ECDSA signature request.
     * @return Calculated ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/sign")
    public ObjectResponse<SignECDSAResponse> signDataWithECDSA(@RequestBody ObjectRequest<SignECDSARequest> request) throws Exception {
        logger.info("SignECDSARequest received: {}", request);
        final ObjectResponse<SignECDSAResponse> response = new ObjectResponse<>("OK", asymmetricSignatureService.signDataWithECDSA(request.getRequestObject()));
        logger.info("SignECDSARequest succeeded: {}", response);
        return response;
    }

    /**
     * Validate ECDSA signature.
     *
     * @param request Verify ECDSA signature request.
     * @return Verify ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/verify")
    public ObjectResponse<VerifyECDSASignatureResponse> verifyECDSASignature(@RequestBody ObjectRequest<VerifyECDSASignatureRequest> request) throws Exception {
        logger.info("VerifyECDSASignatureRequest received: {}", request);
        final ObjectResponse<VerifyECDSASignatureResponse> response = new ObjectResponse<>("OK", asymmetricSignatureService.verifyECDSASignature(request.getRequestObject()));
        logger.info("VerifyECDSASignatureRequest succeeded: {}", response);
        return response;
    }

}
