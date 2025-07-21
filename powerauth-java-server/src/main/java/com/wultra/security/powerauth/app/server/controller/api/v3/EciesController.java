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
 *
 */

package com.wultra.security.powerauth.app.server.controller.api.v3;

import com.wultra.security.powerauth.client.model.request.v3.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.response.v3.GetEciesDecryptorResponse;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.EncryptionBehaviorEcies;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to ECIES encryption.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("eciesControllerV3")
@RequestMapping("/rest/v3/ecies")
@Tag(name = "PowerAuth ECIES Encryption Controller (V3)")
@AllArgsConstructor
@Validated
@Slf4j
public class EciesController {

    private final EncryptionBehaviorEcies service;

    /**
     * Create ECIES decryptor.
     *
     * @param request Get ECIES decryptor parameters for given request.
     * @return Response with ECIES decryptor parameters.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/decryptor")
    public ObjectResponse<GetEciesDecryptorResponse> getEciesDecryptor(@Valid @RequestBody ObjectRequest<GetEciesDecryptorRequest> request) throws Exception {
        final GetEciesDecryptorRequest req = request.getRequestObject();
        logger.info("action: getEciesDecryptor, state: initiated, applicationKey: {}, requestTimestamp: {}", req.getApplicationKey(), req.getTimestamp());
        logger.debug("action: getEciesDecryptor, state: initiated, request: {}", request);
        final ObjectResponse<GetEciesDecryptorResponse> response = new ObjectResponse<>(service.getEciesDecryptor(req));
        logger.info("action: getEciesDecryptor, state: succeeded");
        logger.debug("action: getEciesDecryptor, state: succeeded, response: {}", response);
        return response;
    }

}
