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

import com.wultra.security.powerauth.client.model.request.AddActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.ListActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.RemoveActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.UpdateActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.response.AddActivationFlagsResponse;
import com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse;
import com.wultra.security.powerauth.client.model.response.RemoveActivationFlagsResponse;
import com.wultra.security.powerauth.client.model.response.UpdateActivationFlagsResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.ActivationFlagsServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to activation flags.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("activationFlagsController")
@RequestMapping("/rest/v3/activation/flags")
@Tag(name = "PowerAuth Activation Flags Controller (V3)")
@Slf4j
public class ActivationFlagsController {

    private final ActivationFlagsServiceBehavior service;

    @Autowired
    public ActivationFlagsController(ActivationFlagsServiceBehavior service) {
        this.service = service;
    }

    /**
     * List activation flags.
     *
     * @param request List activation flags request.
     * @return List activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<ListActivationFlagsResponse> listActivationFlags(@RequestBody ObjectRequest<ListActivationFlagsRequest> request) throws Exception {
        logger.info("ListActivationFlagsRequest received: {}", request);
        final ObjectResponse<ListActivationFlagsResponse> response = new ObjectResponse<>("OK", service.listActivationFlags(request.getRequestObject()));
        logger.info("ListActivationFlagsRequest succeeded: {}", response);
        return response;
    }

    /**
     * Add activation flags.
     *
     * @param request Add activation flags request.
     * @return Add activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<AddActivationFlagsResponse> addActivationFlags(@RequestBody ObjectRequest<AddActivationFlagsRequest> request) throws Exception {
        logger.info("AddActivationFlagsRequest received: {}", request);
        final ObjectResponse<AddActivationFlagsResponse> response = new ObjectResponse<>("OK", service.addActivationFlags(request.getRequestObject()));
        logger.info("addActivationFlagsRequest succeeded: {}", response);
        return response;
    }

    /**
     * Update activation flags.
     *
     * @param request Update activation flags request.
     * @return Update activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/update")
    public ObjectResponse<UpdateActivationFlagsResponse> updateActivationFlags(@RequestBody ObjectRequest<UpdateActivationFlagsRequest> request) throws Exception {
        logger.info("UpdateActivationFlagsRequest received: {}", request);
        final ObjectResponse<UpdateActivationFlagsResponse> response = new ObjectResponse<>("OK", service.updateActivationFlags(request.getRequestObject()));
        logger.info("UpdateActivationFlagsRequest succeeded: {}", response);
        return response;
    }

    /**
     * Remove activation flags.
     *
     * @param request Remove activation flags request.
     * @return Remove activation flags response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveActivationFlagsResponse> removeActivationFlags(@RequestBody ObjectRequest<RemoveActivationFlagsRequest> request) throws Exception {
        logger.info("RemoveActivationFlagsRequest received: {}", request);
        final ObjectResponse<RemoveActivationFlagsResponse> response = new ObjectResponse<>("OK", service.removeActivationFlags(request.getRequestObject()));
        logger.info("RemoveActivationFlagsRequest succeeded: {}", response);
        return response;
    }

}
