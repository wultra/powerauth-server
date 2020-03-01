/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.controller;

import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Date;

/**
 * Home page controller of the PowerAuth Server
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Controller
public class HomeController {

    private BuildProperties buildProperties;

    private final PowerAuthServiceConfiguration configuration;

    @Autowired
    public HomeController(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    @Autowired(required = false)
    public void setBuildProperties(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    @GetMapping("/")
    public String home(Model model) {
        // Add build information
        if (buildProperties != null) {
            model.addAttribute("version", buildProperties.getVersion());
            model.addAttribute("buildTime", Date.from(buildProperties.getTime()));
        }

        // Add info about restricted access mode
        model.addAttribute("restrictAccess", configuration.getRestrictAccess());

        // Add info about DB encryption
        boolean dbEncryption = configuration.getMasterDbEncryptionKey() != null && !configuration.getMasterDbEncryptionKey().isEmpty();
        model.addAttribute("dbEncryption", dbEncryption);

        return "home";
    }

}
