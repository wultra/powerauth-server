/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.integration;

import io.getlime.security.powerauth.app.server.database.model.entity.IntegrationEntity;
import io.getlime.security.powerauth.app.server.database.repository.IntegrationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Class that implements user detail service used for authentication of integrations.
 * Integration is essentially an application that is allowed to communicate with
 * PowerAuth Server.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Qualifier("integrationUserDetailsService")
public class IntegrationUserDetailsService implements UserDetailsService {

    private final IntegrationRepository integrationRepository;

    /**
     * Constructor to autowire {@link IntegrationRepository} instance.
     * @param integrationRepository Autowired database.
     */
    @Autowired
    public IntegrationUserDetailsService(IntegrationRepository integrationRepository) {
        this.integrationRepository = integrationRepository;
    }

    /**
     * Method to load user details from the database table "pa_integration" according to "clientToken".
     * @param username Username, represented by Client Token value in the "pa_integration" table.
     * @return User details - an instance of new User object.
     * @throws UsernameNotFoundException When integration with given Client Token was not found.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final IntegrationEntity integration = integrationRepository.findFirstByClientToken(username);
        if (integration != null) {
            final List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new User(integration.getClientToken(), integration.getClientSecret(), authorities);
        } else {
            throw new UsernameNotFoundException("No integration found for client token: " + username);
        }
    }

}
