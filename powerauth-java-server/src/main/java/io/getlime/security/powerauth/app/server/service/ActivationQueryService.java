package io.getlime.security.powerauth.app.server.service;

import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

/**
 * Service for activation queries with pessimistic locking.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class ActivationQueryService {

    private static final Logger logger = LoggerFactory.getLogger(ActivationQueryService.class);

    @Value("${spring.datasource.driver-class-name}")
    private String driverClassName;

    @PersistenceContext
    private EntityManager entityManager;

    private final ActivationRepository activationRepository;

    @Autowired
    public ActivationQueryService(ActivationRepository activationRepository) {
        this.activationRepository = activationRepository;
    }

    public ActivationRecordEntity findActivationForUpdate(String activationId) {
        try {
            switch (driverClassName) {
                case "com.microsoft.sqlserver.jdbc.SQLServerDriver":
                    // Avoid creating locks for non-existent activations
                    long activationCount = activationRepository.getActivationCount(activationId);
                    if (activationCount != 1) {
                        return null;
                    }
                    // Find and lock activation using stored procedure for MSSQL
                    return activationRepository.findActivationWithLockMSSQL(activationId);
                default:
                    return activationRepository.findActivationWithLock(activationId);

            }
        } catch (Exception ex) {
            logger.error("Activation query failed", ex);
            return null;
        }
    }
}
