package io.getlime.security.powerauth.app.server.database.repository;

import static io.getlime.security.powerauth.app.server.database.model.OperationStatusDo.EXPIRED;
import static io.getlime.security.powerauth.app.server.database.model.OperationStatusDo.PENDING;
import static io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes.BIOMETRY;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.joda.time.DateTime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.annotation.Transactional;

import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

/**
 * Test for {@link OperationRepository} CRUD operations.
 */
@DataJpaTest
public class OperationRepositoryTest {

	@Autowired
	private OperationRepository repository;

	@Autowired
	private ApplicationRepository apprepository;

	@Test
	@Transactional
	public void setExpiredTest() {
		ApplicationEntity applicationEntity = new ApplicationEntity();
		applicationEntity.setName("application");
		apprepository.save(applicationEntity);

		// The Pending Entity
		DateTime creationTime = DateTime.now();
		OperationEntity operationEnity = createPendingOperationEntity(creationTime);
		operationEnity.setApplication(applicationEntity);
		repository.save(operationEnity);
		
		List<String> expiringOperationIds = repository.findExpiredPendingOperationIds(creationTime.plusMinutes(3).toDate());
		// Set expired to pendings operations by ID
		repository.setExpiredToPendingOperations(expiringOperationIds);
		// Load the pending entity which one we set to expired
		List<OperationEntity> changedEnities = repository.findOperationsById(expiringOperationIds);
		// Status is set to expired.
		assertTrue(EXPIRED.equals(changedEnities.get(0).getStatus()));
	}
	
	@Test
	@Transactional
	public void stillPendingTest() {
		ApplicationEntity applicationEntity = new ApplicationEntity();
		applicationEntity.setName("application");
		apprepository.save(applicationEntity);
		
		// The Pending Entity
		DateTime creationTime = DateTime.now();
		OperationEntity operationEnity = createPendingOperationEntity(creationTime);
		operationEnity.setApplication(applicationEntity);
		repository.save(operationEnity);
		
		List<String> pendingOperationIds = repository.findExpiredPendingOperationIds(creationTime.plusMinutes(1).toDate());
		// The operation is not expired yet.
		assertTrue(pendingOperationIds.isEmpty());
	}

	private OperationEntity createPendingOperationEntity(DateTime time) {
		OperationEntity enity = new OperationEntity();
		enity.setId("9f03198f-ed98-46cd-adae-11304ffbb62b");
		enity.setUserId("1");
		enity.setStatus(PENDING);
		enity.setOperationType("login");
		enity.setData("A2");
		enity.setSignatureType(new PowerAuthSignatureTypes[] { BIOMETRY });
		enity.setFailureCount(0L);
		enity.setMaxFailureCount(1L);
		enity.setTimestampCreated(time.toDate());
		enity.setTimestampExpires(time.plusMinutes(2).toDate());
		return enity;
	}
}
