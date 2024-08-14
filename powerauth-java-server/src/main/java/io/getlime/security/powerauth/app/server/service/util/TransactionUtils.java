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

package io.getlime.security.powerauth.app.server.service.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Utils class to handle transaction synchronization.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TransactionUtils {

    /**
     * Execute task after current transaction commits.
     * @param task Task to execute.
     */
    public static void executeAfterTransactionCommits(Runnable task) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                task.run();
            }
        });
    }

    /**
     * Execute task after current transaction commits or else run other task.
     * @param onCommit Task to execute on commit.
     * @param onError Task to execute otherwise.
     */
    public static void executeAfterTransactionCommitsOrElse(final Runnable onCommit, final Runnable onError) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(final int status) {
                if (status == TransactionSynchronization.STATUS_COMMITTED) {
                    onCommit.run();
                } else {
                    onError.run();
                }
            }
        });
    }

}
