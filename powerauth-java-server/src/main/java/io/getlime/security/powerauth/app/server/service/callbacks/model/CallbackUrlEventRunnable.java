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

package io.getlime.security.powerauth.app.server.service.callbacks.model;

import lombok.Builder;

/**
 * Runnable action to be executed by an Executor.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Builder
public record CallbackUrlEventRunnable(Runnable dispatchAction, Runnable cancelAction) implements Runnable {

    /**
     * Run dispatching action called by an Executor.
     */
    @Override
    public void run() {
        dispatchAction.run();
    }

    /**
     * Run cancel action on shutdown of an Executor.
     */
    public void cancel() {
        cancelAction.run();
    }

}
