-- Scheduler lock table - https://github.com/lukas-krecan/ShedLock#configure-lockprovider
CREATE TABLE IF NOT EXISTS shedlock
(
    name       VARCHAR(64)  NOT NULL,
    lock_until TIMESTAMP    NOT NULL,
    locked_at  TIMESTAMP    NOT NULL,
    locked_by  VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);


-- Create audit log table - https://github.com/wultra/lime-java-core#wultra-auditing-library
CREATE TABLE IF NOT EXISTS audit_log
(
    audit_log_id      VARCHAR(36) PRIMARY KEY,
    application_name  VARCHAR(256) NOT NULL,
    audit_level       VARCHAR(32)  NOT NULL,
    audit_type        VARCHAR(256),
    timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message           TEXT         NOT NULL,
    exception_message TEXT,
    stack_trace       TEXT,
    param             TEXT,
    calling_class     VARCHAR(256) NOT NULL,
    thread_name       VARCHAR(256) NOT NULL,
    version           VARCHAR(256),
    build_time        TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_param
(
    audit_log_id      VARCHAR(36),
    timestamp_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    param_key         VARCHAR(256),
    param_value       VARCHAR(4000)
);
