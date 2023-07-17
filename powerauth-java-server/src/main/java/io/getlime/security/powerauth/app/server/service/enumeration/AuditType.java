package io.getlime.security.powerauth.app.server.service.enumeration;

/**
 * This enum represents different types of audits.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
public enum AuditType {

    /**
     * Audit type for signatures.
     */
    SIGNATURE("signature"),

    /**
     * Audit type for operations.
     */
    OPERATION("operation"),

    /**
     * Audit type for activations.
     */
    ACTIVATION("activation");

    /**
     * The code associated with each audit type.
     */
    private final String code;

    /**
     * Constructor to initialize the audit type with its code.
     *
     * @param code the code of the audit type
     */
    AuditType(final String code) {
        this.code = code;
    }

    /**
     * Get the code of the audit type.
     *
     * @return the code of the audit type
     */
    public String getCode() {
        return this.code;
    }
}
