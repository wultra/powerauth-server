--
-- Drop old tables if they exist.
--

DROP TABLE IF EXISTS `pa_application_version`;
DROP TABLE IF EXISTS `pa_master_keypair`;
DROP TABLE IF EXISTS `pa_signature_audit`;
DROP TABLE IF EXISTS `pa_token`;
DROP TABLE IF EXISTS `pa_activation`;
DROP TABLE IF EXISTS `pa_application`;
DROP TABLE IF EXISTS `pa_integration`;
DROP TABLE IF EXISTS `pa_application_callback`;

--
-- Drop sequence tables if they exist.
--

DROP TABLE IF EXISTS `pa_application_seq`;
DROP TABLE IF EXISTS `pa_application_version_seq`;
DROP TABLE IF EXISTS `pa_master_keypair_seq`;
DROP TABLE IF EXISTS `pa_signature_audit_seq`;
DROP TABLE IF EXISTS `pa_activation_history_seq`;
