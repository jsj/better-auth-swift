-- Fail before changing the table if old issuer-based accounts have duplicate
-- provider/account keys. Resolve those conflicts before applying this migration.
CREATE UNIQUE INDEX account_providerId_accountId_uidx ON account (provider_id, account_id);
DROP INDEX account_issuer_accountId_uidx;
ALTER TABLE account DROP COLUMN issuer;
