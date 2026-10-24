-- Copyright 2023-2026 Ant Investor Ltd
-- Fintech operations: read loans to match borrower mobile money (2026-10-24).
--
-- service-fintech operations now matches an individual borrower's incoming
-- mobile-money payment to their loan by the quoted loan id or by the payer's
-- phone, which needs LoanAccountGet/LoanAccountSearch (loan_view) on
-- service_loans. The grant itself was added in 20261024_01.

INSERT INTO service_account_authorization_permissions (id, tenant_id, partition_id, grant_id, permission) VALUES ('dbeaj5cpf2t36jctmpqg', 'c2f4j7au6s7f91uqnojg', 'c2f4j7au6s7f91uqnokg', 'dbe6k5g1j4o4jru4etf0', 'loan_view') ON CONFLICT (id) DO NOTHING;
