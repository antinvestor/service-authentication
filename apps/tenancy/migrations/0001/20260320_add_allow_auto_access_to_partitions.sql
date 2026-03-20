ALTER TABLE partitions
    ADD COLUMN IF NOT EXISTS allow_auto_access BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE partitions
SET allow_auto_access = FALSE
WHERE properties ? 'allow_auto_access'
  AND COALESCE((properties ->> 'allow_auto_access')::boolean, TRUE) = FALSE;

UPDATE partitions
SET allow_auto_access = FALSE
WHERE properties ? 'allow_auto_access_setup'
  AND COALESCE((properties ->> 'allow_auto_access_setup')::boolean, TRUE) = FALSE;
