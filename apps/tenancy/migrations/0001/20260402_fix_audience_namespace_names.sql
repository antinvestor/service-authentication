-- Fix audience namespace and permission name mismatches.
--
-- 1. "contacts_manage" → "contact_manage"  (OPL relation is contact_manage, singular)
-- 2. "service_setting" → "service_settings" (OPL namespace is service_settings, plural)
-- 3. "service_chat_drone" → "service_chat"  (no service_chat_drone namespace exists)
-- 4. "service_chat_gateway" → "service_chat" (no service_chat_gateway namespace exists)
-- 5. "service_file" → "service_files"        (OPL namespace is service_files, plural)

-- ── clients table ──────────────────────────────────────────────────────────────

-- Fix contacts_manage → contact_manage in permission arrays
UPDATE clients
SET audiences = (
    SELECT jsonb_object_agg(
        key,
        CASE
            WHEN key = 'service_profile' AND jsonb_typeof(value) = 'array'
            THEN (
                SELECT jsonb_agg(
                    CASE WHEN elem #>> '{}' = 'contacts_manage' THEN '"contact_manage"'::jsonb ELSE elem END
                )
                FROM jsonb_array_elements(value) AS elem
            )
            ELSE value
        END
    )
    FROM jsonb_each(audiences)
)
WHERE audiences ? 'service_profile'
  AND audiences->>'service_profile' LIKE '%contacts_manage%'
  AND deleted_at IS NULL;

-- Fix service_setting → service_settings (rename key)
UPDATE clients
SET audiences = (audiences - 'service_setting') || jsonb_build_object('service_settings', audiences->'service_setting')
WHERE audiences ? 'service_setting'
  AND deleted_at IS NULL;

-- Fix service_chat_drone → service_chat (rename key)
UPDATE clients
SET audiences = (audiences - 'service_chat_drone') || jsonb_build_object('service_chat', audiences->'service_chat_drone')
WHERE audiences ? 'service_chat_drone'
  AND NOT audiences ? 'service_chat'
  AND deleted_at IS NULL;

-- Fix service_chat_gateway → service_chat (rename key)
UPDATE clients
SET audiences = (audiences - 'service_chat_gateway') || jsonb_build_object('service_chat', audiences->'service_chat_gateway')
WHERE audiences ? 'service_chat_gateway'
  AND NOT audiences ? 'service_chat'
  AND deleted_at IS NULL;

-- Fix service_file → service_files (rename key)
UPDATE clients
SET audiences = (audiences - 'service_file') || jsonb_build_object('service_files', audiences->'service_file')
WHERE audiences ? 'service_file'
  AND NOT audiences ? 'service_files'
  AND deleted_at IS NULL;

-- ── service_accounts table ─────────────────────────────────────────────────────

-- Fix contacts_manage → contact_manage
UPDATE service_accounts
SET audiences = (
    SELECT jsonb_object_agg(
        key,
        CASE
            WHEN key = 'service_profile' AND jsonb_typeof(value) = 'array'
            THEN (
                SELECT jsonb_agg(
                    CASE WHEN elem #>> '{}' = 'contacts_manage' THEN '"contact_manage"'::jsonb ELSE elem END
                )
                FROM jsonb_array_elements(value) AS elem
            )
            ELSE value
        END
    )
    FROM jsonb_each(audiences)
)
WHERE audiences ? 'service_profile'
  AND audiences->>'service_profile' LIKE '%contacts_manage%'
  AND deleted_at IS NULL;

-- Fix service_setting → service_settings
UPDATE service_accounts
SET audiences = (audiences - 'service_setting') || jsonb_build_object('service_settings', audiences->'service_setting')
WHERE audiences ? 'service_setting'
  AND deleted_at IS NULL;

-- Fix service_chat_drone → service_chat
UPDATE service_accounts
SET audiences = (audiences - 'service_chat_drone') || jsonb_build_object('service_chat', audiences->'service_chat_drone')
WHERE audiences ? 'service_chat_drone'
  AND NOT audiences ? 'service_chat'
  AND deleted_at IS NULL;

-- Fix service_chat_gateway → service_chat
UPDATE service_accounts
SET audiences = (audiences - 'service_chat_gateway') || jsonb_build_object('service_chat', audiences->'service_chat_gateway')
WHERE audiences ? 'service_chat_gateway'
  AND NOT audiences ? 'service_chat'
  AND deleted_at IS NULL;

-- Fix service_file → service_files
UPDATE service_accounts
SET audiences = (audiences - 'service_file') || jsonb_build_object('service_files', audiences->'service_file')
WHERE audiences ? 'service_file'
  AND NOT audiences ? 'service_files'
  AND deleted_at IS NULL;
