ALTER TABLE events
    ADD COLUMN IF NOT EXISTS user_target_id Nullable(String)
        DEFAULT nullIf(JSONExtractString(document, 'user', 'target', 'id'), ''),
    ADD COLUMN IF NOT EXISTS user_target_name Nullable(String)
        DEFAULT nullIf(JSONExtractString(document, 'user', 'target', 'name'), ''),
    ADD COLUMN IF NOT EXISTS user_target_realm Nullable(String)
        DEFAULT nullIf(JSONExtractString(document, 'user', 'target', 'realm'), '')
