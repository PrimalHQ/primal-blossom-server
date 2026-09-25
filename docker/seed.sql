INSERT INTO media_storage_priority (storage_provider, priority)
VALUES ('st1', 1000)
ON CONFLICT (storage_provider) DO UPDATE SET priority = EXCLUDED.priority;
