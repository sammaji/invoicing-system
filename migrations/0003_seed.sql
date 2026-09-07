-- Demo tenant + three API keys, so `docker compose up` gives you something you
-- can curl immediately with no bootstrap step.
--
-- The three keys exist to make the permission model *demonstrable* rather than
-- merely described: the same request is 200 with one key and 403 with another.
--
-- Plaintext keys (dev only, printed in the README):
--   sk_prod_demofull000000000000000000000001   ['*:*']
--   sk_prod_demoread000000000000000000000002   ['*:read']
--   sk_prod_democoll000000000000000000000003   ['invoice:read', 'payment:create']
--
-- Hashes are computed here with the built-in sha256() (Postgres 11+, no
-- pgcrypto needed) rather than pasted in, so the plaintext above is verifiably
-- the thing that hashes to what is stored.

INSERT INTO businesses (id, name) VALUES
    ('00000000-0000-7000-8000-000000000001', 'Demo Business');

INSERT INTO api_keys (id, business_id, name, key_prefix, key_hash, permissions) VALUES
    (
        '00000000-0000-7000-8000-00000000000a',
        '00000000-0000-7000-8000-000000000001',
        'demo full access',
        'demofull',
        encode(sha256('sk_prod_demofull000000000000000000000001'::bytea), 'hex'),
        ARRAY['*:*']
    ),
    (
        '00000000-0000-7000-8000-00000000000b',
        '00000000-0000-7000-8000-000000000001',
        'demo read only',
        'demoread',
        encode(sha256('sk_prod_demoread000000000000000000000002'::bytea), 'hex'),
        ARRAY['*:read']
    ),
    (
        '00000000-0000-7000-8000-00000000000c',
        '00000000-0000-7000-8000-000000000001',
        'demo payment collector',
        'democoll',
        encode(sha256('sk_prod_democoll000000000000000000000003'::bytea), 'hex'),
        ARRAY['invoice:read', 'payment:create']
    );
