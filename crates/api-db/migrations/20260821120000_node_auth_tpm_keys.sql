-- Stores TPM-certified node-auth JWT verification keys separately from
-- machine identity. A TPM clear or key rotation replaces the row; it never
-- changes the machine ID derived from discovery hardware.
CREATE TABLE node_auth_keys (
    machine_id character varying(64) PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,
    key_id text NOT NULL UNIQUE,
    public_key bytea NOT NULL,
    key_name bytea NOT NULL
);

-- Enrollment data exists only until a TPM answers the EK/AK credential
-- challenge. It cannot itself authorize a JWT.
CREATE TABLE node_auth_key_challenges (
    credential bytea PRIMARY KEY,
    machine_id character varying(64) NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    ak_pub bytea NOT NULL,
    key_id text NOT NULL,
    public_key bytea NOT NULL,
    key_name bytea NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);
