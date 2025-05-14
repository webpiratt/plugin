-- +goose Up
-- +goose StatementBegin
ALTER TABLE plugin_policies DROP COLUMN chain_code_hex,
  DROP COLUMN is_ecdsa;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE plugin_policies
    ADD COLUMN is_ecdsa BOOLEAN DEFAULT TRUE;
ALTER TABLE plugin_policies
    ADD COLUMN chain_code_hex TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd
