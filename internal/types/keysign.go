package types

import (
	vtypes "github.com/vultisig/verifier/types"
)

type PluginKeysignRequest struct {
	vtypes.KeysignRequest
	Transaction     string `json:"transactions"`
	PluginID        string `json:"plugin_id"`
	PolicyID        string `json:"policy_id"`
	TransactionType string `json:"transaction_type"`
}
