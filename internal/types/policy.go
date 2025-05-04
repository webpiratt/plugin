package types

import "encoding/json"

type PluginTriggerEvent struct {
	PolicyID string `json:"policy_id"`
}
