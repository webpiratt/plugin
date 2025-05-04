package dca

type DCAPolicy struct {
	ChainID            string     `json:"chain_id"`
	SourceTokenID      string     `json:"source_token_id"`
	DestinationTokenID string     `json:"destination_token_id"`
	TotalAmount        string     `json:"total_amount"`
	TotalOrders        string     `json:"total_orders"`
	Schedule           Schedule   `json:"schedule"`
	PriceRange         PriceRange `json:"price_range"`
}

type PriceRange struct {
	Min string `json:"min"`
	Max string `json:"max"`
}

// This is duplicated between DCA and Payroll to avoid a 
// circular top-level dependency on the types package
type Schedule struct {
	Frequency string `json:"frequency"`
	Interval  string `json:"interval"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time,omitempty"`
}