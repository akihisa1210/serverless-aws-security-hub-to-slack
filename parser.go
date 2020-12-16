package main

import (
	"encoding/json"
	"fmt"
)

// Detail is the detail field of ClowdWatch Events
type Detail struct {
	Findings []Finding `json:"findings"`
}

// Finding is what Security Hub found
type Finding struct {
	Description   string `json:"Description"`
	Severity      `json:"Severity"`
	ProductFields `json:"ProductFields"`
	Remediation   `json:"Remediation"`
}

// Severity of the phenomenon
type Severity struct {
	SeverityLavel string `json:"Label"`
}

// ProductFields indicates the affected resources
type ProductFields struct {
	ProductName string `json:"aws/securityhub/ProductName"`
}

// Remediation is a countermeasure
type Remediation struct {
	Recommendation `json:"Recommendation"`
}

// Recommendation is a reccomended solution
type Recommendation struct {
	Text string `json:"Text"`
	URL  string `json:"Url"`
}

func parse(raw json.RawMessage) (*[]Finding, error) {
	detail := &Detail{}
	err := json.Unmarshal(raw, &detail)
	if err != nil || len(detail.Findings) == 0 {
		return nil, fmt.Errorf("failed unmarshal: %s", err)
	}
	return &detail.Findings, nil
}
