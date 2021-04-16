package main

import "time"

// 0 byte type..
type void struct{}

type Event struct {
	Records []struct {
		EventVersion         string `json:"EventVersion"`
		EventSubscriptionArn string `json:"EventSubscriptionArn"`
		EventSource          string `json:"EventSource"`
		Sns                  struct {
			SignatureVersion string    `json:"SignatureVersion"`
			Timestamp        time.Time `json:"Timestamp"`
			Signature        string    `json:"Signature"`
			SigningCertURL   string    `json:"SigningCertUrl"`
			MessageID        string    `json:"MessageId"`
			Message          string    `json:"Message"`
			Type             string    `json:"Type"`
			UnsubscribeURL   string    `json:"UnsubscribeUrl"`
			TopicArn         string    `json:"TopicArn"`
			Subject          string    `json:"Subject"`
		} `json:"Sns"`
	} `json:"Records"`
}

type Message struct {
	CreateTime string `json:"create-time"`
	Synctoken  string `json:"synctoken"`
	MD5        string `json:"md5"`
	URL        string `json:"url"`
}

type IPList struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix           string `json:"ip_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"prefixes"`
}

type ServiceScope string

const (
	ScopeGlobal   = ServiceScope("GLOBAL")
	ScopeRegional = ServiceScope("REGION")
	ScopeAll      = ServiceScope("ALL")

	// Security Group tags
	GLOBAL_TAG   = "cloudfront_g"
	REGIONAL_TAG = "cloudfront_r"
)

func (s ServiceScope) IsGlobal() bool {
	return s == ScopeGlobal
}

func (s ServiceScope) IsRegional() bool {
	return s == ScopeRegional
}

func (s ServiceScope) IsAll() bool {
	return s == ScopeAll
}

func (s ServiceScope) GetTags() map[string]string {
	switch s {
	case ScopeGlobal:
		return map[string]string{
			"SecurityGroupType": GLOBAL_TAG,
			"AutoUpdate":        "true",
		}
	case ScopeRegional:
		return map[string]string{
			"SecurityGroupType": REGIONAL_TAG,
			"AutoUpdate":        "true",
		}
	}
	return map[string]string{}
}
