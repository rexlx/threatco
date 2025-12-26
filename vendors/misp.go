package vendors

import (
	"strconv"
	"time"

	"github.com/google/uuid"
)

var IOCToMispMap = map[string]string{
	"md5":      "md5",
	"sha1":     "sha1",
	"sha256":   "sha256",
	"sha512":   "sha512",
	"ipv4":     "ip-src",
	"ipv6":     "ip-src",
	"email":    "email-src",
	"url":      "url",
	"domain":   "domain",
	"filepath": "filename",
	"filename": "filename",
}

type MispEvent struct {
	ID                 string      `json:"id"`
	OrgID              string      `json:"org_id"`
	Distribution       string      `json:"distribution"`
	Info               string      `json:"info"`
	OrgCID             string      `json:"orgc_id"`
	UUID               string      `json:"uuid"`
	Date               string      `json:"date"`
	Published          bool        `json:"published"`
	Analysis           string      `json:"analysis"`
	AttributeCount     string      `json:"attribute_count"`
	Timestamp          string      `json:"timestamp"`
	SharingGroupID     string      `json:"sharing_group_id"`
	ProposalEmailLock  bool        `json:"proposal_email_lock"`
	Locked             bool        `json:"locked"`
	ThreatLevelID      string      `json:"threat_level_id"`
	PublishTimestamp   string      `json:"publish_timestamp"`
	SightingTimestamp  string      `json:"sighting_timestamp"`
	DisableCorrelation bool        `json:"disable_correlation"`
	ExtendsUUID        string      `json:"extends_uuid"`
	EventCreatorEmail  string      `json:"event_creator_email"`
	Protected          bool        `json:"protected"`
	Org                *Org        `json:"Org,omitempty"`
	Orgc               *Orgc       `json:"Orgc,omitempty"`
	Attribute          []Attribute `json:"Attribute"`
}

type MispEventResponse struct {
	// Legacy/Search format: {"response": [{"Event": {...}}]}
	Response []struct {
		Event MispEvent `json:"Event"`
	} `json:"response"`

	// Creation/Direct format: {"Event": {...}}
	Event *MispEvent `json:"Event"`
}

type Org struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Local bool   `json:"local"`
}

type Orgc struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	Local bool   `json:"local"`
}

func (e *MispEvent) SetTimestampString(tstamp, published, sighted int64) error {
	e.Timestamp = strconv.Itoa(int(tstamp))
	e.PublishTimestamp = strconv.Itoa(int(published))
	e.SightingTimestamp = strconv.Itoa(int(sighted))
	return nil
}

func NewEvent(org, dist, info, analysis, threat, xuuid string) *MispEvent {
	attrs := make([]Attribute, 0)
	now := time.Now().Unix()
	id := uuid.New()
	e := &MispEvent{
		Attribute:     attrs,
		UUID:          id.String(),
		OrgID:         org,
		OrgCID:        org,
		Distribution:  dist,
		Info:          info,
		Analysis:      analysis,
		ThreatLevelID: threat,
		ExtendsUUID:   xuuid,
	}
	e.SetTimestampString(now, now, now)
	return e
}

// ATTRUBUTE

type Attribute struct {
	EventID        string `json:"event_id"`
	ObjectID       string `json:"object_id"`
	ObjectRelation string `json:"object_relation"`
	Category       string `json:"category"`
	Type           string `json:"type"`
	Value          string `json:"value"`
	ToIDS          bool   `json:"to_ids"`
	UUID           string `json:"uuid"`
	Timestamp      string `json:"timestamp"`
	Distribution   string `json:"distribution"`
	SharingGroupID string `json:"sharing_group_id"`
	Comment        string `json:"comment"`
	Deleted        bool   `json:"deleted"`
	DisableCorr    bool   `json:"disable_correlation"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
}

type Tag struct {
	Name           string `json:"name"`
	Color          string `json:"colour"`
	Exportable     bool   `json:"exportable"`
	OrgID          string `json:"org_id"`
	UserID         string `json:"user_id"`
	HideTag        bool   `json:"hide_tag"`
	NumericalValue string `json:"numerical_value"`
	IsGalaxy       bool   `json:"is_galaxy"`
	IsCustomGalaxy bool   `json:"is_custom_galaxy"`
	Inherited      int    `json:"inherited"`
}

// Add this to vendors/misp.go

type MispAddAttrSchema struct {
	EventID      string `json:"event_id"`
	Category     string `json:"category"`
	Type         string `json:"type"`
	Value        string `json:"value"`
	ToIDS        bool   `json:"to_ids"`
	UUID         string `json:"uuid"`
	Distribution string `json:"distribution"`
	Comment      string `json:"comment"`
}

// Request payload for attaching a tag
type MispAttachTagRequest struct {
	UUID string `json:"uuid"` // The UUID or ID of the Event or Attribute
	Tag  string `json:"tag"`  // The Tag ID or Tag Name
}

type MispWorkflowRequest struct {
	EventInfo      string `json:"event_info"`
	AttributeValue string `json:"attribute_value"`
	AttributeType  string `json:"attribute_type"`
	TagName        string `json:"tag_name"`
}

func NewTag(name, color, org, user string) *Tag {
	if color == "" {
		color = "#4b3878"
	}
	if name == "" {
		name = "syslogger:regular"
	}
	return &Tag{
		Name:           name,
		Color:          color,
		OrgID:          org,
		UserID:         user,
		Exportable:     true,
		HideTag:        false,
		NumericalValue: "0",
		IsGalaxy:       false,
		IsCustomGalaxy: false,
		Inherited:      0,
	}
}
