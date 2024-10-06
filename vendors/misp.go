package vendors

import (
	"strconv"
	"time"

	"github.com/google/uuid"
)

type Event struct {
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
	Protected          string      `json:"protected"`
	Org                Org         `json:"Org"`
	Orgc               Orgc        `json:"Orgc"`
	Attribute          []Attribute `json:"Attribute"`
}

type Response struct {
	Response []struct {
		Event Event `json:"Event"`
	} `json:"response"`
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

func (e *Event) SetTimestampString(tstamp, published, sighted int64) error {
	e.Timestamp = strconv.Itoa(int(tstamp))
	e.PublishTimestamp = strconv.Itoa(int(published))
	e.SightingTimestamp = strconv.Itoa(int(sighted))
	return nil
}

func NewEvent(org, dist, info, analysis, threat, xuuid string) *Event {
	attrs := make([]Attribute, 0)
	now := time.Now().Unix()
	id := uuid.New()
	e := &Event{
		Attribute:     attrs,
		UUID:          id.String(),
		OrgID:         org,
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
