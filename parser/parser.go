package parser

import (
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type Contextualizer struct {
	ID          string
	Expressions map[string]*regexp.Regexp
	Checks      *PrivateChecks
}

type PrivateChecks struct {
	IgnorePrivateIPs bool
	IgnoredDomains   map[string]struct{}
	IgnoredEmails    map[string]struct{}
}

type Match struct {
	Value string
	Type  string
}

func NewContextualizer(ignoreIPs bool, ignoreDomains []string, ignoreEmails []string) *Contextualizer {
	domainMap := make(map[string]struct{}, len(ignoreDomains))
	for _, d := range ignoreDomains {
		domainMap[strings.ToLower(d)] = struct{}{}
	}

	emailMap := make(map[string]struct{}, len(ignoreEmails))
	for _, e := range ignoreEmails {
		emailMap[strings.ToLower(e)] = struct{}{}
	}

	return &Contextualizer{
		ID: "contextualizer",
		Checks: &PrivateChecks{
			IgnorePrivateIPs: ignoreIPs,
			IgnoredDomains:   domainMap,
			IgnoredEmails:    emailMap,
		},
		Expressions: map[string]*regexp.Regexp{
			"md5":      regexp.MustCompile(`([a-fA-F\d]{32})`),
			"sha1":     regexp.MustCompile(`([a-fA-F\d]{40})`),
			"sha256":   regexp.MustCompile(`([a-fA-F\d]{64})`),
			"sha512":   regexp.MustCompile(`([a-fA-F\d]{128})`),
			"ipv4":     regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`),
			"ipv6":     regexp.MustCompile(`([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})`),
			"email":    regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
			"url":      regexp.MustCompile(`((https?|ftp):\/\/[^\s/$.?#].[^\s]*)`),
			"domain":   regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,3})\b`),
			"filepath": regexp.MustCompile(`([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)`),
			"filename": regexp.MustCompile(`^[\w\-.]+\.[a-zA-Z]{2,4}$`),
		},
	}
}

// isHashType returns true if the kind is a known hash algorithm
func isHashType(kind string) bool {
	return kind == "md5" || kind == "sha1" || kind == "sha256" || kind == "sha512"
}

// isHexDigit checks if a byte is a valid hexadecimal character
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func (c *Contextualizer) GetMatches(text string, kind string, regex *regexp.Regexp) []Match {
	indices := regex.FindAllStringIndex(text, -1)
	var results []Match

	for _, idx := range indices {
		match := text[idx[0]:idx[1]]
		if kind == "url" {
			match = strings.TrimRight(match, "/.,;:")
			match = strings.TrimSuffix(match, "/")
		}

		cleanMatch := strings.ToLower(match)

		// High-fidelity boundary check for hashes
		if isHashType(kind) {
			if (idx[0] > 0 && isHexDigit(text[idx[0]-1])) || (idx[1] < len(text) && isHexDigit(text[idx[1]])) {
				continue
			}
		}

		switch kind {
		case "filepath":
			if strings.HasPrefix(cleanMatch, "http") || strings.HasPrefix(cleanMatch, "www") {
				continue
			}
		case "ipv4":
			if c.Checks.IgnorePrivateIPs && isPrivateIP(match) {
				continue
			}
		case "email":
			if _, exists := c.Checks.IgnoredEmails[cleanMatch]; exists {
				continue
			}
		case "domain":
			if c.isDomainIgnored(cleanMatch) {
				continue
			}
			baseDomain, err := extractSecondLevelDomain(cleanMatch)
			if err == nil && baseDomain != "" && !c.isDomainIgnored(baseDomain) {
				results = append(results, Match{Value: baseDomain, Type: "base_domain"})
			}
		}

		finalValue := match
		if kind == "domain" || kind == "email" || isHashType(kind) {
			finalValue = cleanMatch
		}

		if finalValue != "" {
			results = append(results, Match{Value: finalValue, Type: kind})
		}
	}
	return results
}

type indexRange struct {
	start int
	end   int
}

func (c *Contextualizer) ExtractAll(text string) map[string][]Match {
	results := make(map[string][]Match)
	urlRanges := []indexRange{}

	// Track hashes by their first 8 characters to prevent duplicate type detection
	hashTracker := make(map[string]string)

	if urlRegex, ok := c.Expressions["url"]; ok {
		indices := urlRegex.FindAllStringIndex(text, -1)
		for _, idx := range indices {
			urlRanges = append(urlRanges, indexRange{idx[0], idx[1]})
			matchVal := strings.TrimRight(text[idx[0]:idx[1]], "/.,;:")
			results["url"] = append(results["url"], Match{Value: matchVal, Type: "url"})
		}
	}

	for kind, regex := range c.Expressions {
		if kind == "url" {
			continue
		}

		rawMatches := regex.FindAllStringIndex(text, -1)
		seen := make(map[string]bool)

		for _, idx := range rawMatches {
			val := text[idx[0]:idx[1]]
			cleanVal := strings.ToLower(val)

			if seen[cleanVal] {
				continue
			}

			// Fidelity check: ensure hex matches aren't substrings of longer hex strings
			if isHashType(kind) {
				if (idx[0] > 0 && isHexDigit(text[idx[0]-1])) || (idx[1] < len(text) && isHexDigit(text[idx[1]])) {
					continue
				}

				// Key-based tracking: use first 8 chars as requested
				prefix := cleanVal
				if len(prefix) > 8 {
					prefix = prefix[:8]
				}
				if _, alreadyFound := hashTracker[prefix]; alreadyFound {
					continue // Already processed this entity as a different/longer hash type
				}
				hashTracker[prefix] = kind
			}

			switch kind {
			case "filepath":
				if strings.HasPrefix(cleanVal, "http") || strings.HasPrefix(cleanVal, "www") {
					continue
				}
				isInsideUrl := false
				for _, r := range urlRanges {
					if idx[0] >= r.start && idx[1] <= r.end {
						isInsideUrl = true
						break
					}
				}
				if isInsideUrl {
					continue
				}
			case "ipv4":
				if c.Checks.IgnorePrivateIPs && isPrivateIP(val) {
					continue
				}
			case "email":
				if _, exists := c.Checks.IgnoredEmails[cleanVal]; exists {
					continue
				}
			case "domain":
				if c.isDomainIgnored(cleanVal) {
					continue
				}
			}

			seen[cleanVal] = true
			results[kind] = append(results[kind], Match{Value: cleanVal, Type: kind})
		}
	}

	return results
}

func (c *Contextualizer) isDomainIgnored(domain string) bool {
	current := domain
	for {
		if _, exists := c.Checks.IgnoredDomains[current]; exists {
			return true
		}
		idx := strings.Index(current, ".")
		if idx == -1 {
			break
		}
		current = current[idx+1:]
	}
	return false
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

func extractSecondLevelDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

//
