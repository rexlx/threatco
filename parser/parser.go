package parser

import (
	"net"
	"path/filepath"
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
			"md5":      regexp.MustCompile(`(?i)\b([a-f\d]{32})\b`),
			"sha1":     regexp.MustCompile(`(?i)\b([a-f\d]{40})\b`),
			"sha256":   regexp.MustCompile(`(?i)\b([a-f\d]{64})\b`),
			"sha512":   regexp.MustCompile(`(?i)\b([a-f\d]{128})\b`),
			"ipv4":     regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`),
			"ipv6":     regexp.MustCompile(`(?i)\b([a-f\d]{4}(:[a-f\d]{4}){7})\b`),
			"email":    regexp.MustCompile(`(?i)\b([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})\b`),
			"url":      regexp.MustCompile(`(?i)((https?|ftp):\/\/[^\s/$.?#].[^\s]*)`),
			"domain":   regexp.MustCompile(`(?i)\b([a-z0-9.-]+\.[a-z]{2,24})\b`),
			"filepath": regexp.MustCompile(`\b([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)\b`),
			"filename": regexp.MustCompile(`(?i)\b[\w\-\.]+\.[a-z0-9]{2,6}\b`),
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
				if isLikelyFilename(cleanVal) {
					if !c.isValidTLD(cleanVal) {
						continue
					}
				}
				if !c.isValidTLD(cleanVal) || c.isDomainIgnored(cleanVal) {
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

func (c *Contextualizer) isValidTLD(domain string) bool {
	suffix, icann := publicsuffix.PublicSuffix(domain)

	return icann && suffix != ""
}

func isLikelyFilename(val string) bool {
	val = strings.ToLower(val)

	// Explicit path indicators are strong filename signals
	if strings.HasPrefix(val, "./") || strings.HasPrefix(val, "../") ||
		strings.Contains(val, "/") || strings.Contains(val, "\\") {
		return true
	}

	// Underscores are extremely rare in domains but common in files
	if strings.Contains(val, "_") {
		return true
	}

	fileExts := map[string]struct{}{
		".exe": {}, ".dll": {}, ".bin": {}, ".dat": {}, ".sys": {},
		".tmp": {}, ".log": {}, ".cfg": {}, ".ini": {}, ".vbs": {},
		".ps1": {}, ".bat": {}, ".cmd": {}, ".msi": {}, ".jar": {},
		".go": {}, ".cpp": {}, ".h": {}, ".txt": {}, ".pdf": {},
		".sh": {}, ".zip": {}, ".tar": {}, ".gz": {},
	}

	ext := filepath.Ext(val)
	if _, exists := fileExts[ext]; exists {
		return true
	}

	// Versioned files (e.g., app.v1.0.2) often have many dots.
	// We only flag this if it doesn't look like a standard domain.
	if strings.Count(val, ".") > 3 && !strings.HasPrefix(val, "www.") {
		return true
	}

	return false
}
