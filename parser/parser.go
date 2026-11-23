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

// IsEnrichable returns true if the indicator type has high enough fidelity
// to justify spending rate-limited external Threat Intel API quota.
func (m Match) IsEnrichable() bool {
	switch m.Type {
	case "sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "base_domain", "url", "cve":
		return true
	default:
		// Bare filenames and filepaths are logged locally without burning TI quota
		return false
	}
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
			"filename": regexp.MustCompile(`(?i)\b[\w\-\.]+\.[a-z0-9]*[a-z][a-z0-9]*\b`),
			"cve":      regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,7})\b`),
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
	if kind == "filename" && isPackageManagerNoise(text) {
		return nil
	}

	indices := regex.FindAllStringIndex(text, -1)
	var results []Match

	for _, idx := range indices {
		match := text[idx[0]:idx[1]]
		if kind == "url" {
			match = strings.TrimRight(match, "/.,;:\"'}])<>")
			match = strings.TrimSuffix(match, "/")
		}

		cleanMatch := strings.ToLower(strings.TrimSpace(match))
		if cleanMatch == "" {
			continue
		}

		// High-fidelity boundary check for hashes
		if isHashType(kind) {
			if (idx[0] > 0 && isHexDigit(text[idx[0]-1])) || (idx[1] < len(text) && isHexDigit(text[idx[1]])) {
				continue
			}
		}

		if !c.isValidMatch(kind, match) {
			continue
		}

		if kind == "domain" {
			baseDomain, err := extractSecondLevelDomain(cleanMatch)
			if err == nil && baseDomain != "" && !c.isDomainIgnored(baseDomain) && !isNoiseValue(baseDomain) && c.isValidTLD(baseDomain) {
				results = append(results, Match{Value: baseDomain, Type: "base_domain"})
			}
		}

		finalValue := match
		if kind == "domain" || kind == "email" || isHashType(kind) {
			finalValue = cleanMatch
		} else if kind == "cve" {
			finalValue = strings.ToUpper(match)
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
	// 1. Pre-process the text to remove defanging
	cleanText := Refang(text)

	results := make(map[string][]Match)
	urlRanges := []indexRange{}
	hashTracker := make(map[string]string)
	suppressFilenames := isPackageManagerNoise(cleanText)

	// 2. Handle URLs first to establish "safe zones" for filepath and filename parsers
	if urlRegex, ok := c.Expressions["url"]; ok {
		indices := urlRegex.FindAllStringIndex(cleanText, -1)
		for _, idx := range indices {
			// Trim common trailing punctuation often caught in URL regex
			matchVal := strings.TrimRight(cleanText[idx[0]:idx[1]], "/.,;:")

			// Track the range based on the actual length of the trimmed match
			urlRanges = append(urlRanges, indexRange{idx[0], idx[0] + len(matchVal)})
			results["url"] = append(results["url"], Match{Value: matchVal, Type: "url"})
		}
	}

	for kind, regex := range c.Expressions {
		if kind == "url" {
			continue
		}

		// Skip noisy filename extraction during verified OS/package updates,
		// while still permitting URL, domain, IP, and hash extraction on the same line.
		if kind == "filename" && suppressFilenames {
			continue
		}

		rawMatches := regex.FindAllStringIndex(cleanText, -1)
		seen := make(map[string]bool)

		for _, idx := range rawMatches {
			val := cleanText[idx[0]:idx[1]]
			cleanVal := strings.ToLower(strings.TrimSpace(val))

			if cleanVal == "" || seen[cleanVal] {
				continue
			}

			// Boundary check for hashes (preventing substring matches)
			if isHashType(kind) {
				if (idx[0] > 0 && isHexDigit(cleanText[idx[0]-1])) || (idx[1] < len(cleanText) && isHexDigit(cleanText[idx[1]])) {
					continue
				}

				// Check if this same string was already identified as a longer hash
				prefix := cleanVal
				if len(prefix) > 8 {
					prefix = prefix[:8]
				}
				if _, alreadyFound := hashTracker[prefix]; alreadyFound {
					continue
				}
				hashTracker[prefix] = kind
			}

			// URL collision check for filepath and filename
			if kind == "filepath" || kind == "filename" {
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
			}

			if !c.isValidMatch(kind, val) {
				continue
			}

			seen[cleanVal] = true
			outVal := cleanVal
			if kind == "cve" {
				outVal = strings.ToUpper(val)
			}
			results[kind] = append(results[kind], Match{Value: outVal, Type: kind})
		}
	}

	return results
}

func (c *Contextualizer) isValidMatch(kind, val string) bool {
	cleanVal := strings.ToLower(strings.TrimSpace(val))
	if cleanVal == "" || isNoiseValue(cleanVal) {
		return false
	}

	switch kind {
	case "filepath":
		if strings.HasPrefix(cleanVal, "http") || strings.HasPrefix(cleanVal, "www") {
			return false
		}
		trimmed := strings.TrimPrefix(cleanVal, "/")
		if reProcPath.MatchString(cleanVal) || reProcPath.MatchString(trimmed) {
			return false
		}
		for _, pfx := range []string{"proc/", "usr/", "run/", "sys/", "dev/", "suricata/", "rules/", "post/", "research/"} {
			if strings.HasPrefix(cleanVal, pfx) || strings.HasPrefix(trimmed, pfx) {
				return false
			}
		}
		parts := strings.Split(trimmed, "/")
		last := parts[len(parts)-1]
		if isAllDigits(last) || len(parts[0]) <= 1 {
			return false
		}

	case "filename":
		// 1. Filter out versioned shared libraries (e.g., libssl.so.1.1) and man pages (e.g., curl.1.gz)
		if reSharedLibVersion.MatchString(cleanVal) || (reManPage.MatchString(cleanVal) && !strings.HasSuffix(cleanVal, ".7z")) {
			return false
		}

		// 2. Filter out standard OS/language package archives
		if rePackageArtifact.MatchString(cleanVal) {
			return false
		}

		// 3. Reject emails or valid ICANN domains unless they clearly look like a file
		if strings.Contains(cleanVal, "@") {
			return false
		}
		if c.isValidTLD(cleanVal) && !isLikelyFilename(cleanVal) {
			return false
		}

		// 4. Require an actionable, high-risk extension so benign config/header/doc files don't flood logs
		ext := filepath.Ext(cleanVal)
		if _, isHighRisk := highRiskExts[ext]; !isHighRisk {
			return false
		}

	case "ipv4":
		if c.Checks.IgnorePrivateIPs && isPrivateIP(val) {
			return false
		}

	case "email":
		if _, exists := c.Checks.IgnoredEmails[cleanVal]; exists {
			return false
		}

	case "domain":
		if isLikelyFilename(cleanVal) || !c.isValidTLD(cleanVal) || c.isDomainIgnored(cleanVal) {
			return false
		}
	}

	return true
}

// isPackageManagerNoise checks whether a log line represents routine system package
// management activity targeting standard OS directories.
func isPackageManagerNoise(text string) bool {
	lower := strings.ToLower(text)

	// Check if the event originates from a known package manager
	hasPkgMgr := false
	for _, mgr := range []string{
		"apt-get", "apt ", "dpkg", "dnf", "yum", "pacman",
		"zypper", "apk ", "brew ", "snapd", "flatpak", "rpm ",
	} {
		if strings.Contains(lower, mgr) {
			hasPkgMgr = true
			break
		}
	}

	if !hasPkgMgr {
		return false
	}

	// Only suppress if the activity references standard system/package directories.
	// If a package manager touches /tmp, /dev/shm, /home, etc., we still want to inspect filenames.
	for _, safeDir := range []string{
		"/usr/lib", "/usr/share", "/usr/include", "/usr/bin", "/usr/sbin",
		"/var/cache/apt", "/var/lib/dpkg", "/var/cache/dnf", "/var/cache/pacman",
		"/lib/modules", "/etc/", "/opt/",
	} {
		if strings.Contains(lower, safeDir) {
			return true
		}
	}

	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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

	// www. prefix and URL schemes are strong domain/URL indicators, not filenames
	if strings.HasPrefix(val, "www.") || strings.HasPrefix(val, "http://") ||
		strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "ftp://") {
		return false
	}

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
		".sh": {}, ".zip": {}, ".tar": {}, ".gz": {}, ".rar": {},
		".7z": {}, ".iso": {}, ".img": {}, ".apk": {}, ".deb": {},
		".rpm": {}, ".dmg": {}, ".pkg": {}, ".mp3": {}, ".mp4": {},
		".avi": {}, ".mkv": {}, ".mov": {}, ".flv": {}, ".wmv": {},
		".wav": {}, ".flac": {}, ".ogg": {}, ".webm": {}, ".app": {},
		".js": {}, ".ts": {}, ".py": {}, ".rb": {}, ".php": {},
		".cs": {}, ".rs": {}, ".swift": {}, ".json": {}, ".xml": {},
		".yaml": {}, ".yml": {}, ".csv": {}, ".sql": {}, ".db": {},
		".sqlite": {}, ".md": {}, ".doc": {}, ".docx": {}, ".xls": {},
		".xlsx": {}, ".ppt": {}, ".pptx": {}, ".html": {}, ".htm": {},
		".so": {}, ".service": {}, ".scope": {}, ".socket": {},
		".target": {}, ".rules": {},
	}

	ext := filepath.Ext(val)
	if _, exists := fileExts[ext]; exists {
		return true
	}
	if _, exists := highRiskExts[ext]; exists {
		return true
	}

	// Versioned files (e.g., app.v1.0.2) often have many dots.
	if strings.Count(val, ".") > 3 {
		return true
	}

	return false
}

var (
	// High-signal executable, script, and archive extensions worth alerting on
	highRiskExts = map[string]struct{}{
		".exe": {}, ".dll": {}, ".sys": {}, ".scr": {}, ".cpl": {},
		".vbs": {}, ".vbe": {}, ".js": {}, ".jse": {}, ".wsf": {}, ".wsh": {},
		".ps1": {}, ".psm1": {}, ".bat": {}, ".cmd": {}, ".hta": {},
		".msi": {}, ".msp": {}, ".jar": {}, ".war": {}, ".ear": {},
		".sh": {}, ".bash": {}, ".zsh": {}, ".py": {}, ".pl": {}, ".rb": {},
		".elf": {}, ".bin": {}, ".out": {}, ".run": {}, ".appimage": {},
		".apk": {}, ".dmg": {}, ".pkg": {}, ".iso": {}, ".img": {},
		".zip": {}, ".7z": {}, ".rar": {}, ".tar": {}, ".tgz": {},
		".docm": {}, ".xlsm": {}, ".pptm": {}, ".lnk": {}, ".chm": {},
		".so": {},
	}

	// Pre-compile refanging patterns for performance
	reDots   = regexp.MustCompile(`(?i)\[\.\]|\(\.\)|\{\.\}`)
	reAt     = regexp.MustCompile(`(?i)\[at\]|\(at\)| @ `)
	reHxxp   = regexp.MustCompile(`(?i)h[x|t]{2}p(s?)://`)
	reColons = regexp.MustCompile(`(?i)\[:\]`)

	// Noise filter patterns
	reMetricOrDuration  = regexp.MustCompile(`(?i)^\d+(\.\d+)?(ns|us|µs|ms|s|m|h|d|kb|mb|gb|tb|b|%|fps|hz|khz|mhz|ghz)$`)
	reSystemdUnit       = regexp.MustCompile(`(?i)\.(service|scope|slice|socket|target|timer|mount|automount|swap|device)$`)
	reLogTokenSuffix    = regexp.MustCompile(`(?i)\.(detection|version|actions)$`)
	reProcPath          = regexp.MustCompile(`(?i)^/?proc/\d+`)
	reTimestampFragment = regexp.MustCompile(`(?i)^(\d+[-_T:]?)*\d+\.\d+(z|utc|gmt)$`)
	reSharedLibVersion  = regexp.MustCompile(`(?i)\.so(\.\d+)+$`)
	reManPage           = regexp.MustCompile(`(?i)\.\d[a-z]?(\.(gz|xz|bz2|zst))?$`)
	rePackageArtifact   = regexp.MustCompile(`(?i)\.(deb|rpm|whl|gem|crate|nupkg|tar\.(gz|xz|bz2|zst))$`)
)

func isNoiseValue(val string) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return true
	}
	if reMetricOrDuration.MatchString(val) {
		return true
	}
	if reSystemdUnit.MatchString(val) {
		return true
	}
	if reLogTokenSuffix.MatchString(val) {
		return true
	}
	if reTimestampFragment.MatchString(val) && !strings.HasSuffix(strings.ToLower(val), ".7z") {
		return true
	}
	if strings.HasPrefix(strings.ToLower(val), "org.freedesktop") {
		return true
	}
	return false
}

func Refang(text string) string {
	// 1. Standardize dots: [.] or (.) -> .
	text = reDots.ReplaceAllString(text, ".")

	// 2. Standardize "at" symbols: [at] -> @
	text = reAt.ReplaceAllString(text, "@")

	// 3. Standardize protocols: hxxp:// -> http://
	text = reHxxp.ReplaceAllString(text, "http$1://")

	// 4. Standardize colons: [:] -> :
	text = reColons.ReplaceAllString(text, ":")

	return text
}
