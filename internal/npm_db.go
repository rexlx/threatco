package internal

// NpmVulnerability defines the metadata for a malicious or compromised package.
type NpmVulnerability struct {
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Type        string `json:"type"` // e.g., Typosquat, Supply Chain, Malware
}

// MaliciousNpmPackages is the static database of known bad dependencies.
// This list is expanded to include React ecosystem threats and recent 2024/2025 findings.
var MaliciousNpmPackages = map[string]NpmVulnerability{
	// --- React Ecosystem Typosquats ---
	"reacht": {
		Description: "Typosquat of 'react'. Steals environment variables and Discord tokens.",
		Severity:    "critical",
		Type:        "Typosquat",
	},
	"react-dom-scripts": {
		Description: "Typosquat of 'react-dom'. Executes malicious post-install scripts to install backdoors.",
		Severity:    "critical",
		Type:        "Malware",
	},
	"react-redux-router": {
		Description: "Typosquat targeting the popular Redux/Router integration. Contains a credential stealer.",
		Severity:    "high",
		Type:        "Typosquat",
	},
	"react-router-dom-v6": {
		Description: "Malicious version pretending to be a V6 backport. Exfiltrates .env files.",
		Severity:    "high",
		Type:        "Typosquat",
	},
	"react-scripts-webpack": {
		Description: "Typosquat of react-scripts. Modifies webpack config to inject scripts into production builds.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"react-native-clipboard-lib": {
		Description: "Malicious library that monitors the system clipboard for BIP39 mnemonic phrases.",
		Severity:    "critical",
		Type:        "Malware",
	},
	// --- 2025 React & Related Typosquats / Malware Waves ---
	"reeact-login-page": {
		Description: "Typosquat of popular 'react-login-page'. Deploys keylogger and exfiltrates sensitive data (part of a 16-package campaign by author 'lolapalooza' targeting React login/UI components).",
		Severity:    "critical",
		Type:        "Typosquat + Malware",
	},
	"react-router-dom.js": {
		Description: "Typosquat of 'react-router-dom' (added .js suffix). Part of July/October 2025 wave delivering multi-stage info-stealers (credential harvesting across Windows/macOS/Linux via postinstall scripts and obfuscated payloads).",
		Severity:    "critical",
		Type:        "Typosquat + Info Stealer",
	},
	"vite-plugin-react-extend": {
		Description: "Typosquat of official '@vitejs/plugin-react'. Deploys destructive payloads (recursive file deletion, system crashes) targeting React/Vite projects; remained undetected for years in some cases.",
		Severity:    "critical",
		Type:        "Typosquat + Destructive Malware",
	},
	"zustand.js": {
		Description: "Typosquat of 'zustand' state management lib (common in React apps). Part of the same 2025 multi-stage credential theft campaign as react-router-dom.js variants.",
		Severity:    "high",
		Type:        "Typosquat + Info Stealer",
	},
	"nodemonjs": {
		Description: "Typosquat of 'nodemon'. Delivers obfuscated info-stealer payloads in 2025 campaigns affecting React/Next.js developer workflows.",
		Severity:    "high",
		Type:        "Typosquat + Malware",
	},
	"typescriptjs": {
		Description: "Typosquat of 'typescript'. Part of coordinated 2025 waves using postinstall hooks to launch cross-platform stealers targeting dev environments.",
		Severity:    "high",
		Type:        "Typosquat + Info Stealer",
	},

	// --- High Profile Supply Chain Incidents ---
	"ua-parser-js": {
		Description: "Versions 0.7.29, 0.8.1, and 1.0.1 were compromised via account takeover to include cryptominers.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"coa": {
		Description: "Version 2.0.2 was compromised. Widely used in React build pipelines via SVGO.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"node-ipc": {
		Description: "Versions 10.1.1 and 10.1.2 contained 'peacemod' code that deleted files on specific system locales.",
		Severity:    "critical",
		Type:        "Sabotage",
	},
	"polyfill-library": {
		Description: "Associated with the polyfill.io supply chain attack; injects malicious redirects into browsers.",
		Severity:    "high",
		Type:        "Supply Chain",
	},

	// --- Recent 2024/2025 Malware Findings ---
	"crossenv": {
		Description: "Typosquat of 'cross-env'. Exfiltrates process.env to a remote server.",
		Severity:    "high",
		Type:        "Typosquat",
	},
	"everything": {
		Description: "A 'dependency hell' package designed to crash systems by installing every npm package as a dependency.",
		Severity:    "medium",
		Type:        "DoS",
	},
	"discord-selfbot-v14": {
		Description: "Several variations found in 2024 containing token exfiltration logic.",
		Severity:    "high",
		Type:        "Malware",
	},
	"hidden-wallet-stealer": {
		Description: "Found disguised as a helper for react-native-crypto. Steals private keys.",
		Severity:    "critical",
		Type:        "Malware",
	},
	"modified-axios": {
		Description: "disguised as a performance fork of axios. Logs all POST request bodies to a C2 server.",
		Severity:    "critical",
		Type:        "Malware",
	},
}
