package internal

type NpmVulnerability struct {
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Type        string `json:"type"` // e.g., Typosquat, Supply Chain, Malware
}

// MaliciousNpmPackages is the static database of known bad dependencies.
var MaliciousNpmPackages = map[string]NpmVulnerability{
	"axios": {
		Description: "Official package compromised (Mar 2026). Versions 1.14.1 and 0.30.4 contain a RAT (Remote Access Trojan) via 'plain-crypto-js' dependency.",
		Severity:    "critical",
		Type:        "Supply Chain / Account Takeover",
	},
	"plain-crypto-js": {
		Description: "Malicious dependency used in the 2026 Axios attack. Deploys cross-platform droppers and C2 beacons.",
		Severity:    "critical",
		Type:        "Malware / Dropper",
	},

	"debug": {
		Description: "Compromised Sept 2025 via phished maintainer. Malicious versions target crypto wallets and swap addresses in transit.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"chalk": {
		Description: "Compromised Sept 2025 (same wave as 'debug'). Injected code for browser-based wallet hijacking.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"ansi-styles": {
		Description: "Part of the Sept 2025 utility compromise wave; performs network response manipulation to steal crypto.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"@shadanai/openclaw": {
		Description: "Linked to 2025/2026 malware waves; known to vendor 'plain-crypto-js' and execute info-stealing payloads.",
		Severity:    "high",
		Type:        "Malware",
	},

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

	"reeact-login-page": {
		Description: "Typosquat of 'react-login-page'. Deploys keylogger (part of the 'lolapalooza' campaign).",
		Severity:    "critical",
		Type:        "Typosquat + Malware",
	},
	"react-router-dom.js": {
		Description: "Typosquat targeting React projects. Delivers multi-stage info-stealers via postinstall scripts.",
		Severity:    "critical",
		Type:        "Typosquat + Info Stealer",
	},
	"vite-plugin-react-extend": {
		Description: "Typosquat of official Vite plugin. Deploys destructive payloads including recursive file deletion.",
		Severity:    "critical",
		Type:        "Destructive Malware",
	},
	"zustand.js": {
		Description: "Typosquat of 'zustand'. Part of the 2025 multi-stage credential theft campaign.",
		Severity:    "high",
		Type:        "Typosquat + Info Stealer",
	},

	"ua-parser-js": {
		Description: "Versions 0.7.29, 0.8.1, and 1.0.1 were compromised to include cryptominers.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"coa": {
		Description: "Version 2.0.2 was compromised. Widely used in React build pipelines via SVGO.",
		Severity:    "critical",
		Type:        "Supply Chain",
	},
	"node-ipc": {
		Description: "Versions 10.1.1 and 10.1.2 contained 'peacemod' code for file deletion (Sabotage).",
		Severity:    "critical",
		Type:        "Sabotage",
	},
	"sync-axios": {
		Description: "Malicious 2024 package targeting Discord tokens and performing process hijacking.",
		Severity:    "critical",
		Type:        "Malware",
	},

	"crossenv": {
		Description: "Typosquat of 'cross-env'. Exfiltrates process.env to a remote server.",
		Severity:    "high",
		Type:        "Typosquat",
	},
	"everything": {
		Description: "A 'dependency hell' package designed to crash systems (DoS).",
		Severity:    "medium",
		Type:        "DoS",
	},
	"modified-axios": {
		Description: "Disguised as a performance fork. Logs POST request bodies to a C2 server.",
		Severity:    "critical",
		Type:        "Malware",
	},
}
