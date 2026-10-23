// Refanging patterns
const reDots = /\[\.\]|\(\.\)|\{\.\}/gi;
const reAt = /\[at\]|\(at\)| @ /gi;
const reHxxp = /h[xt]{2}p(s?):\/\//gi;
const reColons = /\[:\]/gi;

// Noise filter patterns
const reMetricOrDuration = /^\d+(\.\d+)?(ns|us|µs|ms|s|m|h|d|kb|mb|gb|tb|b|%|fps|hz|khz|mhz|ghz)$/i;
const reSystemdUnit = /\.(service|scope|slice|socket|target|timer|mount|automount|swap|device)$/i;
const reLogTokenSuffix = /\.(detection|version|actions)$/i;
const reProcPath = /^\/?proc\/\d+/i;
const reTimestampFragment = /^(\d+[-_T:]?)*\d+\.\d+(z|utc|gmt)$/i;

const FILE_EXTS = new Set([
  '.exe', '.dll', '.bin', '.dat', '.sys', '.tmp', '.log', '.cfg', '.ini', '.vbs',
  '.ps1', '.bat', '.cmd', '.msi', '.jar', '.go', '.cpp', '.h', '.txt', '.pdf',
  '.sh', '.zip', '.tar', '.gz', '.rar', '.7z', '.iso', '.img', '.apk', '.deb',
  '.rpm', '.dmg', '.pkg', '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.flv', '.wmv',
  '.wav', '.flac', '.ogg', '.webm', '.app', '.js', '.ts', '.py', '.rb', '.php',
  '.cs', '.rs', '.swift', '.json', '.xml', '.yaml', '.yml', '.csv', '.sql', '.db',
  '.sqlite', '.md', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.html', '.htm',
  '.so', '.service', '.scope', '.socket', '.target', '.rules'
]);

export function refang(text) {
  if (!text) return "";
  text = text.replace(reDots, ".");
  text = text.replace(reAt, "@");
  text = text.replace(reHxxp, "http$1://");
  text = text.replace(reColons, ":");
  return text;
}

export function isNoiseValue(val) {
  if (!val) return true;
  val = val.trim();
  if (val === "") return true;

  const lower = val.toLowerCase();
  if (reMetricOrDuration.test(val)) return true;
  if (reSystemdUnit.test(val)) return true;
  if (reLogTokenSuffix.test(val)) return true;
  if (reTimestampFragment.test(val) && !lower.endsWith('.7z')) return true;
  if (lower.startsWith('org.freedesktop')) return true;

  return false;
}

export function isLikelyFilename(val) {
  val = val.toLowerCase();
  if (val.startsWith('www.') || val.startsWith('http://') || val.startsWith('https://') || val.startsWith('ftp://')) {
    return false;
  }
  if (val.startsWith('./') || val.startsWith('../') || val.includes('/') || val.includes('\\')) {
    return true;
  }
  if (val.includes('_')) {
    return true;
  }
  const lastDot = val.lastIndexOf('.');
  if (lastDot !== -1) {
    const ext = val.slice(lastDot);
    if (FILE_EXTS.has(ext)) {
      return true;
    }
  }
  const dotCount = (val.match(/\./g) || []).length;
  if (dotCount > 3) {
    return true;
  }
  return false;
}

function isAllDigits(s) {
  if (!s) return false;
  return /^\d+$/.test(s);
}

export class Contextualizer {
  constructor(ignorePrivateIPs = false, ignoredDomains = [], ignoredEmails = []) {
    this.id = "contextualizer";
    this.ignorePrivateIPs = ignorePrivateIPs;
    this.ignoredDomains = new Set(ignoredDomains.map(d => d.toLowerCase()));
    this.ignoredEmails = new Set(ignoredEmails.map(e => e.toLowerCase()));

    // Expressions ordered with longer hashes first to support prefix tracking
    this.expressions = {
      "sha512": /\b([a-fA-F\d]{128})\b/g,
      "sha256": /\b([a-fA-F\d]{64})\b/g,
      "sha1": /\b([a-fA-F\d]{40})\b/g,
      "md5": /\b([a-fA-F\d]{32})\b/g,
      "ipv4": /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
      "ipv6": /\b([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})\b/g,
      "email": /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
      "url": /((https?|ftp):\/\/[^\s/$.?#].[^\s]*)/g,
      "domain": /\b([a-z0-9.-]+\.[a-z]{2,24})\b/g,
      "filepath": /\b([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)\b/g,
      "filename": /\b[\w\-.]+\.[a-z0-9]*[a-z][a-z0-9]*\b/g,
      "cve": /\b(CVE-\d{4}-\d{4,7})\b/g,
    };
  }

  isHashType(kind) {
    return kind === "md5" || kind === "sha1" || kind === "sha256" || kind === "sha512";
  }

  isHexDigit(char) {
    if (!char) return false;
    return /^[a-fA-F\d]$/.test(char);
  }

  isDomainIgnored(domain) {
    let current = domain.toLowerCase();
    while (current) {
      if (this.ignoredDomains.has(current)) {
        return true;
      }
      const idx = current.indexOf('.');
      if (idx === -1) break;
      current = current.slice(idx + 1);
    }
    return false;
  }

  isPrivateIP(ipStr) {
    const parts = (ipStr || "").trim().split('.');
    if (parts.length !== 4) return false;
    const nums = parts.map(p => Number(p));
    if (nums.some(n => isNaN(n) || n < 0 || n > 255 || !Number.isInteger(n))) {
      return false;
    }
    const [a, b] = nums;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }

  extractSecondLevelDomain(domain) {
    if (!domain) return "";
    const parts = domain.split('.');
    if (parts.length < 2) return "";
    const ccTlds = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']);
    if (parts.length >= 3 && ccTlds.has(parts[parts.length - 2])) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  isValidTLD(domain) {
    const parts = domain.split('.');
    const suffix = parts[parts.length - 1];
    if (FILE_EXTS.has('.' + suffix)) return false;
    return suffix.length >= 2 && suffix.length <= 24 && !/^\d+$/.test(suffix);
  }

  isLikelyFilename(val) {
    return isLikelyFilename(val);
  }

  isValidMatch(kind, val) {
    const cleanVal = (val || "").trim().toLowerCase();
    if (!cleanVal || isNoiseValue(cleanVal)) {
      return false;
    }

    switch (kind) {
      case "filepath": {
        if (cleanVal.startsWith("http") || cleanVal.startsWith("www")) {
          return false;
        }
        const trimmed = cleanVal.startsWith("/") ? cleanVal.replace(/^\/+/, "") : cleanVal;
        if (reProcPath.test(cleanVal) || reProcPath.test(trimmed)) {
          return false;
        }
        const badPrefixes = ["proc/", "usr/", "run/", "sys/", "dev/", "suricata/", "rules/", "post/", "research/"];
        for (const pfx of badPrefixes) {
          if (cleanVal.startsWith(pfx) || trimmed.startsWith(pfx)) {
            return false;
          }
        }
        const parts = trimmed.split("/");
        const last = parts[parts.length - 1];
        if (isAllDigits(last) || parts[0].length <= 1) {
          return false;
        }
        break;
      }
      case "ipv4": {
        if (this.ignorePrivateIPs && this.isPrivateIP(val)) {
          return false;
        }
        break;
      }
      case "email": {
        if (this.ignoredEmails.has(cleanVal)) {
          return false;
        }
        break;
      }
      case "domain": {
        if (isLikelyFilename(cleanVal) || !this.isValidTLD(cleanVal) || this.isDomainIgnored(cleanVal)) {
          return false;
        }
        break;
      }
    }

    return true;
  }

  getMatches(text, kind, regex = null) {
    const rx = regex
      ? new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g')
      : new RegExp(this.expressions[kind].source, this.expressions[kind].flags);
    const results = [];
    let match;

    while ((match = rx.exec(text)) !== null) {
      let val = match[0];
      if (kind === "url") {
        val = val.replace(/[/.,;:"'}\])<>]+$/, '').replace(/\/+$/, '');
      }

      const cleanMatch = val.trim().toLowerCase();
      if (!cleanMatch) continue;

      if (this.isHashType(kind)) {
        const start = match.index;
        const end = start + val.length;
        if ((start > 0 && this.isHexDigit(text[start - 1])) || (end < text.length && this.isHexDigit(text[end]))) {
          continue;
        }
      }

      if (!this.isValidMatch(kind, val)) {
        continue;
      }

      if (kind === "domain") {
        const baseDomain = this.extractSecondLevelDomain(cleanMatch);
        if (baseDomain && !this.isDomainIgnored(baseDomain) && !isNoiseValue(baseDomain) && this.isValidTLD(baseDomain)) {
          results.push({ value: baseDomain, type: "base_domain" });
        }
      }

      let finalValue = val;
      if (kind === "domain" || kind == "email" || this.isHashType(kind)) {
        finalValue = cleanMatch;
      } else if (kind === "cve") {
        finalValue = val.toUpperCase();
      }

      if (finalValue) {
        results.push({ value: finalValue, type: kind });
      }
    }

    return results;
  }

  extractAll(text) {
    const cleanText = refang(text || "");
    const results = {};
    const urlRanges = [];
    const hashTracker = {};

    // 1. Process URLs first to establish safe zones for filepath
    if (this.expressions["url"]) {
      const urlRegex = new RegExp(this.expressions["url"].source, this.expressions["url"].flags);
      let urlMatch;
      while ((urlMatch = urlRegex.exec(cleanText)) !== null) {
        let val = urlMatch[0].replace(/[/.,;:]+$/, '');
        urlRanges.push({ start: urlMatch.index, end: urlMatch.index + val.length });
        if (!results["url"]) results["url"] = [];
        results["url"].push({ value: val, type: "url" });
      }
    }

    // 2. Process all other types
    for (const [kind, expr] of Object.entries(this.expressions)) {
      if (kind === "url") continue;

      const regex = new RegExp(expr.source, expr.flags.includes('g') ? expr.flags : expr.flags + 'g');
      let match;
      const seen = new Set();

      while ((match = regex.exec(cleanText)) !== null) {
        const val = match[0];
        const cleanVal = val.trim().toLowerCase();
        const start = match.index;
        const end = start + val.length;

        if (!cleanVal || seen.has(cleanVal)) continue;

        // Boundary check for hashes (preventing substring matches)
        if (this.isHashType(kind)) {
          if ((start > 0 && this.isHexDigit(cleanText[start - 1])) || (end < cleanText.length && this.isHexDigit(cleanText[end]))) {
            continue;
          }

          let prefix = cleanVal;
          if (prefix.length > 8) {
            prefix = prefix.slice(0, 8);
          }
          if (hashTracker[prefix]) {
            continue;
          }
          hashTracker[prefix] = kind;
        }

        // URL collision check for filepath
        if (kind === "filepath") {
          let isInsideUrl = false;
          for (const r of urlRanges) {
            if (start >= r.start && end <= r.end) {
              isInsideUrl = true;
              break;
            }
          }
          if (isInsideUrl) continue;
        }

        if (!this.isValidMatch(kind, val)) {
          continue;
        }

        seen.add(cleanVal);
        let outVal = cleanVal;
        if (kind === "cve") {
          outVal = val.toUpperCase();
        }

        if (!results[kind]) results[kind] = [];
        results[kind].push({ value: outVal, type: kind });
      }
    }

    return results;
  }
}