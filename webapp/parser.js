export class Contextualizer {
  constructor(ignorePrivateIPs = false, ignoredDomains = [], ignoredEmails = []) {
    this.ignorePrivateIPs = ignorePrivateIPs;
    this.ignoredDomains = new Set(ignoredDomains.map(d => d.toLowerCase()));
    this.ignoredEmails = new Set(ignoredEmails.map(e => e.toLowerCase()));

    this.expressions = {
      // Boundaries \b are used for general matches
      // For hashes, we use custom logic to ensure we aren't matching substrings of longer hex strings
      "md5": /\b([a-fA-F\d]{32})\b/g,
      "sha1": /\b([a-fA-F\d]{40})\b/g,
      "sha256": /\b([a-fA-F\d]{64})\b/g,
      "sha512": /\b([a-fA-F\d]{128})\b/g,
      "ipv4": /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
      "ipv6": /\b([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})\b/g,
      "email": /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
      "url": /((https?|ftp):\/\/[^\s/$.?#].[^\s]*)/g,
      "domain": /\b([a-z0-9.-]+\.[a-z]{2,24})\b/g,
      "filepath": /\b([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)\b/g,
      // Logic-based: Matches a dot and 2-6 char extension
      "filename": /\b[\w\-.]+\.[a-z0-9]{2,6}\b/g,
    };
  }

  /**
   * High-fidelity boundary check for hex digits (Hashes)
   */
  isHexDigit(char) {
    return /^[a-fA-F\d]$/.test(char);
  }

  isLikelyFilename(val) {
    val = val.toLowerCase();
    // Indicators that it's a file path
    if (val.includes('/') || val.includes('\\') || val.includes('_') || val.startsWith('./') || val.startsWith('../')) {
      return true;
    }
    // High dot count (versioning) often indicates a file
    const dots = (val.match(/\./g) || []).length;
    if (dots > 2 && !val.startsWith('www.')) {
      return true;
    }
    return false;
  }

  isValidTLD(domain) {
    // In a browser/JS environment, you'd ideally use a library like 'psl' or 'tldjs'.
    // Here, we use a length heuristic: most TLDs are 2-6 chars and recognized.
    const parts = domain.split('.');
    const suffix = parts[parts.length - 1];
    
    // Basic filter: common non-TLD extensions that are 2-4 chars
    const fileExts = new Set(['exe', 'dll', 'bin', 'dat', 'sys', 'tmp', 'log', 'cfg', 'ini', 'vbs', 'ps1', 'bat', 'cmd', 'msi', 'jar', 'csv']);
    if (fileExts.has(suffix)) return false;

    return suffix.length >= 2 && suffix.length <= 6;
  }

  extractAll(text) {
    let results = {};
    const urlRanges = [];

    // 1. Process URLs first to prevent sub-matching
    const urlRegex = this.expressions["url"];
    let urlMatch;
    while ((urlMatch = urlRegex.exec(text)) !== null) {
      let val = urlMatch[0].replace(/[/.,;:]+$/, ''); // Trim trailing punctuation
      urlRanges.push({ start: urlMatch.index, end: urlMatch.index + val.length });
      if (!results["url"]) results["url"] = [];
      results["url"].push({ value: val, type: "url" });
    }

    // 2. Process all other types
    for (const [kind, regex] of Object.entries(this.expressions)) {
      if (kind === "url") continue;
      
      regex.lastIndex = 0;
      let match;
      const seen = new Set();

      while ((match = regex.exec(text)) !== null) {
        let val = match[0];
        const cleanVal = val.toLowerCase();
        const start = match.index;
        const end = start + val.length;

        if (seen.has(cleanVal)) continue;

        // Hash Fidelity: check if neighbors are hex digits
        if (["md5", "sha1", "sha256", "sha512"].includes(kind)) {
          const prevChar = text[start - 1];
          const nextChar = text[end];
          if (this.isHexDigit(prevChar) || this.isHexDigit(nextChar)) {
            continue;
          }
        }

        // Domain vs Filename Classification
        if (kind === "domain") {
          if (this.isLikelyFilename(cleanVal) && !this.isValidTLD(cleanVal)) continue;
          if (!this.isValidTLD(cleanVal)) continue;
        }

        if (kind === "filepath") {
          if (cleanVal.startsWith('http') || cleanVal.startsWith('www')) continue;
          // Ensure we aren't inside a URL already found
          if (urlRanges.some(r => start >= r.start && end <= r.end)) continue;
        }

        if (!results[kind]) results[kind] = [];
        results[kind].push({ value: val, type: kind });
        seen.add(cleanVal);
      }
    }
    return results;
  }
}