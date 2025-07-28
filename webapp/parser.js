export class Contextualizer {
  constructor() {
    this.expressions = {
        "md5": /([a-fA-F\d]{32})/g,
        "sha1": /([a-fA-F\d]{40})/g,
        "sha256": /([a-fA-F\d]{64})/g,
        "sha512": /([a-fA-F\d]{128})/g,
        "ipv4": /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g,
        "ipv6": /([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})/g,
        "email": /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
        "url": /((https?|ftp):\/\/[^\s/$.?#].[^\s]*)/g,
        "domain": /([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
        "filepath": /([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)/g,
        "filename": /^(?!(\d{1,3}\.){2}\d{1,3}\.[\d]{2,4}$)[\w\-. ]+\.[\w]{2,4}$/g,
    };
    this.context = [];
  }

  getMatches(text, regex) {
    regex.lastIndex = 0;
    let matches = [];
    let match;
    while (match = regex.exec(text)) {
      matches.push(match[0]);
    }
    return matches;
  }
}