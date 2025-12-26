import { escapeHtml } from '../utils.js';

export class DnsTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-dns" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">DNS Lookup</h4>
            <p class="has-text-grey-light mb-4">Perform a server-side DNS forward (domain to IP) or reverse (IP to domain) lookup.</p>
            <div class="field has-addons">
                <div class="control is-expanded">
                    <input class="input has-background-dark has-text-white" type="text" id="inputDnsValue" placeholder="Enter Domain (e.g. example.com) or IP (e.g. 1.1.1.1)">
                </div>
                <div class="control">
                    <button class="button is-info is-outlined" id="btnRunDns">
                        <span class="icon"><i class="material-icons">search</i></span>
                        <span>Lookup</span>
                    </button>
                </div>
            </div>
            <div class="has-text-grey-light mt-2" id="dnsLookupResult"></div>
        </div>`;
    }

    attachListeners() {
        const btn = document.getElementById('btnRunDns');
        if (btn) btn.addEventListener('click', () => this.runLookup());
    }

    async runLookup() {
        const input = document.getElementById('inputDnsValue');
        const value = input.value.trim();
        const btn = document.getElementById('btnRunDns');
        const resultDiv = document.getElementById('dnsLookupResult');

        if (!value) return alert("Please enter a domain or IP.");

        btn.classList.add('is-loading');
        try {
            const encoded = encodeURIComponent(value);
            const res = await this.app._fetch(`/tools/dnslookup2?value=${encoded}`, { method: 'POST' });
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            resultDiv.innerHTML = `<p class="has-text-grey-light">${escapeHtml(data.info)}</p>`;
        } catch (error) {
            alert("DNS lookup failed: " + error.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }
}