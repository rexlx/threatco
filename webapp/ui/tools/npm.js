import { escapeHtml } from '../utils.js';

export class NpmTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-npm" class="block">
            <h4 class="title is-4 has-text-white">NPM Security Auditor</h4>
            <p class="has-text-grey-light mb-4">Upload <code>package.json</code> files to audit for malicious dependencies.</p>
            
            <div class="file has-name is-fullwidth is-info mb-4">
                <label class="file-label">
                    <input class="file-input" type="file" id="npmFilesInput" multiple>
                    <span class="file-cta">
                        <span class="file-icon"><i class="material-icons">inventory_2</i></span>
                        <span class="file-label">Choose package.json files…</span>
                    </span>
                    <span class="file-name" id="npmFileName">No files selected</span>
                </label>
            </div>
            
            <button class="button is-info is-outlined is-fullwidth" id="btnCheckNpm">
                <span class="icon"><i class="material-icons">security</i></span><span>Run Audit</span>
            </button>
            
            <div id="npmResults" class="content mt-5"></div>
        </div>`;
    }

    attachListeners() {
        const input = document.getElementById('npmFilesInput');
        const nameLabel = document.getElementById('npmFileName');
        const btn = document.getElementById('btnCheckNpm');

        if (input) {
            input.onchange = () => {
                const count = input.files.length;
                nameLabel.textContent = count > 0 ? `${count} file(s) selected` : 'No files selected';
            };
        }

        if (btn) btn.onclick = () => this.performCheck();
    }

    async performCheck() {
        const input = document.getElementById('npmFilesInput');
        if (!input.files.length) return alert("Please select at least one file.");

        const btn = document.getElementById('btnCheckNpm');
        btn.classList.add('is-loading');

        try {
            const formData = new FormData();
            for (let file of input.files) {
                formData.append('files', file);
            }

            const res = await this.app._fetch('/tools/npm-check', {
                method: 'POST',
                body: formData
            });

            if (!res.ok) throw new Error(await res.text());
            const results = await res.json();
            this.renderResults(results);
        } catch (e) {
            document.getElementById('npmResults').innerHTML = `<div class="notification is-danger">${e.message}</div>`;
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    renderResults(data) {
        const container = document.getElementById('npmResults');
        container.innerHTML = '';

        data.forEach(res => {
            const box = document.createElement('div');
            box.className = "box has-background-black-bis mb-4";

            // FIX: Change res.FileName to res.file_name
            let content = `<h5 class="title is-5 has-text-info">${escapeHtml(res.file_name)}</h5>`;

            if (res.error) { // FIX: Change res.Error to res.error
                content += `<p class="has-text-danger">Error: ${escapeHtml(res.error)}</p>`;
            } else if (!res.matches || res.matches.length === 0) { // FIX: Change res.Matches to res.matches
                content += `<p class="has-text-success"><span class="icon"><i class="material-icons">check_circle</i></span> Clean: No known malicious packages found.</p>`;
            } else {
                res.matches.forEach(match => { // FIX: Change res.matches
                    const severityClass = match.severity === 'critical' ? 'is-danger' : 'is-warning';
                    content += `
                <div class="notification ${severityClass} is-light mb-2" style="border-left: 5px solid">
                    <div class="level is-mobile mb-1">
                        <div class="level-left">
                            <strong>${escapeHtml(match.name)}</strong>
                        </div>
                        <div class="level-right">
                            <span class="tag is-black is-uppercase">${escapeHtml(match.type)}</span>
                        </div>
                    </div>
                    <p class="is-size-7"><strong>[${escapeHtml(match.severity.toUpperCase())}]</strong> ${escapeHtml(match.description)}</p>
                </div>`;
                });
            }

            box.innerHTML = content;
            container.appendChild(box);
        });
    }
}