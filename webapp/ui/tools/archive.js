import { escapeHtml } from '../utils.js';

export class ArchiveTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-archive" class="block">
            <h4 class="title is-4 has-text-white">Archive Inspector</h4>
            <p class="has-text-grey-light mb-4">
                Safely inspect ZIP contents. Large files (up to 500MB) are streamed to a temporary sandbox, 
                analyzed for threats (Zip Slips, Bombs), and immediately deleted.
            </p>
            
            <div class="file has-name is-fullwidth is-info mb-4">
                <label class="file-label">
                    <input class="file-input" type="file" id="toolArchiveInput" accept=".zip">
                    <span class="file-cta"><span class="file-icon"><i class="material-icons">folder_zip</i></span><span class="file-label">Choose a ZIP file…</span></span>
                    <span class="file-name" id="toolArchiveName">No file uploaded</span>
                </label>
            </div>
            
            <button class="button is-info is-outlined is-fullwidth" id="btnInspectArchive">
                <span class="icon"><i class="material-icons">security</i></span><span>Secure Inspect</span>
            </button>

            <div id="toolArchiveResults" class="content has-text-white mt-5"></div>
        </div>`;
    }

    attachListeners() {
        const fileInput = document.getElementById('toolArchiveInput');
        if (fileInput) fileInput.onchange = () => { 
            if (fileInput.files.length) document.getElementById('toolArchiveName').textContent = fileInput.files[0].name; 
        };
        
        const btn = document.getElementById('btnInspectArchive');
        if (btn) btn.onclick = () => this.uploadAndInspect();
    }

    async uploadAndInspect() {
        const f = document.getElementById('toolArchiveInput').files[0];
        if (!f) return alert("Select a file.");
        
        const btn = document.getElementById('btnInspectArchive');
        btn.classList.add('is-loading');
        const container = document.getElementById('toolArchiveResults');
        container.innerHTML = '';

        try {
            const formData = new FormData();
            formData.append('file', f);
            
            const res = await this.app._fetch('/tools/inspect-archive', { method: 'POST', body: formData });
            if (!res.ok) throw new Error(await res.text());
            
            const data = await res.json();
            this.renderResults(data);
        } catch (e) {
            container.innerHTML = `<div class="notification is-danger">${escapeHtml(e.message)}</div>`;
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    renderResults(files) {
        const container = document.getElementById('toolArchiveResults');
        if (!files || files.length === 0) {
            container.innerHTML = '<div class="notification is-warning">Archive is empty or invalid.</div>';
            return;
        }

        // Sort: Suspicious first
        files.sort((a, b) => (b.suspicious === true) - (a.suspicious === true));

        let rows = files.map(f => {
            let rowClass = "";
            let icon = "";
            let shaDisplay = f.sha256;

            if (f.suspicious) {
                rowClass = "has-background-danger-dark";
                icon = `<span class="icon has-text-warning" title="${escapeHtml(f.warning)}"><i class="material-icons">warning</i></span>`;
                shaDisplay = `<span class="has-text-warning">${escapeHtml(f.warning)}</span>`;
            }

            return `
            <tr class="${rowClass}">
                <td style="word-break: break-all; font-family: monospace;">
                    ${icon} ${escapeHtml(f.name)}
                </td>
                <td class="has-text-right">${this.formatBytes(f.size)}</td>
                <td style="font-family: monospace; font-size: 0.85em;">${shaDisplay || f.sha256}</td>
            </tr>
            `;
        }).join('');

        container.innerHTML = `
            <div class="table-container">
                <table class="table is-fullwidth is-striped is-hoverable has-background-dark has-text-light">
                    <thead>
                        <tr>
                            <th class="has-text-white">Filename</th>
                            <th class="has-text-white has-text-right">Size</th>
                            <th class="has-text-white">SHA-256 / Risk</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    }

    formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }
}