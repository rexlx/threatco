import { escapeHtml } from '../utils.js';

export class NpmTool {
    constructor(app) {
        this.app = app;
        this.activeMode = 'upload'; // Fixed: Tracks active view state cleanly
    }

    render() {
        return `
        <div id="tool-npm" class="block">
            <h4 class="title is-4 has-text-white">Repository Security Auditor (OSV)</h4>
            <p class="has-text-grey-light mb-4">Scan your ecosystem manifests (npm, Go, Cargo, pip) by uploading files or providing a public Git repository URL.</p>
            
            <div class="tabs is-boxed is-small mb-4">
                <ul>
                    <li id="tab-npm-upload" class="is-active">
                        <a>
                            <span class="icon is-small"><i class="material-icons">upload_file</i></span>
                            <span>File Upload</span>
                        </a>
                    </li>
                    <li id="tab-npm-git">
                        <a>
                            <span class="icon is-small"><i class="material-icons">hub</i></span>
                            <span>Git Repository</span>
                        </a>
                    </li>
                </ul>
            </div>

            <div id="npm-input-container">
                <div id="block-npm-upload" class="field">
                    <div class="file has-name is-fullwidth is-info mb-4">
                        <label class="file-label">
                            <input class="file-input" type="file" id="npmFilesInput" multiple>
                            <span class="file-cta">
                                <span class="file-icon"><i class="material-icons">inventory_2</i></span>
                                <span class="file-label">Choose manifest / lockfiles…</span>
                            </span>
                            <span class="file-name" id="npmFileName">No files selected</span>
                        </label>
                    </div>
                </div>

                <div id="block-npm-git" class="field is-hidden">
                    <div class="control has-icons-left mb-4">
                        <input class="input is-info has-background-black-ter has-text-white" type="url" id="npmGitUrlInput" placeholder="https://github.com/username/repository">
                        <span class="icon is-left">
                            <i class="material-icons">link</i>
                        </span>
                    </div>
                </div>
            </div>
            
            <button class="button is-info is-outlined is-fullwidth" id="btnCheckNpm">
                <span class="icon"><i class="material-icons">security</i></span><span id="btnCheckNpmText">Run File Audit</span>
            </button>
            
            <div id="npmResults" class="content mt-5"></div>
        </div>`;
    }

    attachListeners() {
        const input = document.getElementById('npmFilesInput');
        const nameLabel = document.getElementById('npmFileName');
        const btn = document.getElementById('btnCheckNpm');
        
        const tabUpload = document.getElementById('tab-npm-upload');
        const tabGit = document.getElementById('tab-npm-git');
        const blockUpload = document.getElementById('block-npm-upload');
        const blockGit = document.getElementById('block-npm-git');
        const btnText = document.getElementById('btnCheckNpmText');

        // Tab Switching Logic
        if (tabUpload && tabGit) {
            tabUpload.onclick = () => {
                this.activeMode = 'upload';
                tabUpload.classList.add('is-active');
                tabGit.classList.remove('is-active');
                blockUpload.classList.remove('is-hidden');
                blockGit.classList.add('is-hidden');
                btnText.textContent = 'Run File Audit';
            };

            tabGit.onclick = () => {
                this.activeMode = 'git';
                tabGit.classList.add('is-active');
                tabUpload.classList.remove('is-active');
                blockGit.classList.remove('is-hidden');
                blockUpload.classList.add('is-hidden');
                btnText.textContent = 'Clone & Scan Repository';
            };
        }

        if (input && nameLabel) {
            input.onchange = () => {
                const count = input.files.length;
                nameLabel.textContent = count > 0 ? `${count} file(s) selected` : 'No files selected';
            };
        }

        if (btn) btn.onclick = () => this.performCheck();
    }

    async performCheck() {
        const btn = document.getElementById('btnCheckNpm');
        let fetchOptions = {};

        if (this.activeMode === 'upload') {
            const fileInput = document.getElementById('npmFilesInput');
            if (!fileInput.files.length) return alert("Please select at least one package manifest file to upload.");

            const formData = new FormData();
            for (let file of fileInput.files) {
                formData.append('files', file);
            }

            fetchOptions = {
                method: 'POST',
                body: formData
            };
        } else {
            const urlInput = document.getElementById('npmGitUrlInput');
            const repoUrl = urlInput.value.trim();
            if (!repoUrl) return alert("Please specify a public HTTP/HTTPS repository address.");

            fetchOptions = {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: repoUrl })
            };
        }

        btn.classList.add('is-loading');

        try {
            const res = await this.app._fetch('/tools/npm-check', fetchOptions);

            if (!res.ok) throw new Error(await res.text());
            const results = await res.json();
            this.renderResults(results);
        } catch (e) {
            // Fixed XSS vulnerability by escaping error messages
            document.getElementById('npmResults').innerHTML = `<div class="notification is-danger">${escapeHtml(e.message)}</div>`;
        } finally {
            // Fixed syntax issue: replaced broken 'platform' keyword with 'finally'
            btn.classList.remove('is-loading');
        }
    }

    renderResults(data) {
        const container = document.getElementById('npmResults');
        container.innerHTML = '';

        if (!data || data.length === 0) {
            container.innerHTML = `<div class="notification is-success">No scan results returned. Workspace dependencies are clean.</div>`;
            return;
        }

        data.forEach(res => {
            const box = document.createElement('div');
            box.className = "box has-background-black-bis mb-4";

            let content = `<h5 class="title is-5 has-text-info mb-3">
                <span class="icon-text">
                    <span class="icon"><i class="material-icons">source</i></span>
                    <span>${escapeHtml(res.file_name)}</span>
                </span>
            </h5>`;

            if (res.error) { 
                content += `<p class="has-text-danger">Error processing target: ${escapeHtml(res.error)}</p>`;
            } else if (!res.matches || res.matches.length === 0) { 
                content += `<p class="has-text-success mb-0"><span class="icon"><i class="material-icons">check_circle</i></span> Clean: No known vulnerabilities caught by OSV tracker.</p>`;
            } else {
                res.matches.forEach(match => { 
                    const displayType = match.type ? match.type.toUpperCase() : 'UNKNOWN';
                    const severityKey = (match.severity || 'warning').toLowerCase();
                    
                    // Style Mapper: Configure box-bounding borders to map metrics natively
                    let bulmaAlertClass = 'is-warning';
                    let inlineBorderStyle = 'border: 1px solid #ffdd57;'; // Warning yellow
                    
                    if (severityKey === 'critical') {
                        bulmaAlertClass = 'is-danger';
                        inlineBorderStyle = 'border: 2px solid #b10dc9; background-color: rgba(177, 13, 201, 0.05) !important;'; // Deep Purple Border for Criticals
                    } else if (severityKey === 'high') {
                        bulmaAlertClass = 'is-danger';
                        inlineBorderStyle = 'border: 1px solid #f14668;'; // Danger red
                    } else if (severityKey === 'info') {
                        bulmaAlertClass = 'is-info';
                        inlineBorderStyle = 'border: 1px solid #3e8ed0;'; // Info blue
                    }
                    
                    content += `
                <div class="notification ${bulmaAlertClass} is-light mb-2" style="${inlineBorderStyle} padding: 0.75rem 1.25rem; border-left: none;">
                    <div class="level is-mobile mb-1">
                        <div class="level-left">
                            <strong>${escapeHtml(match.name)}</strong>
                        </div>
                        <div class="level-right">
                            <span class="tag is-black">${escapeHtml(displayType)}</span>
                        </div>
                    </div>
                    <p class="is-size-7 mb-0">
                        <span class="tag is-dark is-uppercase mr-2" style="font-weight: bold; font-size: 0.65rem; letter-spacing: 0.5px;">
                            ${escapeHtml(severityKey)}
                        </span> 
                        ${escapeHtml(match.description)}
                    </p>
                </div>`;
                });
            }

            box.innerHTML = content;
            container.appendChild(box);
        });
    }
}