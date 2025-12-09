import { escapeHtml } from './utils.js';

export class ToolsController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.selectedSet = new Set();
        this.results = null;
    }

    render() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
            <div class="box has-background-custom">
                <h2 class="title is-2 has-text-info">Tools</h2>
                
                <div class="block">
                    <h4 class="title is-4 has-text-white">IOC Extractor</h4>
                    <p class="has-text-grey-light mb-4">Upload a file to extract potential Indicators of Compromise (IOCs).</p>
                    <div class="file has-name is-fullwidth is-info mb-4">
                        <label class="file-label">
                            <input class="file-input" type="file" id="toolFileInput">
                            <span class="file-cta">
                                <span class="file-icon"><i class="material-icons">upload_file</i></span>
                                <span class="file-label">Choose a file…</span>
                            </span>
                            <span class="file-name" id="toolFileName">No file uploaded</span>
                        </label>
                    </div>
                    <button class="button is-info is-outlined is-fullwidth" id="btnExtract">
                        <span class="icon"><i class="material-icons">search</i></span>
                        <span>Extract IOCs</span>
                    </button>
                </div>

                <div id="toolSearchControls" class="is-hidden mb-4">
                    <button class="button is-info is-fullwidth" id="btnAnalyzeSelected">
                        <span class="icon"><i class="material-icons">bolt</i></span>
                        <span>Analyze Selected (<span id="toolSelectedCount">0</span>)</span>
                    </button>
                </div>
                <div id="toolResults" class="content has-text-white mt-5"></div>

                <hr class="has-background-grey-darker my-6">

                <div class="block">
                    <h4 class="title is-4 has-text-white">AES256 Encryptor</h4>
                    <p class="has-text-grey-light mb-4">Securely encrypt or decrypt data via the server.</p>

                    <div class="tabs is-toggle is-fullwidth is-small mb-4">
                        <ul>
                            <li class="is-active" id="tabModeEncrypt">
                                <a>
                                    <span class="icon is-small"><i class="material-icons">lock</i></span>
                                    <span>Encrypt</span>
                                </a>
                            </li>
                            <li id="tabModeDecrypt">
                                <a>
                                    <span class="icon is-small"><i class="material-icons">lock_open</i></span>
                                    <span>Decrypt</span>
                                </a>
                            </li>
                        </ul>
                    </div>
                    
                    <div class="tabs is-boxed is-small mb-3">
                        <ul>
                            <li class="is-active" id="tabTypeString">
                                <a>
                                    <span class="icon is-small"><i class="material-icons">text_fields</i></span>
                                    <span>String / Base64</span>
                                </a>
                            </li>
                            <li id="tabTypeFile">
                                <a>
                                    <span class="icon is-small"><i class="material-icons">insert_drive_file</i></span>
                                    <span>File</span>
                                </a>
                            </li>
                        </ul>
                    </div>

                    <div id="sectionTypeString" class="field">
                        <div class="control">
                            <textarea class="textarea has-background-dark has-text-white" id="inputCryptoString" rows="3" placeholder="Enter text to encrypt..."></textarea>
                        </div>
                    </div>

                    <div id="sectionTypeFile" class="field is-hidden">
                        <div class="file has-name is-fullwidth is-info">
                            <label class="file-label">
                                <input class="file-input" type="file" id="inputCryptoFile">
                                <span class="file-cta">
                                    <span class="file-icon"><i class="material-icons">upload_file</i></span>
                                    <span class="file-label">Choose file…</span>
                                </span>
                                <span class="file-name" id="displayCryptoFileName">No file selected</span>
                            </label>
                        </div>
                    </div>

                    <div class="field mt-4">
                        <label class="label has-text-grey-light">Password</label>
                        <div class="control has-icons-left">
                            <input class="input has-background-dark has-text-white" type="password" id="inputCryptoPassword" placeholder="Enter a strong password">
                            <span class="icon is-small is-left"><i class="material-icons">vpn_key</i></span>
                        </div>
                    </div>

                    <button class="button is-info is-fullwidth" id="btnRunCrypto">
                        <span class="icon"><i class="material-icons">play_arrow</i></span>
                        <span id="btnRunCryptoLabel">Encrypt Data</span>
                    </button>

                    <div id="cryptoResultContainer" class="message is-info mt-4 is-hidden">
                        <div class="message-header">
                            <p>Result</p>
                            <button class="delete" aria-label="delete" id="btnCloseCryptoResult"></button>
                        </div>
                        <div class="message-body has-background-black-ter">
                            <div class="field has-addons">
                                <div class="control is-expanded">
                                    <textarea class="textarea is-small has-background-black has-text-info" readonly id="outputCryptoResult" rows="3"></textarea>
                                </div>
                            </div>
                             <div class="buttons">
                                <button class="button is-small is-info is-outlined" id="btnDownloadCryptoFile">
                                    <span class="icon"><i class="material-icons">download</i></span>
                                    <span>Download File</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        this.attachListeners();
        
        if (this.results) {
             this.renderResults(this.results);
        }
    }

    attachListeners() {
        const fileInput = document.getElementById('toolFileInput');
        const fileName = document.getElementById('toolFileName');
        
        if (fileInput) {
             fileInput.addEventListener('change', () => {
                if (fileInput.files.length > 0) {
                    fileName.textContent = fileInput.files[0].name;
                }
            });
        }

        const btnExtract = document.getElementById('btnExtract');
        if (btnExtract) btnExtract.addEventListener('click', () => this.uploadAndParse());
        
        const btnAnalyze = document.getElementById('btnAnalyzeSelected');
        if (btnAnalyze) btnAnalyze.addEventListener('click', () => this.analyzeSelected());

        const tabModeEncrypt = document.getElementById('tabModeEncrypt');
        const tabModeDecrypt = document.getElementById('tabModeDecrypt');
        const btnLabel = document.getElementById('btnRunCryptoLabel');
        const stringInput = document.getElementById('inputCryptoString');

        if (tabModeEncrypt && tabModeDecrypt) {
            tabModeEncrypt.addEventListener('click', () => {
                tabModeEncrypt.classList.add('is-active');
                tabModeDecrypt.classList.remove('is-active');
                btnLabel.textContent = "Encrypt Data";
                stringInput.placeholder = "Enter text to encrypt...";
                this.updateCryptoUI();
            });

            tabModeDecrypt.addEventListener('click', () => {
                tabModeDecrypt.classList.add('is-active');
                tabModeEncrypt.classList.remove('is-active');
                btnLabel.textContent = "Decrypt Data";
                stringInput.placeholder = "Paste ciphertext (Base64) to decrypt...";
                this.updateCryptoUI();
            });
        }

        const tabTypeString = document.getElementById('tabTypeString');
        const tabTypeFile = document.getElementById('tabTypeFile');
        const sectTypeString = document.getElementById('sectionTypeString');
        const sectTypeFile = document.getElementById('sectionTypeFile');

        if (tabTypeString && tabTypeFile) {
            tabTypeString.addEventListener('click', () => {
                tabTypeString.classList.add('is-active');
                tabTypeFile.classList.remove('is-active');
                sectTypeString.classList.remove('is-hidden');
                sectTypeFile.classList.add('is-hidden');
            });

            tabTypeFile.addEventListener('click', () => {
                tabTypeFile.classList.add('is-active');
                tabTypeString.classList.remove('is-active');
                sectTypeFile.classList.remove('is-hidden');
                sectTypeString.classList.add('is-hidden');
            });
        }

        const cFileInput = document.getElementById('inputCryptoFile');
        const cFileName = document.getElementById('displayCryptoFileName');
        if (cFileInput) {
            cFileInput.addEventListener('change', () => {
                if (cFileInput.files.length > 0) cFileName.textContent = cFileInput.files[0].name;
            });
        }

        const btnRunCrypto = document.getElementById('btnRunCrypto');
        if (btnRunCrypto) btnRunCrypto.addEventListener('click', () => this.runCryptoOperation());

        const btnCloseCrypto = document.getElementById('btnCloseCryptoResult');
        if (btnCloseCrypto) btnCloseCrypto.addEventListener('click', () => {
            document.getElementById('cryptoResultContainer').classList.add('is-hidden');
        });
    }

    updateCryptoUI() {
        document.getElementById('inputCryptoString').value = "";
        document.getElementById('inputCryptoFile').value = "";
        document.getElementById('displayCryptoFileName').textContent = "No file selected";
        document.getElementById('cryptoResultContainer').classList.add('is-hidden');
    }

    async runCryptoOperation() {
        const password = document.getElementById('inputCryptoPassword').value;
        if (!password) {
            alert("Please enter a password.");
            return;
        }

        const isEncrypt = document.getElementById('tabModeEncrypt').classList.contains('is-active');
        const isFile = document.getElementById('tabTypeFile').classList.contains('is-active');
        const btn = document.getElementById('btnRunCrypto');
        
        btn.classList.add('is-loading');

        try {
            const formData = new FormData();
            formData.append('password', password);

            let mode = isEncrypt ? 'encrypt' : 'decrypt';
            let endpoint = `/tools/${mode}`;
            let filename = "result";

            if (isFile) {
                const fileInput = document.getElementById('inputCryptoFile');
                if (!fileInput.files.length) throw new Error("Please select a file.");
                formData.append('file', fileInput.files[0]);
                filename = fileInput.files[0].name;
            } else {
                const text = document.getElementById('inputCryptoString').value;
                if (!text) throw new Error("Please enter text input.");
                
                if (isEncrypt) {
                    formData.append('text', text);
                    filename = "encrypted.txt";
                } else {
                    try {
                        const binaryString = atob(text);
                        const len = binaryString.length;
                        const bytes = new Uint8Array(len);
                        for (let i = 0; i < len; i++) {
                            bytes[i] = binaryString.charCodeAt(i);
                        }
                        const blob = new Blob([bytes]);
                        formData.append('file', blob, "pasted_ciphertext.bin");
                        filename = "decrypted.txt";
                    } catch (e) {
                        throw new Error("Invalid Base64 input. Ensure you pasted the full ciphertext.");
                    }
                }
            }

            const response = await this.app._fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error(await response.text());

            const blob = await response.blob();
            const resultBuffer = await blob.arrayBuffer();
            
            const headerName = response.headers.get('X-Filename');
            if (headerName) filename = headerName;

            this.showCryptoResult(resultBuffer, filename, isEncrypt);

        } catch (error) {
            console.error(error);
            alert("Operation failed: " + error.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    showCryptoResult(buffer, filename, wasEncrypting) {
        const container = document.getElementById('cryptoResultContainer');
        const outputText = document.getElementById('outputCryptoResult');
        const downloadBtn = document.getElementById('btnDownloadCryptoFile');

        container.classList.remove('is-hidden');

        if (wasEncrypting) {
            const base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
            outputText.value = base64String;
        } else {
            try {
                const text = new TextDecoder("utf-8", {fatal: true}).decode(buffer);
                if (text.includes('\0')) throw new Error("Binary");
                outputText.value = text;
            } catch (e) {
                outputText.value = "[Binary Data Decrypted] - Download the file to view content.";
            }
        }

        const newDownloadBtn = downloadBtn.cloneNode(true);
        downloadBtn.parentNode.replaceChild(newDownloadBtn, downloadBtn);
        
        newDownloadBtn.onclick = () => {
            const blob = new Blob([buffer], { type: "application/octet-stream" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        };
    }

    async uploadAndParse() {
        const fileInput = document.getElementById('toolFileInput');
        const file = fileInput.files[0];
        if (!file) {
            alert("Please select a file first.");
            return;
        }

        const btn = document.getElementById('btnExtract');
        btn.classList.add('is-loading');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await this.app._fetch('/tools/parse', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error(await response.text());
            
            this.results = await response.json();
            this.renderResults(this.results);
        } catch (error) {
            console.error('Error:', error);
            document.getElementById('toolResults').innerHTML = `<div class="notification is-danger">${error.message}</div>`;
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    renderResults(data) {
        const container = document.getElementById('toolResults');
        container.innerHTML = '';
        this.selectedSet.clear();
        this.updateCount();

        if (!data || Object.keys(data).length === 0) {
            container.innerHTML = '<div class="notification is-warning">No IOCs found.</div>';
            return;
        }

        for (const [type, matches] of Object.entries(data)) {
            if (!matches || matches.length === 0) continue;

            const uniqueValues = [...new Set(matches.map(m => m.Value))];
            
            const box = document.createElement('div');
            box.className = "box has-background-black-bis mb-4";

            const headerLevel = document.createElement('div');
            headerLevel.className = "level is-mobile mb-2";
            
            const left = document.createElement('div');
            left.className = "level-left";
            left.innerHTML = `<div class="level-item"><h5 class="title is-5 has-text-info">${type.toUpperCase()} (${uniqueValues.length})</h5></div>`;
            
            const right = document.createElement('div');
            right.className = "level-right";
            
            const selectAllBtn = document.createElement('button');
            selectAllBtn.className = "button is-small is-text has-text-grey-light";
            selectAllBtn.textContent = "Select All";
            selectAllBtn.onclick = () => this.toggleSection(type, uniqueValues, selectAllBtn);
            
            right.appendChild(selectAllBtn);
            headerLevel.appendChild(left);
            headerLevel.appendChild(right);
            box.appendChild(headerLevel);

            const tags = document.createElement('div');
            tags.className = "tags";
            tags.id = `tags-${type}`;

            uniqueValues.forEach(value => {
                const tag = document.createElement('span');
                tag.className = "tag is-dark is-medium";
                tag.style.cursor = "pointer";
                tag.style.transition = "all 0.2s";
                tag.textContent = value;
                tag.dataset.value = value;
                tag.onclick = () => this.toggleTag(tag, value);
                tags.appendChild(tag);
            });

            box.appendChild(tags);
            container.appendChild(box);
        }
    }

    toggleSection(type, values, btn) {
        const parent = document.getElementById(`tags-${type}`);
        const allTags = parent.querySelectorAll('.tag');
        const allSelected = Array.from(allTags).every(t => t.classList.contains('is-info'));
        
        if (allSelected) {
            values.forEach(v => this.selectedSet.delete(v));
            allTags.forEach(t => {
                t.classList.remove('is-info');
                t.classList.add('is-dark');
            });
            btn.textContent = "Select All";
        } else {
            values.forEach(v => this.selectedSet.add(v));
            allTags.forEach(t => {
                t.classList.remove('is-dark');
                t.classList.add('is-info');
            });
            btn.textContent = "Deselect All";
        }
        this.updateCount();
    }

    toggleTag(element, value) {
        if (this.selectedSet.has(value)) {
            this.selectedSet.delete(value);
            element.classList.remove('is-info');
            element.classList.add('is-dark');
        } else {
            this.selectedSet.add(value);
            element.classList.remove('is-dark');
            element.classList.add('is-info');
        }
        this.updateCount();
    }

    updateCount() {
        const count = this.selectedSet.size;
        document.getElementById('toolSelectedCount').textContent = count;
        const controls = document.getElementById('toolSearchControls');
        if (count > 0) controls.classList.remove('is-hidden');
        else controls.classList.add('is-hidden');
    }

    async analyzeSelected() {
        if (this.selectedSet.size === 0) return;
        const btn = document.getElementById('btnAnalyzeSelected');
        btn.classList.add('is-loading');
        const blob = Array.from(this.selectedSet).join('\n');
        
        try {
            const results = await this.app.fetchMatchDontParse(blob);
            this.renderAnalysisResults(results);
        } catch (error) {
            console.error(error);
            alert("Analysis failed: " + error.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    renderAnalysisResults(resultsArray) {
        this.container.innerHTML = "";
        
        if (!resultsArray || resultsArray.length === 0) {
            this.container.innerHTML = '<div class="notification is-warning">No results found from analysis.</div>';
            this.addBackButton();
            return;
        }

        resultsArray.sort((a, b) => (b.matched || 0) - (a.matched || 0));

        const header = document.createElement('h2');
        header.className = "title is-3 has-text-info mb-5";
        header.textContent = "Analysis Results";
        this.container.appendChild(header);

        for (const result of resultsArray) {
            const article = document.createElement('article');
            article.className = 'message is-dark';
            const msgHeader = document.createElement('div');
            msgHeader.className = 'message-header';
            if (typeof result.background === 'string') msgHeader.classList.add(escapeHtml(result.background));
            msgHeader.innerHTML = `<p>${escapeHtml(result.from)}</p>`;
            
            const body = document.createElement('div');
            body.className = 'message-body has-background-dark-ter';
            body.innerHTML = `
                <p class="has-text-white">Match: <span class="has-text-white">${escapeHtml(String(result.value))}</span></p>
                <p class="has-text-white">Matched: <span class="has-text-white">${escapeHtml(String(result.matched))}</span></p>
                <p class="has-text-white">ID: <span class="has-text-white">${escapeHtml(String(result.id))}</span></p>
                <p class="has-text-white">Server ID: <span class="has-text-white">${escapeHtml(String(result.link))}</span></p>
                <p class="has-text-white">Info: <span class="has-text-white">${escapeHtml(String(result.info))}</span></p>
                <p class="has-text-white">Score: <span class="has-text-white">${escapeHtml(String(result.threat_level_id))}</span></p>
                <p class="has-text-white">Attrs: <span class="has-text-white">${escapeHtml(String(result.attr_count))}</span></p>
            `;

            const footer = document.createElement('footer');
            footer.className = 'card-footer';
            
            const historyButton = document.createElement('a');
            historyButton.href = '#';
            historyButton.className = 'card-footer-item has-background-black has-text-info';
            historyButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">history</i></span><span>Past Searches</span></span>`;
            historyButton.addEventListener('click', async (e) => {
                e.preventDefault();
                const pastSearches = await this.app.fetchPastSearches(result.value);
                alert(`Found ${pastSearches.length} past searches. See console.`);
                console.log(pastSearches);
            });

            const viewButton = document.createElement('a');
            viewButton.href = '#';
            viewButton.className = 'card-footer-item has-background-black has-text-info';
            viewButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">visibility</i></span><span>View Details</span></span>`;
            
            if (!result.link || result.link === "none") viewButton.classList.add('is-disabled');
            viewButton.addEventListener('click', async (e) => {
                e.preventDefault();
                if (!result.link || result.link === "none") return;
                const customEvent = new CustomEvent('req-open-details', { detail: result.link });
                document.dispatchEvent(customEvent);
            });

            footer.appendChild(historyButton);
            footer.appendChild(viewButton);
            article.appendChild(msgHeader);
            article.appendChild(body);
            article.appendChild(footer);
            this.container.appendChild(article);
        }

        this.addBackButton();
    }

    addBackButton() {
         const footer = document.createElement('div');
         footer.className = "mt-5 mb-5";
         const btn = document.createElement('button');
         btn.className = "button is-medium is-dark is-fullwidth";
         btn.innerHTML = `<span class="icon"><i class="material-icons">arrow_back</i></span><span>Back to Extractor</span>`;
         btn.onclick = () => this.render();
         footer.appendChild(btn);
         this.container.appendChild(footer);
    }
}