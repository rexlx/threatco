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
                <h2 class="title is-2 has-text-primary">Tools</h2>
                <div class="block">
                    <h4 class="title is-4 has-text-info">IOC Extractor</h4>
                    <p class="has-text-white mb-4">Upload a file to extract potential Indicators of Compromise (IOCs). Select tags to analyze them.</p>
                    <div class="file has-name is-fullwidth is-primary mb-4">
                        <label class="file-label">
                            <input class="file-input" type="file" id="toolFileInput">
                            <span class="file-cta">
                                <span class="file-icon"><i class="material-icons">upload_file</i></span>
                                <span class="file-label">Choose a file…</span>
                            </span>
                            <span class="file-name" id="toolFileName">No file uploaded</span>
                        </label>
                    </div>
                    <button class="button is-primary is-outlined is-fullwidth" id="btnExtract">
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
            </div>
        `;
        this.attachListeners();
    }

    attachListeners() {
        const fileInput = document.getElementById('toolFileInput');
        const fileName = document.getElementById('toolFileName');
        
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                fileName.textContent = fileInput.files[0].name;
            }
        });

        document.getElementById('btnExtract').addEventListener('click', () => this.uploadAndParse());
        document.getElementById('btnAnalyzeSelected').addEventListener('click', () => this.analyzeSelected());
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
            await this.app.fetchMatchDontParse(blob);
            const event = new CustomEvent('req-show-responses');
            document.dispatchEvent(event);
        } catch (error) {
            console.error(error);
            alert("Analysis failed: " + error.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }
}