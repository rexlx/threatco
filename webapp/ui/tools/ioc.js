import { escapeHtml } from '../utils.js';

export class IocTool {
    constructor(app) {
        this.app = app;
        this.selectedSet = new Set();
        this.results = null;
    }

    render() {
        return `
        <div id="tool-ioc" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">IOC Extractor</h4>
            <p class="has-text-grey-light mb-4">Upload a file to extract potential Indicators of Compromise (IOCs).</p>
            <div class="file has-name is-fullwidth is-info mb-4">
                <label class="file-label">
                    <input class="file-input" type="file" id="toolFileInput">
                    <span class="file-cta"><span class="file-icon"><i class="material-icons">upload_file</i></span><span class="file-label">Choose a file…</span></span>
                    <span class="file-name" id="toolFileName">No file uploaded</span>
                </label>
            </div>
            <button class="button is-info is-outlined is-fullwidth" id="btnExtract">
                <span class="icon"><i class="material-icons">search</i></span><span>Extract IOCs</span>
            </button>
            <div id="toolSearchControls" class="is-hidden mb-4 mt-4">
                <button class="button is-info is-fullwidth" id="btnAnalyzeSelected">
                    <span class="icon"><i class="material-icons">bolt</i></span><span>Analyze Selected (<span id="toolSelectedCount">0</span>)</span>
                </button>
            </div>
            <div id="toolResults" class="content has-text-white mt-5"></div>
        </div>`;
    }

    attachListeners(renderRootCallback) {
        this.renderRoot = renderRootCallback; // Callback to re-render main tools view if needed (back button)
        
        const fileInput = document.getElementById('toolFileInput');
        if (fileInput) fileInput.onchange = () => { if (fileInput.files.length) document.getElementById('toolFileName').textContent = fileInput.files[0].name; };
        
        const btnExtract = document.getElementById('btnExtract');
        if (btnExtract) btnExtract.onclick = () => this.uploadAndParse();

        const btnAnalyze = document.getElementById('btnAnalyzeSelected');
        if (btnAnalyze) btnAnalyze.onclick = () => this.analyzeSelected();
    }

    async uploadAndParse() {
        const f = document.getElementById('toolFileInput').files[0];
        if (!f) return alert("Select file.");
        
        const btn = document.getElementById('btnExtract');
        btn.classList.add('is-loading');
        
        try {
            const formData = new FormData();
            formData.append('file', f);
            const res = await this.app._fetch('/tools/parse', { method: 'POST', body: formData });
            if (!res.ok) throw new Error(await res.text());
            
            this.results = await res.json();
            this.renderResults(this.results);
        } catch (e) {
            document.getElementById('toolResults').innerHTML = `<div class="notification is-danger">${e.message}</div>`;
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    renderResults(data) {
        const container = document.getElementById('toolResults');
        container.innerHTML = '';
        this.selectedSet.clear();
        this.updateCount();

        if (!data || !Object.keys(data).length) return container.innerHTML = '<div class="notification is-warning">No IOCs found.</div>';

        for (const [type, matches] of Object.entries(data)) {
            if (!matches || !matches.length) continue;
            const unique = [...new Set(matches.map(m => m.Value))];
            
            const box = document.createElement('div');
            box.className = "box has-background-black-bis mb-4";
            
            // Header with Select All
            const header = document.createElement('div');
            header.className = "level is-mobile mb-2";
            header.innerHTML = `
                <div class="level-left"><div class="level-item"><h5 class="title is-5 has-text-info">${type.toUpperCase()} (${unique.length})</h5></div></div>
                <div class="level-right"><button class="button is-small is-text has-text-grey-light action-select-all">Select All</button></div>`;
            
            header.querySelector('.action-select-all').onclick = (e) => this.toggleSection(type, unique, e.target);
            box.appendChild(header);

            // Tags
            const tags = document.createElement('div');
            tags.className = "tags";
            tags.id = `tags-${type}`;
            unique.forEach(val => {
                const tag = document.createElement('span');
                tag.className = "tag is-dark is-medium";
                tag.style.cursor = "pointer";
                tag.textContent = val;
                tag.onclick = () => {
                    this.selectedSet.has(val) ? (this.selectedSet.delete(val), tag.classList.remove('is-info'), tag.classList.add('is-dark')) : (this.selectedSet.add(val), tag.classList.remove('is-dark'), tag.classList.add('is-info'));
                    this.updateCount();
                };
                tags.appendChild(tag);
            });
            box.appendChild(tags);
            container.appendChild(box);
        }
    }

    toggleSection(type, values, btn) {
        const parent = document.getElementById(`tags-${type}`);
        const tags = parent.querySelectorAll('.tag');
        const allSelected = Array.from(tags).every(t => t.classList.contains('is-info'));

        if (allSelected) {
            values.forEach(v => this.selectedSet.delete(v));
            tags.forEach(t => { t.classList.remove('is-info'); t.classList.add('is-dark'); });
            btn.textContent = "Select All";
        } else {
            values.forEach(v => this.selectedSet.add(v));
            tags.forEach(t => { t.classList.remove('is-dark'); t.classList.add('is-info'); });
            btn.textContent = "Deselect All";
        }
        this.updateCount();
    }

    updateCount() {
        const count = this.selectedSet.size;
        document.getElementById('toolSelectedCount').textContent = count;
        document.getElementById('toolSearchControls').classList.toggle('is-hidden', count === 0);
    }

    async analyzeSelected() {
        if (!this.selectedSet.size) return;
        const btn = document.getElementById('btnAnalyzeSelected');
        btn.classList.add('is-loading');
        try {
            const blob = Array.from(this.selectedSet).join('\n');
            const results = await this.app.fetchMatchDontParse(blob);
            this.renderAnalysis(results);
        } catch (e) {
            alert("Analysis failed: " + e.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    renderAnalysis(results) {
        const container = document.getElementById('toolResults');
        container.innerHTML = `<h2 class="title is-3 has-text-info mb-5">Analysis Results</h2>`;
        
        if (!results || !results.length) {
            container.innerHTML += '<div class="notification is-warning">No results found.</div>';
        } else {
            results.sort((a, b) => (b.matched || 0) - (a.matched || 0));
            results.forEach(r => {
                const article = document.createElement('article');
                article.className = 'message is-dark mb-4';
                article.innerHTML = `
                    <div class="message-header ${escapeHtml(r.background || '')}"><p>${escapeHtml(r.from)}</p></div>
                    <div class="message-body has-background-dark-ter">
                        <p class="has-text-white">Match: ${escapeHtml(String(r.value))}</p>
                        <p class="has-text-white">Info: ${escapeHtml(String(r.info))}</p>
                    </div>`;
                
                // Add simple View Details button if link exists
                if (r.link && r.link !== "none") {
                    const footer = document.createElement('footer');
                    footer.className = 'card-footer';
                    const btn = document.createElement('a');
                    btn.className = 'card-footer-item has-background-black has-text-info';
                    btn.textContent = 'View Details';
                    btn.onclick = (e) => {
                        e.preventDefault();
                        document.dispatchEvent(new CustomEvent('req-open-details', { detail: r.link }));
                    };
                    footer.appendChild(btn);
                    article.appendChild(footer);
                }
                container.appendChild(article);
            });
        }

        const backBtn = document.createElement('button');
        backBtn.className = "button is-medium is-dark is-fullwidth mt-5";
        backBtn.innerHTML = `<span class="icon"><i class="material-icons">arrow_back</i></span><span>Back</span>`;
        backBtn.onclick = () => {
             // Reset UI
             const toolIoc = document.getElementById('tool-ioc');
             // We can just re-render the results if we kept them, or empty it. 
             // Simplest is to clear the analysis view and show the tags again.
             if (this.results) this.renderResults(this.results); 
        };
        container.appendChild(backBtn);
    }
}