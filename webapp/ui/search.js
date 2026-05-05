import { escapeHtml, makeUnique, isPrivateIP } from './utils.js';

export class SearchController {
    constructor(containerId, app, contextualizer) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.contextualizer = contextualizer;
        this.isSearching = false;
        this.extractedMatches = []; 
        this.currentQueue = [];
        this.activeTab = 'search';
        this.attachFormListeners();
    }

    async renderForm() {
        this.container.classList.remove('is-hidden'); 

        let stats = {
            open_cases: 0,
            active_responses: 0,
            archived_responses: 0,
            total_users: 0,
            server_metrics: { vendor_responses: 0 }
        };

        try {
            const resp = await fetch('/dashboard/stats'); 
            if (resp.ok) stats = await resp.json();
        } catch (e) {
            console.error("Failed to load dashboard stats", e);
        }

        this.container.innerHTML = `
        <h1 class="title has-text-info">Overview</h1>
        
        <div class="columns is-multiline is-mobile mb-6">
            ${this._renderStatBox("Open Cases", stats.open_cases, "warning")}
            ${this._renderStatBox("Responses", stats.active_responses, "info")}
            ${this._renderStatBox("Archived", stats.archived_responses, "grey")}
            ${this._renderStatBox("Users", stats.total_users, "success")}
            ${this._renderStatBox("Proxied", stats.server_metrics?.vendor_responses || 0, "white")}
        </div>

        <div class="tabs is-boxed mt-6">
            <ul>
                <li class="${this.activeTab === 'search' ? 'is-active' : ''}">
                    <a id="searchTabBtn">
                        <span class="icon is-small"><i class="material-icons">search</i></span>
                        <span>Search</span>
                    </a>
                </li>
                <li class="${this.activeTab === 'fetch' ? 'is-active' : ''}">
                    <a id="fetchTabBtn">
                        <span class="icon is-small"><i class="material-icons">cloud_download</i></span>
                        <span>Fetch URL</span>
                    </a>
                </li>
                <li class="${this.activeTab === 'failed' ? 'is-active' : ''}">
                    <a id="failedTabBtn">
                        <span class="icon is-small"><i class="material-icons">report_problem</i></span>
                        <span>Failed</span>
                    </a>
                </li>
            </ul>
        </div>
        <div id="tabContent"></div>`;

        // Render the content for the active tab
        if (this.activeTab === 'search') {
            this.renderSearchTab();
            // If matches are staged for review, render the selection grid
            if (this.extractedMatches.length > 0) this.renderMatchSelection();
        } else if (this.activeTab === 'fetch') {
            this.renderFetchTab();
        } else {
            this.renderFailedTab();
        }
    }

    _renderStatBox(label, value, colorClass) {
        return `
            <div class="column is-one-fifth-tablet is-half-mobile">
                <div class="box has-background-black has-text-centered" style="border: 1px solid #333; height: 100%;">
                    <p class="heading has-text-grey-light">${label}</p>
                    <p class="title is-4 has-text-${colorClass}">${value}</p>
                </div>
            </div>`;
    }

    renderSearchTab() {
        const content = document.getElementById('tabContent');
        content.innerHTML = `
        <h2 class="subtitle has-text-info mt-4">New Search</h2>
        <form>
            <div class="field"><div class="control"><textarea class="textarea" placeholder="Paste text or IOCs here..." id="userSearch"></textarea></div></div>
            <div class="field"><div class="control">
                <label class="checkbox has-text-grey-light"><input type="checkbox" id="dontParseCheckbox"> parse on server</label>
                <label class="checkbox has-text-grey-light ml-4"><input type="checkbox" id="viewQueueCheckbox"> preview matches</label>
            </div></div>
            <div class="field"><div class="control">
                <button class="button is-info is-outlined" id="searchButton" type="submit">
                    <span class="icon-text"><span class="icon"><i class="material-icons">search</i></span><span>Find IOCs</span></span>
                </button>
                <button class="button is-success is-outlined is-hidden" id="executeQueueButton" type="button">
                    <span class="icon-text"><span class="icon"><i class="material-icons">bolt</i></span><span>Analyze Selected (<span id="queueCount">0</span>)</span></span>
                </button>
            </div></div>
            
            <div id="iocSelectionArea" class="mt-4"></div>

            <div class="field"><div class="control"><div class="buttons are-small">
                <button type="button" class="button is-black has-text-info-light" id="historyButton"><span class="icon-text"><span class="icon"><i class="material-icons">history</i></span><span>history</span></span></button>
                <button type="button" class="button is-black has-text-info-light" id="goToButton"><span class="icon-text"><span class="icon"><i class="material-icons">double_arrow</i></span><span>go to</span></span></button>
                <button type="button" class="button is-black has-text-info-light" id="uploadButton"><span class="icon-text"><span class="icon"><i class="material-icons">upload_file</i></span><span>upload</span></span></button>
            </div></div></div>
        </form>`;
    }

    renderFetchTab() {
        const content = document.getElementById('tabContent');
        content.innerHTML = `
        <h2 class="subtitle has-text-info mt-4">Fetch and Extract URL</h2>
        <p class="has-text-grey-light mb-4">Input a URL to extract IOCs for manual review.</p>
        <form id="fetchUrlForm">
            <div class="field">
                <div class="control has-icons-left">
                    <input class="input" type="url" id="userUrlSearch" placeholder="https://example.com/threat-report" required>
                    <span class="icon is-small is-left"><i class="material-icons">link</i></span>
                </div>
            </div>
            <div class="field">
                <div class="control">
                    <button class="button is-info is-outlined" id="fetchSearchButton" type="submit">
                        <span class="icon-text"><span class="icon"><i class="material-icons">cloud_download</i></span><span>Fetch & Review</span></span>
                    </button>
                </div>
            </div>
        </form>`;
    }

    /**
     * Renders the Opt-In selection grid. Items are dark by default.
     * Click a tag to turn it blue and add it to the execution queue.
     */
    renderMatchSelection() {
        const area = document.getElementById('iocSelectionArea');
        const execBtn = document.getElementById('executeQueueButton');
        if (!area || !execBtn) return;

        area.innerHTML = `<h3 class="subtitle is-5 has-text-info">Found Indicators (Click to select)</h3>`;
        
        this.extractedMatches.forEach(group => {
            const box = document.createElement('div');
            box.className = "box has-background-black-bis mb-3";
            box.innerHTML = `<h6 class="title is-6 has-text-grey-light mb-2">${group.type.toUpperCase()}</h6>`;
            
            const tagsDiv = document.createElement('div');
            tagsDiv.className = "field is-grouped is-grouped-multiline";
            
            group.matches.forEach(val => {
                const tag = document.createElement('span');
                const isSelected = this.currentQueue.some(q => q.value === val && q.type === group.type);
                
                tag.className = `tag is-medium ${isSelected ? 'is-info' : 'is-dark'}`;
                tag.style.cursor = "pointer";
                tag.textContent = val;
                
                tag.onclick = () => {
                    if (tag.classList.contains('is-dark')) {
                        tag.classList.replace('is-dark', 'is-info');
                        this.currentQueue.push({ value: val, type: group.type });
                    } else {
                        tag.classList.replace('is-info', 'is-dark');
                        this.currentQueue = this.currentQueue.filter(q => !(q.value === val && q.type === group.type));
                    }
                    this.updateQueueCount();
                };
                tagsDiv.appendChild(tag);
            });
            box.appendChild(tagsDiv);
            area.appendChild(box);
        });
        this.updateQueueCount();
    }

    updateQueueCount() {
        const count = this.currentQueue.length;
        const btn = document.getElementById('executeQueueButton');
        const countSpan = document.getElementById('queueCount');
        if (btn) btn.classList.toggle('is-hidden', count === 0);
        if (countSpan) countSpan.textContent = count;
    }

    async renderFailedTab() {
        const content = document.getElementById('tabContent');
        content.innerHTML = '<p class="has-text-grey-light">Loading failed requests...</p><progress class="progress is-small is-info" max="100"></progress>';

        try {
            const resp = await fetch('/failed-requests');
            const requests = await resp.json();

            if (!requests || requests.length === 0) {
                content.innerHTML = '<h2 class="subtitle has-text-info mt-4">Failed Requests</h2><p class="has-text-white">No failed requests found.</p>';
                return;
            }

            let html = `
                <h2 class="subtitle has-text-info mt-4">Failed Requests</h2>
                <table class="table is-fullwidth is-striped mt-4">
                    <thead>
                        <tr>
                            <th>Vendor</th>
                            <th>Type</th>
                            <th>Value</th>
                            <th class="has-text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody>`;

            requests.forEach((req) => {
                html += `
                    <tr>
                        <td class="is-vcentered"><strong>${escapeHtml(req.to)}</strong></td>
                        <td class="is-vcentered">${escapeHtml(req.type)}</td>
                        <td class="is-vcentered" style="word-break: break-all;">${escapeHtml(req.value)}</td>
                        <td class="is-vcentered">
                            <div class="field is-grouped is-grouped-right">
                                <p class="control">
                                    <button class="button is-small is-info is-light retry-failed-btn" 
                                            title="Retry Request"
                                            data-vendor="${req.to}" data-val="${req.value}" data-type="${req.type}">
                                        <span class="icon is-small"><i class="material-icons">refresh</i></span>
                                    </button>
                                </p>
                                <p class="control">
                                    <button class="button is-small is-danger is-light delete-failed-btn" 
                                            title="Remove Record"
                                            data-id="${req.transaction_id}">
                                        <span class="icon is-small"><i class="material-icons">delete</i></span>
                                    </button>
                                </p>
                            </div>
                        </td>
                    </tr>`;
            });

            html += '</tbody></table>';
            content.innerHTML = html;

            // Retry listener
            content.querySelectorAll('.retry-failed-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const { vendor, val, type } = btn.dataset;
                    btn.classList.add('is-loading');
                    try {
                        const result = await this.app.fetchMatch(vendor, val, type, "");
                        this.renderResultCards([result]);
                    } catch (err) {
                        alert("Retry failed: " + err);
                        btn.classList.remove('is-loading');
                    }
                });
            });

            // Delete listener
            content.querySelectorAll('.delete-failed-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const id = btn.dataset.id;
                    if (!confirm("Are you sure you want to remove this failed request record?")) return;

                    btn.classList.add('is-loading');
                    try {
                        const delResp = await fetch('/failed-requests/delete', {
                            method: 'POST',
                            body: JSON.stringify({ id: id }),
                            headers: { 'Content-Type': 'application/json' }
                        });
                        if (delResp.ok) {
                            this.renderFailedTab();
                        } else {
                            throw new Error("Failed to delete record");
                        }
                    } catch (err) {
                        alert("Error: " + err.message);
                        btn.classList.remove('is-loading');
                    }
                });
            });

        } catch (e) {
            content.innerHTML = `<p class="has-text-danger">Error loading failed requests: ${e.message}</p>`;
        }
    }

    attachFormListeners() {
        this.container.addEventListener('click', async (event) => {
            const button = event.target.closest('button, a');

            if (!button) return;

            // Tab Switching Logic
            if (button.id === 'searchTabBtn') {
                this.activeTab = 'search';
                this.renderForm();
                return;
            }
            if (button.id === 'fetchTabBtn') {
                this.activeTab = 'fetch';
                this.renderForm();
                return;
            }
            if (button.id === 'failedTabBtn') {
                this.activeTab = 'failed';
                this.renderForm();
                return;
            }

            const targetId = button.id;

            if (targetId === 'searchButton') {
                event.preventDefault();
                await this.handleSearch();
            } else if (targetId === 'fetchSearchButton') {
                event.preventDefault();
                await this.handleUrlFetch();
            } else if (targetId === 'executeQueueButton') {
                event.preventDefault();
                await this.handleExecuteQueue();
            } else if (targetId === 'historyButton') {
                this.renderResultCards(this.app.resultHistory, true);
            } else if (targetId === 'goToButton') {
                this.renderGoToForm();
            } else if (targetId === 'uploadButton') {
                this.handleUpload();
            } else if (targetId === 'goButton') {
                const id = document.getElementById('goToValue').value;
                const customEvent = new CustomEvent('req-open-details', { detail: id });
                document.dispatchEvent(customEvent);
            }
        });
    }

    async handleSearch() {
        const userSearchInput = document.getElementById('userSearch');
        if (!userSearchInput) return;

        const searchText = userSearchInput.value;
        const dontParse = document.getElementById('dontParseCheckbox').checked;
        const viewQueue = document.getElementById('viewQueueCheckbox').checked;

        if (viewQueue && !dontParse) {
            // Updated to use the new extractAll parser method
            const extractedQueue = this.contextualizer.extractAll(searchText);
            
            this.extractedMatches = Object.keys(extractedQueue).map(key => ({
                type: key,
                matches: [...new Set(extractedQueue[key].map(m => m.value))]
            })).filter(group => group.matches.length > 0);

            this.currentQueue = []; // Reset previous selections
            this.renderMatchSelection();
            return;
        }

        await this.executeStandardSearch(searchText, dontParse);
    }

    /**
     * URL Fetch Logic: Populates the Selection Grid for manual review.
     */
    async handleUrlFetch() {
        const urlInput = document.getElementById('userUrlSearch');
        if (!urlInput || !urlInput.value) return;

        const url = urlInput.value;
        const btn = document.getElementById('fetchSearchButton');
        
        btn.classList.add('is-loading');
        const content = document.getElementById('tabContent');
        const originalContent = content.innerHTML;
        content.innerHTML = `<p class="has-text-info">Fetching URL and extracting IOCs for review...</p><progress class='progress is-info' max='100'></progress>`;

        try {
            const res = await this.app._fetch('/tools/parse-url', {
                method: 'POST',
                body: JSON.stringify({ url })
            });

            if (!res.ok) throw new Error(await res.text());
            const iocs = await res.json();

            // Map backend map[type][]Match into the extraction review format
            this.extractedMatches = Object.entries(iocs).map(([type, matches]) => ({
                type: type,
                matches: [...new Set(matches.map(m => m.Value))]
            })).filter(group => group.matches.length > 0);

            if (this.extractedMatches.length === 0) {
                alert("No IOCs were found in the provided URL.");
                content.innerHTML = originalContent;
                return;
            }

            // Switch back to Search tab to display selection grid
            this.activeTab = 'search';
            this.currentQueue = [];
            await this.renderForm(); 
        } catch (e) {
            alert("URL Fetch Failed: " + e.message);
            content.innerHTML = originalContent;
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    /**
     * Helper to safely extract second-level domain locally
     */
    _extractSecondLevelDomain(domain) {
        if (!domain) return null;
        let parts = domain.split('.');
        if (parts.length < 2) {
            return domain;
        }
        return parts.slice(-2).join('.');
    }

    async executeStandardSearch(searchText, dontParse) {
        this.isSearching = true;
        this.app.results = [];
        this.app.errors = [];
        this.app.notifications = this.app.notifications.filter(n => n.type !== 'search');

        this.container.innerHTML = "<p>Analyzing data... please wait...</p><progress class='progress is-link' max='100'></progress>";

        try {
            if (dontParse) {
                await this.processMatches(null, { value: searchText }, null, true);
            } else {
                // Updated to use extractAll instead of getMatches
                const extracted = this.contextualizer.extractAll(searchText);
                const allMatches = Object.keys(extracted).map(key => ({
                    type: key,
                    matches: [...new Set(extracted[key].map(m => m.value))]
                }));

                const promises = [];
                for (let svr of this.app.user.services) {
                    for (let matchPair of allMatches) {
                        if (matchPair.type === "domain" && matchPair.matches.length > 0) {
                            const baseDomains = new Set();
                            for (const domain of matchPair.matches) {
                                // Updated to use the local merged helper method
                                const baseDomain = this._extractSecondLevelDomain(domain);
                                if (baseDomain) baseDomains.add(baseDomain);
                            }
                            matchPair.matches = [...new Set([...matchPair.matches, ...baseDomains])];
                        }

                        if (svr.type.includes(matchPair.type)) {
                            const route = svr.route_map ? svr.route_map.find(r => r.type === matchPair.type)?.route : "";
                            promises.push(this.processMatches(svr.kind, matchPair, route, false));
                        }
                    }
                }
                await Promise.allSettled(promises);
            }
        } finally {
            this.isSearching = false;
            this.renderResultCards(this.app.results);
        }
    }

    async handleExecuteQueue() {
        this.isSearching = true;
        this.app.results = [];
        this.app.errors = [];
        this.app.notifications = this.app.notifications.filter(n => n.type !== 'search');

        this.container.innerHTML = "<p>Processing reviewed items...</p><progress class='progress is-link' max='100'></progress>";

        // Combine all selected queue items into a single space-separated string
        const blob = this.currentQueue.map(q => q.value).join(' ');

        try {
            this.app.resultWorkers.push(1);
            
            // Send to ParserHandler with parsed = true
            let result = await this.app.fetchMatchDontParse(blob, true);
            
            if (Array.isArray(result)) {
                this.app.results.push(...result);
            } else if (result) {
                this.app.results.push(result);
            }
        } catch (error) {
            this.app.errors.push(error.toString());
        } finally {
            this.app.resultWorkers.pop();
            this.isSearching = false;
            this.currentQueue = [];
            this.extractedMatches = [];
            await this.app.setHistory();
            this.renderResultCards(this.app.results);
        }
    }

    async processMatches(kind, matchData, route, dontParse) {
        if (dontParse) {
            this.app.resultWorkers.push(1);
            try {
                let result = await this.app.fetchMatchDontParse(matchData.value);
                if (Array.isArray(result)) {
                    this.app.results.push(...result);
                } else if (result) {
                    this.app.results.push(result);
                }
            } catch (error) {
                this.app.errors.push(error.toString());
            }
            this.app.resultWorkers.pop();
        } else {
            const promises = [];
            for (let match of matchData.matches) {
                if (isPrivateIP(match)) continue;

                this.app.resultWorkers.push(1);

                const promise = this.app.fetchMatch(kind, match, matchData.type, route)
                    .then(result => {
                        this.app.results.push(result);
                    })
                    .catch(error => {
                        this.app.errors.push(error.toString());
                    })
                    .finally(() => {
                        this.app.resultWorkers.pop();
                    });
                promises.push(promise);
            }
            await Promise.allSettled(promises);
        }

        await this.app.setHistory();
    }

    handleUpload() {
        const fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.addEventListener("change", async () => {
            if (!fileInput.files[0]) return;
            const file = new File([fileInput.files[0]], makeUnique(fileInput.files[0].name), { type: fileInput.files[0].type });
            await this.app.uploadFile(file);
        });
        fileInput.click();
    }

    renderGoToForm() {
        this.container.innerHTML = `<div class="field"><label class="label has-text-info">Enter ID</label><div class="control"><input class="input" type="text" placeholder="ID" id="goToValue"></div><div class="control"><button class="button is-primary mt-2" id="goButton">Go</button></div></div>`;
    }

    renderResultCards(resultsArray, isHistoryView = false) {
        if (this.isSearching && (!resultsArray || resultsArray.length === 0)) {
            return;
        }

        this.container.innerHTML = "";

        if (!resultsArray || resultsArray.length === 0) {
            this.container.innerHTML = `<p class="has-text-info">${isHistoryView ? 'History is empty.' : 'No results found.'}</p>`;
            const backBtn = document.createElement('button');
            backBtn.className = "button is-small is-dark mt-4";
            backBtn.textContent = "Back to Search";
            backBtn.onclick = () => this.renderForm();
            this.container.appendChild(backBtn);
            return;
        }

        if (!isHistoryView) {
            resultsArray.sort((a, b) => (b.threat_level_id || 0) - (a.threat_level_id || 0));
        }

        for (const result of resultsArray) {
            const article = document.createElement('article');
            article.className = 'message is-dark';
            const header = document.createElement('div');
            header.className = 'message-header';
            if (typeof result.background === 'string') header.classList.add(escapeHtml(result.background));
            header.innerHTML = `<p>${escapeHtml(result.from)}</p>`;

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

                if (!pastSearches || pastSearches.length === 0) {
                    alert(`No past searches found for: ${result.value}`);
                    return;
                }

                const historyReport = pastSearches
                    .map(search => `• ${search.info}`)
                    .join('\n');

                alert(`Historical matches for ${result.value}:\n\n${historyReport}`);
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
            article.appendChild(header);
            article.appendChild(body);
            article.appendChild(footer);
            this.container.appendChild(article);
        }

        const footerContainer = document.createElement('footer');
        footerContainer.className = 'card-footer mt-4';

        const clearButton = document.createElement('a');
        clearButton.href = '#';
        clearButton.className = 'card-footer-item has-background-danger has-text-white';
        clearButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">delete_sweep</i></span><span>${isHistoryView ? 'Clear History' : 'Clear Results'}</span></span>`;
        clearButton.addEventListener('click', (e) => {
            e.preventDefault();
            if (isHistoryView) {
                this.app.resultHistory = [];
                this.app.setHistory();
            }
            this.app.results = [];
            this.renderForm();
        });

        footerContainer.appendChild(clearButton);
        this.container.appendChild(footerContainer);
    }
}