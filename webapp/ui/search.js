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
        this.container.classList.remove('has-background-custom');
        this.container.classList.add('has-background-black');
        this.container.classList.add('search-view');

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
        <!-- Sticky Search Header / Navigation Bar -->
        <div class="users-nav-bar search-nav-bar mb-3" id="search-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title">Indicator Search</span>
                    <span class="tag is-info is-dark is-rounded charts-count-badge" id="searchCountBadge">Ready</span>
                </div>
            </div>

            <div class="users-nav-right">
                <button type="button" class="button is-small terminal-btn" id="historyButton" title="View past search history">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">history</i></span>
                    <span>History</span>
                </button>
                <button type="button" class="button is-small terminal-btn" id="goToButton" title="Look up record by transaction ID">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">double_arrow</i></span>
                    <span>Lookup ID</span>
                </button>
                <button type="button" class="button is-small terminal-btn" id="uploadButton" title="Upload threat intelligence file">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">upload_file</i></span>
                    <span>Upload</span>
                </button>
                <button type="button" class="button is-small is-dark is-outlined" id="searchRefreshBtn" title="Refresh dashboard stats">↻ Refresh</button>
            </div>
        </div>

        <!-- Telemetry Overview Metric Cards -->
        <div class="search-stats-grid mb-4">
            ${this._renderStatBox("Open Cases", stats.open_cases, "warning", "statBoxOpenCases", "work_outline")}
            ${this._renderStatBox("Responses", stats.active_responses, "info", "statBoxResponses", "history")}
            ${this._renderStatBox("Archived", stats.archived_responses, "grey", "statBoxArchived", "archive")}
            ${this._renderStatBox("Users", stats.total_users, "success", "statBoxUsers", "people")}
            ${this._renderStatBox("Proxied", stats.server_metrics?.vendor_responses || 0, "white", "statBoxProxied", "alt_route")}
        </div>

        <!-- Main Search Window -->
        <div class="users-window search-window" id="searchWindow">
            <div class="terminal-titlebar">
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span>indicator investigation console</span>
                </div>
                <div class="terminal-actions">
                    <div class="buttons has-addons mb-0 search-tab-buttons">
                        <button id="searchTabBtn" class="button is-small terminal-btn ${this.activeTab === 'search' ? 'terminal-btn-active' : ''}" type="button">
                            <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">search</i></span>
                            <span>Search</span>
                        </button>
                        <button id="fetchTabBtn" class="button is-small terminal-btn ${this.activeTab === 'fetch' ? 'terminal-btn-active' : ''}" type="button">
                            <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">cloud_download</i></span>
                            <span>Fetch URL</span>
                        </button>
                        <button id="failedTabBtn" class="button is-small terminal-btn ${this.activeTab === 'failed' ? 'terminal-btn-active' : ''}" type="button">
                            <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">report_problem</i></span>
                            <span>Failed</span>
                        </button>
                    </div>
                    <span class="system-status-pill status-nominal">
                        <span class="status-indicator-dot dot-nominal"></span>ONLINE
                    </span>
                </div>
            </div>

            <div class="search-window-body" id="tabContent"></div>

            <div class="terminal-statusbar">
                <span id="searchStatusbarText">Intel Search Engine &bull; Ready</span>
                <span class="is-pulled-right">threatco telemetry &bull; query pipeline</span>
            </div>
        </div>`;

        // Render the content for the active tab
        if (this.activeTab === 'search') {
            this.renderSearchTab();
            if (this.extractedMatches.length > 0) this.renderMatchSelection();
        } else if (this.activeTab === 'fetch') {
            this.renderFetchTab();
        } else {
            this.renderFailedTab();
        }
    }

    _renderStatBox(label, value, colorClass, id = '', icon = 'analytics') {
        return `
            <div class="search-stat-card stat-box" ${id ? `id="${id}"` : ''} title="Click to view ${escapeHtml(label)}">
                <div class="search-stat-card-header">
                    <span class="search-stat-label">${escapeHtml(label)}</span>
                    <i class="material-icons search-stat-icon">${escapeHtml(icon)}</i>
                </div>
                <div class="search-stat-value val-${colorClass} has-text-${colorClass}">${escapeHtml(String(value ?? 0))}</div>
            </div>`;
    }

    renderSearchTab() {
        const content = document.getElementById('tabContent');
        if (!content) return;
        content.innerHTML = `
        <div class="search-form-card">
            <div class="search-form-header">
                <h2 class="search-form-title">New Search/h2>
                <p class="search-form-subtitle">Enter IP addresses, domains, hashes (MD5, SHA256), URLs, or raw threat telemetry text to extract and query.</p>
            </div>
            <form onsubmit="return false;">
                <div class="field">
                    <div class="control">
                        <textarea class="textarea search-textarea" placeholder="Paste IOCs, logs, emails, or threat intel reports here..." id="userSearch" rows="6"></textarea>
                    </div>
                </div>
                
                <div class="search-controls-row">
                    <div class="search-options-group">
                        <label class="search-check-pill" title="Send raw payload directly to server without client parsing">
                            <input type="checkbox" id="dontParseCheckbox">
                            <span>Parse on Server</span>
                        </label>
                        <label class="search-check-pill" title="Preview extracted IOCs in staging area before querying intelligence sources">
                            <input type="checkbox" id="viewQueueCheckbox">
                            <span>Preview Matches (Staging)</span>
                        </label>
                    </div>
                    
                    <div class="search-actions-group">
                        <button class="button search-btn-primary" id="searchButton" type="submit">
                            <span class="icon-text">
                                <span class="icon"><i class="material-icons">search</i></span>
                                <span>Find IOCs</span>
                            </span>
                        </button>
                        <button class="button search-btn-success is-hidden" id="executeQueueButton" type="button">
                            <span class="icon-text">
                                <span class="icon"><i class="material-icons">bolt</i></span>
                                <span>Analyze Selected (<span id="queueCount">0</span>)</span>
                            </span>
                        </button>
                    </div>
                </div>
                
                <div id="iocSelectionArea" class="mt-4"></div>
            </form>
        </div>`;
    }

    renderFetchTab() {
        const content = document.getElementById('tabContent');
        if (!content) return;
        content.innerHTML = `
        <div class="search-form-card">
            <div class="search-form-header">
                <h2 class="search-form-title">Fetch & Extract from URL</h2>
                <p class="search-form-subtitle">Input a threat report, blog post, or advisory URL to crawl and automatically extract IOCs for manual review.</p>
            </div>
            <form id="fetchUrlForm" onsubmit="return false;">
                <div class="field mb-4">
                    <div class="control has-icons-left">
                        <input class="input search-input" type="url" id="userUrlSearch" placeholder="https://example.com/threat-report" required>
                        <span class="icon is-small is-left has-text-info"><i class="material-icons">link</i></span>
                    </div>
                </div>
                <div class="field">
                    <div class="control">
                        <button class="button search-btn-primary" id="fetchSearchButton" type="submit">
                            <span class="icon-text">
                                <span class="icon"><i class="material-icons">cloud_download</i></span>
                                <span>Fetch & Review</span>
                            </span>
                        </button>
                    </div>
                </div>
            </form>
        </div>`;
    }

    /**
     * Renders the Opt-In selection grid. Items are dark by default.
     * Click a tag to highlight and add it to the execution queue.
     */
    renderMatchSelection() {
        const area = document.getElementById('iocSelectionArea');
        const execBtn = document.getElementById('executeQueueButton');
        if (!area || !execBtn) return;

        const totalCount = this.extractedMatches.reduce((acc, g) => acc + g.matches.length, 0);

        area.innerHTML = `
            <div class="is-flex is-justify-content-between is-align-items-center mb-3">
                <h3 class="search-form-title" style="font-size: 0.95rem;">Extracted Indicators (Click to Select)</h3>
                <span class="tag is-dark is-small" style="color: #94a3b8;">${totalCount} detected</span>
            </div>`;
        
        this.extractedMatches.forEach(group => {
            const box = document.createElement('div');
            box.className = "ioc-match-group mb-3";
            box.innerHTML = `
                <div class="ioc-match-group-title">
                    <i class="material-icons" style="font-size: 14px;">label</i>
                    <span>${escapeHtml(group.type.toUpperCase())}</span>
                    <span class="tag is-dark is-small ml-1" style="font-size: 0.7rem;">${group.matches.length}</span>
                </div>`;
            
            const tagsDiv = document.createElement('div');
            tagsDiv.className = "is-flex is-flex-wrap-wrap";
            
            group.matches.forEach(val => {
                const tag = document.createElement('span');
                const isSelected = this.currentQueue.some(q => q.value === val && q.type === group.type);
                
                tag.className = `tag is-medium ioc-chip ${isSelected ? 'is-info is-selected' : 'is-dark is-unselected'}`;
                tag.style.cursor = "pointer";
                tag.textContent = val;
                
                tag.onclick = () => {
                    if (tag.classList.contains('is-unselected') || tag.classList.contains('is-dark')) {
                        tag.classList.remove('is-dark', 'is-unselected');
                        tag.classList.add('is-info', 'is-selected');
                        this.currentQueue.push({ value: val, type: group.type });
                    } else {
                        tag.classList.remove('is-info', 'is-selected');
                        tag.classList.add('is-dark', 'is-unselected');
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
        if (!content) return;
        content.innerHTML = `
            <div class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                <p class="has-text-info mb-2">Loading failed requests...</p>
                <progress class="progress is-small is-info" max="100"></progress>
            </div>`;

        try {
            const resp = await fetch('/failed-requests');
            const requests = await resp.json();

            if (!requests || requests.length === 0) {
                content.innerHTML = `
                    <div class="terminal-placeholder" style="text-align: center; padding: 3rem 1.5rem; color: #64748b;">
                        <p class="mb-2"><i class="material-icons" style="font-size: 36px; color: #10b981;">check_circle</i></p>
                        <p class="has-text-info" style="font-size: 1rem; font-weight: 600;">No Failed Requests</p>
                        <p class="has-text-grey-light" style="font-size: 0.85rem;">All vendor intelligence queries completed successfully.</p>
                    </div>`;
                return;
            }

            let html = `
                <div class="search-form-header mb-3">
                    <h2 class="search-form-title">Failed Query Records</h2>
                    <p class="search-form-subtitle">${requests.length} failed requests awaiting retry or removal.</p>
                </div>
                <div class="terminal-table-container">
                    <table class="terminal-table users-table search-table">
                        <thead>
                            <tr>
                                <th style="width: 160px;">VENDOR</th>
                                <th style="width: 120px;">TYPE</th>
                                <th>VALUE</th>
                                <th style="width: 120px; text-align: right;">ACTIONS</th>
                            </tr>
                        </thead>
                        <tbody>`;

            requests.forEach((req) => {
                html += `
                    <tr class="terminal-table-row">
                        <td class="is-vcentered">
                            <span class="tag is-dark is-small terminal-vendor-tag">${escapeHtml(req.to)}</span>
                        </td>
                        <td class="is-vcentered">
                            <span class="tag is-dark is-small" style="color: #cbd5e1; border: 1px solid rgba(56, 189, 248, 0.2);">${escapeHtml(req.type)}</span>
                        </td>
                        <td class="is-vcentered">
                            <span class="search-ioc-val">${escapeHtml(req.value)}</span>
                        </td>
                        <td class="is-vcentered" style="text-align: right;">
                            <div class="buttons is-right are-small mb-0">
                                <button class="button is-small terminal-btn retry-failed-btn" 
                                        title="Retry Request"
                                        data-vendor="${escapeHtml(req.to)}" data-val="${escapeHtml(req.value)}" data-type="${escapeHtml(req.type)}">
                                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">refresh</i></span>
                                </button>
                                <button class="button is-small terminal-btn terminal-btn-danger delete-failed-btn" 
                                        title="Remove Record"
                                        data-id="${escapeHtml(req.transaction_id)}">
                                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">delete</i></span>
                                </button>
                            </div>
                        </td>
                    </tr>`;
            });

            html += '</tbody></table></div>';
            content.innerHTML = html;

            // Retry listener
            content.querySelectorAll('.retry-failed-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const { vendor, val, type } = btn.dataset;
                    btn.classList.add('is-loading');
                    try {
                        const result = await this.app.fetchMatch(vendor, val, type, "");
                        const results = Array.isArray(result) ? result : [result];
                        this.renderResultCards(results.filter(Boolean), false);
                    } catch (err) {
                        alert("Retry failed: " + err);
                    } finally {
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
            content.innerHTML = `<p class="has-text-danger p-4">Error loading failed requests: ${escapeHtml(e.message)}</p>`;
        }
    }

    attachFormListeners() {
        this.container.addEventListener('click', async (event) => {
            const statBox = event.target.closest('.stat-box');
            if (statBox) {
                const target = statBox.id;
                if (target === 'statBoxOpenCases') {
                    document.getElementById('sidebarCases')?.click();
                    return;
                }
                if (target === 'statBoxResponses' || target === 'statBoxArchived' || target === 'statBoxProxied') {
                    document.getElementById('sidebarRecentActivity')?.click();
                    return;
                }
                if (target === 'statBoxUsers') {
                    window.location.href = '/users';
                    return;
                }
            }

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
                if (typeof this.app.fetchHistory === 'function') {
                    await this.app.fetchHistory();
                }
                this.renderResultCards(this.app.resultHistory || [], true);
            } else if (targetId === 'goToButton') {
                this.renderGoToForm();
            } else if (targetId === 'goToBackBtn' || targetId === 'searchRefreshBtn') {
                await this.renderForm();
            } else if (targetId === 'uploadButton') {
                this.handleUpload();
            } else if (targetId === 'goButton') {
                const inputEl = document.getElementById('goToValue');
                const id = inputEl?.value;
                if (id) {
                    const customEvent = new CustomEvent('req-open-details', { detail: id });
                    document.dispatchEvent(customEvent);
                }
            }
        });
    }

    async handleSearch() {
        const userSearchInput = document.getElementById('userSearch');
        if (!userSearchInput) return;

        const searchText = userSearchInput.value;
        const dontParse = document.getElementById('dontParseCheckbox')?.checked || false;
        const viewQueue = document.getElementById('viewQueueCheckbox')?.checked || false;

        if (viewQueue && !dontParse) {
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
        content.innerHTML = `
            <div class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                <p class="has-text-info mb-2">Fetching URL and extracting IOCs for review...</p>
                <progress class="progress is-small is-info" max="100"></progress>
            </div>`;

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

        this.renderRunningTerminal('ioc-analysis.running', 'Analyzing indicators across threat intelligence sources...');

        try {
            if (dontParse) {
                await this.processMatches(null, { value: searchText }, null, true);
            } else {
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
            this.finalizeSearchResults();
        }
    }

    async handleExecuteQueue() {
        this.isSearching = true;
        this.app.results = [];
        this.app.errors = [];
        this.app.notifications = this.app.notifications.filter(n => n.type !== 'search');

        this.renderRunningTerminal('ioc-analysis.queue', 'Processing reviewed indicators...');

        // Combine all selected queue items into a single space-separated string
        const blob = this.currentQueue.map(q => q.value).join(' ');

        try {
            this.app.resultWorkers.push(1);
            
            // Send to ParserHandler with parsed = true
            let result = await this.app.fetchMatchDontParse(blob, true);
            
            if (Array.isArray(result)) {
                for (const item of result) {
                    this.app.results.push(item);
                    this.appendStreamingResult(item);
                }
            } else if (result) {
                this.app.results.push(result);
                this.appendStreamingResult(result);
            }
        } catch (error) {
            this.app.errors.push(error.toString());
        } finally {
            this.app.resultWorkers.pop();
            this.isSearching = false;
            this.currentQueue = [];
            this.extractedMatches = [];
            await this.app.setHistory();
            this.finalizeSearchResults();
        }
    }

    async processMatches(kind, matchData, route, dontParse) {
        if (dontParse) {
            this.app.resultWorkers.push(1);
            try {
                let result = await this.app.fetchMatchDontParse(matchData.value);
                if (Array.isArray(result)) {
                    for (const item of result) {
                        this.app.results.push(item);
                        this.appendStreamingResult(item);
                    }
                } else if (result) {
                    this.app.results.push(result);
                    this.appendStreamingResult(result);
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
                        if (result) {
                            this.app.results.push(result);
                            this.appendStreamingResult(result);
                        }
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
        this.container.classList.remove('is-hidden');
        this.container.classList.remove('has-background-custom');
        this.container.classList.add('has-background-black');
        this.container.classList.add('search-view');

        this.container.innerHTML = `
        <div class="users-nav-bar search-nav-bar mb-3" id="search-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title">Indicator Search</span>
                    <span class="tag is-info is-dark is-rounded charts-count-badge">Record Lookup</span>
                </div>
            </div>
            <div class="users-nav-right">
                <button type="button" class="button is-small terminal-btn" id="goToBackBtn" title="Back to Search">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">arrow_back</i></span>
                    <span>Back to Search</span>
                </button>
            </div>
        </div>

        <div class="users-window search-window" id="searchWindow">
            <div class="terminal-titlebar">
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span>telemetry record lookup</span>
                </div>
                <div class="terminal-actions">
                    <span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>LOOKUP READY</span>
                </div>
            </div>
            <div class="search-window-body p-5">
                <div class="search-form-card" style="max-width: 580px; margin: 1.5rem auto;">
                    <div class="search-form-header">
                        <h2 class="search-form-title">Enter Transaction ID</h2>
                        <p class="search-form-subtitle">Look up and view raw response telemetry by its unique transaction link identifier.</p>
                    </div>
                    <form onsubmit="return false;">
                        <div class="field mb-4">
                            <div class="control has-icons-left">
                                <input class="input search-input" type="text" placeholder="Transaction ID (e.g. 1042)..." id="goToValue" autocomplete="off" />
                                <span class="icon is-small is-left has-text-info"><i class="material-icons">key</i></span>
                            </div>
                        </div>
                        <div class="field is-grouped">
                            <p class="control">
                                <button class="button search-btn-primary" id="goButton" type="button">
                                    <span class="icon-text">
                                        <span class="icon"><i class="material-icons">visibility</i></span>
                                        <span>Lookup Details</span>
                                    </span>
                                </button>
                            </p>
                            <p class="control">
                                <button class="button is-dark terminal-btn" id="goToBackBtn" type="button">Cancel</button>
                            </p>
                        </div>
                    </form>
                </div>
            </div>
            <div class="terminal-statusbar">
                <span>Direct Telemetry Store &bull; Transaction Lookup</span>
                <span class="is-pulled-right">threatco runtime &bull; direct query</span>
            </div>
        </div>`;
    }

    renderRunningTerminal(titleText = 'ioc-analysis.running', messageText = 'Analyzing indicators across threat intelligence sources...') {
        this.container.classList.remove('is-hidden');
        this.container.classList.remove('has-background-custom');
        this.container.classList.add('has-background-black');
        this.container.classList.add('search-view');

        this.container.innerHTML = `
        <div class="users-nav-bar search-nav-bar mb-3" id="search-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title">Indicator Search</span>
                    <span class="tag is-info is-dark is-rounded charts-count-badge" id="resultsCountBadge">0 items</span>
                </div>
            </div>
            <div class="users-nav-right">
                <button id="terminalBackBtn" class="button is-small terminal-btn" type="button" title="Back to Search Form">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">arrow_back</i></span>
                    <span>Search</span>
                </button>
                <button id="terminalClearBtn" class="button is-small terminal-btn terminal-btn-danger" type="button" title="Clear">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">delete_sweep</i></span>
                    <span>Clear Results</span>
                </button>
            </div>
        </div>

        <div class="users-window search-window terminal-window">
            <div class="terminal-titlebar">
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span id="runningTerminalTitle">${escapeHtml(titleText)}</span>
                </div>
                <div class="terminal-actions">
                    <input id="iocFilterInput" type="text" class="input is-small search-input" style="min-width: 200px;" placeholder="Filter results (IOC, vendor, info)..." />
                    <div class="buttons has-addons mb-0">
                        <button id="filterAllResultsBtn" class="button is-small terminal-btn terminal-btn-active" type="button">All (<span id="countAllBtn">0</span>)</button>
                        <button id="filterMatchedOnlyBtn" class="button is-small terminal-btn" type="button">Matches (<span id="countMatchedBtn">0</span>)</button>
                    </div>
                </div>
            </div>
            <div class="terminal-body" id="iocResultsBody" style="min-height: 220px; height: auto;">
                <div class="terminal-placeholder" id="iocStreamingPlaceholder">
                    <p class="has-text-info mb-3">
                        <span class="animate-spin" style="display: inline-block; margin-right: 8px;">⏳</span> ${escapeHtml(messageText)}
                    </p>
                    <progress class="progress is-small is-info" max="100"></progress>
                </div>
            </div>
            <div class="terminal-statusbar">
                <span id="terminalStatusCount">Query in progress &bull; waiting for vendor telemetry...</span>
                <span class="is-pulled-right" id="terminalStatusRight">threatco runtime &bull; active</span>
            </div>
        </div>`;

        this._wireLiveTerminalControls(false);
    }

    _wireLiveTerminalControls(isHistoryView = false) {
        const backBtn = this.container.querySelector('#terminalBackBtn');
        if (backBtn) {
            backBtn.onclick = () => this.renderForm();
        }

        const clearBtn = this.container.querySelector('#terminalClearBtn');
        if (clearBtn) {
            clearBtn.onclick = (e) => {
                e.preventDefault();
                if (isHistoryView) {
                    this.app.resultHistory = [];
                    this.app.setHistory();
                }
                this.app.results = [];
                this.renderForm();
            };
        }

        const filterInput = this.container.querySelector('#iocFilterInput');
        const filterAllBtn = this.container.querySelector('#filterAllResultsBtn');
        const filterMatchedBtn = this.container.querySelector('#filterMatchedOnlyBtn');

        const applyFilter = () => {
            const body = this.container.querySelector('#iocResultsBody');
            if (!body) return;
            const items = body.querySelectorAll('.terminal-result-item');
            const q = (filterInput?.value || '').trim().toLowerCase();
            const onlyMatches = filterMatchedBtn?.classList.contains('terminal-btn-active');
            let visibleCount = 0;
            let totalMatches = 0;

            items.forEach(el => {
                const isMatch = el.getAttribute('data-matched') === 'true';
                if (isMatch) totalMatches++;
                const text = el.textContent.toLowerCase();
                const matchesQ = !q || text.includes(q);
                const matchesFilter = !onlyMatches || isMatch;

                if (matchesQ && matchesFilter) {
                    el.style.display = '';
                    visibleCount++;
                } else {
                    el.style.display = 'none';
                }
            });

            const statusCountEl = this.container.querySelector('#terminalStatusCount');
            if (statusCountEl) {
                statusCountEl.textContent = `Showing ${visibleCount} of ${items.length} items (${totalMatches} threat matches)`;
            }
        };

        let filterDebounce = null;
        if (filterInput) {
            filterInput.oninput = () => {
                clearTimeout(filterDebounce);
                filterDebounce = setTimeout(applyFilter, 120);
            };
        }

        if (filterAllBtn && filterMatchedBtn) {
            filterAllBtn.onclick = () => {
                filterAllBtn.classList.add('terminal-btn-active');
                filterMatchedBtn.classList.remove('terminal-btn-active');
                applyFilter();
            };
            filterMatchedBtn.onclick = () => {
                filterMatchedBtn.classList.add('terminal-btn-active');
                filterAllBtn.classList.remove('terminal-btn-active');
                applyFilter();
            };
        }
    }

    _createResultItemElement(result, isStreaming = false) {
        if (!result) return document.createElement('div');

        const isMatched = result.matched === true || 
                          result.matched === 'true' || 
                          (typeof result.threat_level_id === 'number' && result.threat_level_id > 1);

        const item = document.createElement('div');
        item.className = `terminal-result-item ${isMatched ? 'is-match' : 'is-clean'}${isStreaming ? ' item-fade-enter' : ''}`;
        item.setAttribute('data-matched', isMatched ? 'true' : 'false');
        item.setAttribute('data-threat-level', String(result.threat_level_id || 0));

        const threatScore = result.threat_level_id ?? 0;
        const threatScoreClass = threatScore > 1 ? 'terminal-v-score-high' : '';

        const statusBadgeHtml = isMatched ? `
            <span class="terminal-match-badge match-flagged">
                <i class="material-icons" style="font-size: 13px;">warning</i> MATCH
            </span>
        ` : `
            <span class="terminal-match-badge match-clean">
                <i class="material-icons" style="font-size: 13px;">check_circle</i> NO MATCH
            </span>
        `;

        item.innerHTML = `
            <div class="terminal-result-header">
                <div class="terminal-result-meta-left">
                    ${statusBadgeHtml}
                    <span class="tag is-dark is-small terminal-vendor-tag">${escapeHtml(result.from || 'VENDOR')}</span>
                    <span class="terminal-ioc-val">${escapeHtml(String(result.value || ''))}</span>
                </div>
                <div class="terminal-result-actions">
                    <button class="button is-small terminal-btn past-searches-btn" type="button" data-val="${escapeHtml(String(result.value || ''))}" title="View past searches for this indicator">
                        <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">history</i></span>
                        <span>Past Searches</span>
                    </button>
                    <button class="button is-small terminal-btn view-details-btn" type="button" data-link="${escapeHtml(String(result.link || ''))}" title="View raw vendor response details" ${(!result.link || result.link === "none") ? 'disabled' : ''}>
                        <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">visibility</i></span>
                        <span>View Details</span>
                    </button>
                </div>
            </div>
            <div class="terminal-result-body">
                <div class="terminal-kv-row">
                    <span class="terminal-k">INFO:</span>
                    <span class="terminal-v terminal-v-info">${escapeHtml(String(result.info || 'No description provided'))}</span>
                </div>
                <div class="terminal-kv-meta">
                    <span><span class="terminal-k">SCORE:</span> <span class="terminal-v ${threatScoreClass}">${escapeHtml(String(threatScore))}</span></span>
                    <span><span class="terminal-k">ATTRS:</span> <span class="terminal-v">${escapeHtml(String(result.attr_count ?? 0))}</span></span>
                    <span><span class="terminal-k">ID:</span> <span class="terminal-v">${escapeHtml(String(result.id || 'none'))}</span></span>
                    <span><span class="terminal-k">SERVER ID:</span> <span class="terminal-v">${escapeHtml(String(result.link || 'none'))}</span></span>
                </div>
            </div>
        `;

        const pastSearchesBtn = item.querySelector('.past-searches-btn');
        if (pastSearchesBtn) {
            pastSearchesBtn.onclick = async (e) => {
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
            };
        }

        const viewDetailsBtn = item.querySelector('.view-details-btn');
        if (viewDetailsBtn) {
            viewDetailsBtn.onclick = (e) => {
                e.preventDefault();
                if (!result.link || result.link === "none") return;
                const customEvent = new CustomEvent('req-open-details', { detail: result.link });
                document.dispatchEvent(customEvent);
            };
        }

        return item;
    }

    appendStreamingResult(result) {
        let body = this.container.querySelector('#iocResultsBody');
        if (!body) {
            this.renderRunningTerminal('ioc-analysis.results', 'Processing incoming telemetry...');
            body = this.container.querySelector('#iocResultsBody');
        }

        const placeholder = this.container.querySelector('#iocStreamingPlaceholder');
        if (placeholder) {
            placeholder.remove();
        }

        const item = this._createResultItemElement(result, true);
        const newScore = result.threat_level_id || 0;
        
        // Find insert location to maintain sorted order by threat level descending
        const existingItems = Array.from(body.querySelectorAll('.terminal-result-item'));
        let inserted = false;
        for (const existing of existingItems) {
            const existingScore = parseInt(existing.getAttribute('data-threat-level') || '0', 10);
            if (newScore > existingScore) {
                body.insertBefore(item, existing);
                inserted = true;
                break;
            }
        }
        if (!inserted) {
            body.appendChild(item);
        }

        // Animate smooth fade-in
        requestAnimationFrame(() => {
            item.classList.add('item-fade-enter-active');
            setTimeout(() => {
                item.classList.remove('item-fade-enter', 'item-fade-enter-active');
            }, 180);
        });

        // Update counts
        const allItems = body.querySelectorAll('.terminal-result-item');
        const matchedItems = body.querySelectorAll('.terminal-result-item[data-matched="true"]');
        const totalCount = allItems.length;
        const matchedCount = matchedItems.length;

        const countBadge = this.container.querySelector('#resultsCountBadge');
        if (countBadge) countBadge.textContent = `${totalCount} items`;

        const countAllBtn = this.container.querySelector('#countAllBtn');
        if (countAllBtn) countAllBtn.textContent = totalCount;

        const countMatchedBtn = this.container.querySelector('#countMatchedBtn');
        if (countMatchedBtn) countMatchedBtn.textContent = matchedCount;

        const statusCountEl = this.container.querySelector('#terminalStatusCount');
        if (statusCountEl) {
            statusCountEl.textContent = `Showing ${totalCount} of ${totalCount} items (${matchedCount} threat matches)`;
        }
    }

    finalizeSearchResults() {
        const placeholder = this.container.querySelector('#iocStreamingPlaceholder');
        if (placeholder) {
            placeholder.remove();
        }

        const body = this.container.querySelector('#iocResultsBody');
        const count = body ? body.querySelectorAll('.terminal-result-item').length : 0;
        
        if (count === 0) {
            this.renderResultCards([], false);
            return;
        }

        const titleEl = this.container.querySelector('#runningTerminalTitle');
        if (titleEl) titleEl.textContent = 'ioc-analysis.results';

        const statusRight = this.container.querySelector('#terminalStatusRight');
        if (statusRight) statusRight.textContent = 'threatco ioc analysis • complete';
    }

    renderResultCards(resultsArray, isHistoryView = false) {
        if (this.isSearching && (!resultsArray || resultsArray.length === 0)) {
            return;
        }

        this.container.classList.remove('is-hidden');
        this.container.classList.remove('has-background-custom');
        this.container.classList.add('has-background-black');
        this.container.classList.add('search-view');

        this.container.innerHTML = "";

        const validResults = Array.isArray(resultsArray) 
            ? resultsArray.filter(r => r && typeof r === 'object') 
            : [];

        if (validResults.length === 0) {
            this.container.innerHTML = `
                <div class="users-nav-bar search-nav-bar mb-3" id="search-top">
                    <div class="users-nav-left">
                        <div class="users-nav-title-group">
                            <span class="users-nav-title">${isHistoryView ? 'Search History' : 'Indicator Search'}</span>
                            <span class="tag is-info is-dark is-rounded charts-count-badge">0 items</span>
                        </div>
                    </div>
                    <div class="users-nav-right">
                        <button class="button is-small terminal-btn" id="emptyBackBtn" type="button">
                            <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">arrow_back</i></span>
                            <span>Back to Search</span>
                        </button>
                    </div>
                </div>

                <div class="users-window search-window terminal-window">
                    <div class="terminal-titlebar">
                        <div class="terminal-title">
                            <span class="terminal-status-dot"></span>
                            <span>${isHistoryView ? 'ioc-history.log' : 'ioc-analysis.results'}</span>
                        </div>
                        <div class="terminal-actions">
                            <span class="system-status-pill status-unknown">
                                <span class="status-indicator-dot dot-unknown"></span>EMPTY
                            </span>
                        </div>
                    </div>
                    <div class="terminal-body" style="min-height: 220px; height: auto;">
                        <div class="terminal-placeholder">
                            <p class="has-text-grey-light mb-2"><i class="material-icons" style="font-size: 36px; vertical-align: middle;">search_off</i></p>
                            <p class="has-text-info">${isHistoryView ? 'History is empty.' : 'No results found.'}</p>
                        </div>
                    </div>
                    <div class="terminal-statusbar">
                        <span>0 items</span>
                        <span class="is-pulled-right">threatco ioc analysis &bull; ${isHistoryView ? 'history' : 'live'}</span>
                    </div>
                </div>`;
            const backBtn = this.container.querySelector('#emptyBackBtn');
            if (backBtn) backBtn.onclick = () => this.renderForm();
            return;
        }

        const resultsList = isHistoryView ? [...validResults].reverse() : [...validResults];
        if (!isHistoryView) {
            resultsList.sort((a, b) => (b.threat_level_id || 0) - (a.threat_level_id || 0));
        }

        const matchedCount = resultsList.filter(r => 
            r.matched === true || r.matched === 'true' || (typeof r.threat_level_id === 'number' && r.threat_level_id > 1)
        ).length;

        this.container.innerHTML = `
        <div class="users-nav-bar search-nav-bar mb-3" id="search-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title">${isHistoryView ? 'Search History' : 'Indicator Search'}</span>
                    <span class="tag is-info is-dark is-rounded charts-count-badge" id="resultsCountBadge">${resultsList.length} items</span>
                </div>
            </div>
            <div class="users-nav-right">
                <button id="terminalBackBtn" class="button is-small terminal-btn" type="button" title="Back to Search Form">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">arrow_back</i></span>
                    <span>Search</span>
                </button>
                <button id="terminalClearBtn" class="button is-small terminal-btn terminal-btn-danger" type="button" title="Clear">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">delete_sweep</i></span>
                    <span>${isHistoryView ? 'Clear History' : 'Clear Results'}</span>
                </button>
            </div>
        </div>

        <div class="users-window search-window terminal-window">
            <div class="terminal-titlebar">
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span>${isHistoryView ? 'ioc-history.log' : 'ioc-analysis.results'}</span>
                </div>
                <div class="terminal-actions">
                    <input id="iocFilterInput" type="text" class="input is-small search-input" style="min-width: 200px;" placeholder="Filter results (IOC, vendor, info)..." />
                    <div class="buttons has-addons mb-0">
                        <button id="filterAllResultsBtn" class="button is-small terminal-btn terminal-btn-active" type="button">All (${resultsList.length})</button>
                        <button id="filterMatchedOnlyBtn" class="button is-small terminal-btn" type="button">Matches (${matchedCount})</button>
                    </div>
                </div>
            </div>
            <div class="terminal-body" id="iocResultsBody" style="min-height: 220px; height: auto;"></div>
            <div class="terminal-statusbar">
                <span id="terminalStatusCount">Showing ${resultsList.length} of ${resultsList.length} items (${matchedCount} threat matches)</span>
                <span class="is-pulled-right">threatco ioc analysis &bull; ${isHistoryView ? 'history' : 'live'}</span>
            </div>
        </div>`;

        const body = this.container.querySelector('#iocResultsBody');
        for (const result of resultsList) {
            const item = this._createResultItemElement(result, false);
            body.appendChild(item);
        }

        this._wireLiveTerminalControls(isHistoryView);
    }
}