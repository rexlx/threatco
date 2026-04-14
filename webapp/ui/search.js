import { escapeHtml, makeUnique, isPrivateIP } from './utils.js';

export class SearchController {
    constructor(containerId, app, contextualizer) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.contextualizer = contextualizer;
        this.isSearching = false;
        this.currentQueue = []; // Holds extracted matches for preview
        this.activeTab = 'search'; // Track the active tab

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

        // Render overview stats and tab headers
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
            <div class="field"><div class="control"><textarea class="textarea" placeholder="feed me..." id="userSearch"></textarea></div></div>
            <div class="field"><div class="control">
                <label class="checkbox has-text-grey-light"><input type="checkbox" id="dontParseCheckbox"> parse on server</label>
                <label class="checkbox has-text-grey-light ml-4"><input type="checkbox" id="viewQueueCheckbox"> preview matches</label>
            </div></div>
            <div class="field"><div class="control">
                <button class="button is-info is-outlined" id="searchButton" type="submit">
                    <span class="icon-text"><span class="icon"><i class="material-icons">search</i></span><span>Search</span></span>
                </button>
                <button class="button is-success is-outlined is-hidden" id="executeQueueButton" type="button">
                    <span class="icon-text"><span class="icon"><i class="material-icons">play_arrow</i></span><span>Execute Search</span></span>
                </button>
            </div></div>
            
            <div id="iocQueue" class="field is-grouped is-grouped-multiline mt-4"></div>

            <div class="field"><div class="control"><div class="buttons are-small">
                <button type="button" class="button is-black has-text-info-light" id="historyButton"><span class="icon-text"><span class="icon"><i class="material-icons">history</i></span><span>history</span></span></button>
                <button type="button" class="button is-black has-text-info-light" id="goToButton"><span class="icon-text"><span class="icon"><i class="material-icons">double_arrow</i></span><span>go to</span></span></button>
                <button type="button" class="button is-black has-text-info-light" id="uploadButton"><span class="icon-text"><span class="icon"><i class="material-icons">upload_file</i></span><span>upload</span></span></button>
            </div></div></div>
        </form>`;
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

            requests.forEach((req, idx) => {
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
                            this.renderFailedTab(); // Refresh list
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

            if (button && button.classList.contains('delete')) {
                const index = parseInt(button.dataset.index);
                const type = button.dataset.type;
                const group = this.currentQueue.find(q => q.type === type);
                if (group) {
                    group.matches.splice(index, 1);
                    this.renderQueue();
                }
                return;
            }

            if (!button) return;

            // Tab Switching Logic
            if (button.id === 'searchTabBtn') {
                this.activeTab = 'search';
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

    renderQueue() {
        const queueDiv = document.getElementById('iocQueue');
        const execBtn = document.getElementById('executeQueueButton');
        if (!queueDiv || !execBtn) return;

        queueDiv.innerHTML = "";
        let hasItems = false;

        this.currentQueue.forEach(group => {
            group.matches.forEach((match, idx) => {
                hasItems = true;
                const tagWrapper = document.createElement('div');
                tagWrapper.className = "control";
                tagWrapper.innerHTML = `
                    <div class="tags has-addons">
                        <span class="tag is-dark">${escapeHtml(group.type)}</span>
                        <span class="tag is-info">${escapeHtml(match)}</span>
                        <a class="tag is-delete delete" data-type="${escapeHtml(group.type)}" data-index="${idx}"></a>
                    </div>`;
                queueDiv.appendChild(tagWrapper);
            });
        });

        if (hasItems) execBtn.classList.remove('is-hidden');
        else execBtn.classList.add('is-hidden');
    }

    async handleSearch() {
        const userSearchInput = document.getElementById('userSearch');
        if (!userSearchInput) return;

        const searchText = userSearchInput.value;
        const dontParse = document.getElementById('dontParseCheckbox').checked;
        const viewQueue = document.getElementById('viewQueueCheckbox').checked;

        if (viewQueue && !dontParse) {
            // Extract matches and show queue instead of searching immediately
            this.currentQueue = Object.keys(this.contextualizer.expressions).map(key => ({
                type: key,
                matches: [...new Set(this.contextualizer.getMatches(searchText, key, this.contextualizer.expressions[key]))]
            })).filter(group => group.matches.length > 0);

            this.renderQueue();
            return;
        }

        // Proceed with immediate search if preview is not enabled
        await this.executeStandardSearch(searchText, dontParse);
    }

    async executeStandardSearch(searchText, dontParse) {
        this.isSearching = true;
        this.app.results = [];
        this.app.errors = [];
        this.app.notifications = this.app.notifications.filter(n => n.type !== 'search');

        this.container.innerHTML = "<p>Parsing text... searching...</p><progress class='progress is-link' max='100'></progress>";

        try {
            if (dontParse) {
                await this.processMatches(null, { value: searchText }, null, true);
            } else {
                const allMatches = Object.keys(this.contextualizer.expressions).map(key => ({
                    type: key,
                    matches: [...new Set(this.contextualizer.getMatches(searchText, key, this.contextualizer.expressions[key]))]
                }));

                const promises = [];
                for (let svr of this.app.user.services) {
                    for (let matchPair of allMatches) {
                        if (matchPair.type === "domain" && matchPair.matches.length > 0) {
                            const baseDomains = new Set();
                            for (const domain of matchPair.matches) {
                                const baseDomain = this.contextualizer.extractSecondLevelDomain(domain);
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

        const promises = [];
        for (let svr of this.app.user.services) {
            for (let matchPair of this.currentQueue) {
                // Ensure we only process types supported by the service
                if (svr.type.includes(matchPair.type)) {
                    const route = svr.route_map ? svr.route_map.find(r => r.type === matchPair.type)?.route : "";
                    promises.push(this.processMatches(svr.kind, matchPair, route, false));
                }
            }
        }

        try {
            await Promise.allSettled(promises);
        } finally {
            this.isSearching = false;
            this.currentQueue = [];
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