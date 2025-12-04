import { escapeHtml, makeUnique, isPrivateIP } from './utils.js';

export class SearchController {
    constructor(containerId, app, contextualizer) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.contextualizer = contextualizer;
        this.isSearching = false; // Track search state
        
        // FIX: Attach the listener ONCE here.
        // Since we use event delegation (this.container.addEventListener), 
        // it will automatically work for buttons we add/remove later.
        this.attachFormListeners();
    }

    renderForm() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
            <h1 class="title has-text-info">Search</h1>
            <form>
                <div class="field"><div class="control"><textarea class="textarea" placeholder="feed me..." id="userSearch"></textarea></div></div>
                <div class="field"><div class="control"><label class="checkbox has-text-grey-light"><input type="checkbox" id="dontParseCheckbox"> parse on server</label></div></div>
                <div class="field"><div class="control"><button class="button is-info is-outlined" id="searchButton" type="submit"><span class="icon-text"><span class="icon"><i class="material-icons">search</i></span><span>Search</span></span></button></div></div>
                <div class="field"><div class="control"><div class="buttons are-small">
                    <button type="button" class="button is-black has-text-info-light" id="historyButton"><span class="icon-text"><span class="icon"><i class="material-icons">history</i></span><span>history</span></span></button>
                    <button type="button" class="button is-black has-text-info-light" id="goToButton"><span class="icon-text"><span class="icon"><i class="material-icons">double_arrow</i></span><span>go to</span></span></button>
                    <button type="button" class="button is-black has-text-info-light" id="uploadButton"><span class="icon-text"><span class="icon"><i class="material-icons">upload_file</i></span><span>upload</span></span></button>
                </div></div></div>
            </form>`;
    }

    attachFormListeners() {
        this.container.addEventListener('click', async (event) => {
            const button = event.target.closest('button');
            if (!button) return;
            const targetId = button.id; 

            if (targetId === 'searchButton') {
                event.preventDefault();
                await this.handleSearch();
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
        this.isSearching = true; // Set flag to prevent UI loop from overwriting loader
        this.app.results = [];
        this.app.errors = [];
        
        // Clear old search notifications
        this.app.notifications = this.app.notifications.filter(n => n.type !== 'search');
        
        const userSearchInput = document.getElementById('userSearch');
        if (!userSearchInput) {
            this.isSearching = false;
            return; 
        }
        const searchText = userSearchInput.value;
        const dontParse = document.getElementById('dontParseCheckbox').checked;
        
        // Restored style to is-danger and max=100
        this.container.innerHTML = "<p>Parsing text... searching...</p><progress class='progress is-link' max='100'></progress>";

        try {
            if (dontParse) {
                await this.processMatches(null, { value: searchText }, null, true);
            } else {
                // UPDATED: Pass 'key' (the type) as the second argument to getMatches
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
                            // We don't await here so they run in parallel
                            promises.push(this.processMatches(svr.kind, matchPair, route, false));
                        }
                    }
                }
                await Promise.allSettled(promises);
            }
        } finally {
            this.isSearching = false;
            // Force render at the end to ensure we show "No results" if empty,
            // or clean up the progress bar if results came in.
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
        // If searching and no results yet, DO NOT clear the container (keep the progress bar)
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
            resultsArray.sort((a, b) => (b.matched || 0) - (a.matched || 0));
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