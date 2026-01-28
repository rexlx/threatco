import { escapeHtml } from './utils.js';

export class CaseController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.currentCase = null;
        
        // Pagination & Filter State
        this.currentPage = 1;
        this.itemsPerPage = 50;
        this.currentFilter = 'all'; // Default to showing all cases
    }

    async render() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
            <div class="columns is-vcentered mb-2">
                <div class="column is-narrow">
                    <h1 class="title has-text-info">Case Management</h1>
                </div>
                <div class="column">
                    <div class="field has-addons is-justify-content-center">
                        <div class="control is-expanded" style="max-width: 600px;">
                            <input class="input" type="text" id="caseSearchInput" placeholder="Search for IOCs, Case Names, or Descriptions...">
                        </div>
                        <div class="control">
                            <button class="button is-info" id="btnSearchCases">
                                <span class="icon"><i class="material-icons">search</i></span>
                            </button>
                        </div>
                    </div>
                </div>
                <div class="column is-narrow">
                    <button class="button is-success" id="btnNewCase">
                        <span class="icon"><i class="material-icons">add</i></span>
                        <span>New Case</span>
                    </button>
                </div>
            </div>

            <div class="tabs is-boxed mb-4">
                <ul>
                    <li class="${this.currentFilter === 'all' ? 'is-active' : ''}" data-filter="all">
                        <a><span class="icon is-small"><i class="material-icons">list</i></span><span>All Cases</span></a>
                    </li>
                    <li class="${this.currentFilter === 'user' ? 'is-active' : ''}" data-filter="user">
                        <a><span class="icon is-small"><i class="material-icons">person</i></span><span>User Cases</span></a>
                    </li>
                    <li class="${this.currentFilter === 'auto' ? 'is-active' : ''}" data-filter="auto">
                        <a><span class="icon is-small"><i class="material-icons">smart_toy</i></span><span>Auto Cases</span></a>
                    </li>
                </ul>
            </div>

            <div class="level mb-4">
                <div class="level-left">
                    <div class="level-item">
                        <div class="field has-addons">
                            <p class="control">
                                <button class="button is-small is-info is-light" id="btnExportCases">
                                    <span class="icon is-small"><i class="material-icons">file_download</i></span>
                                    <span>Export CSV</span>
                                </button>
                            </p>
                            <p class="control">
                                <label class="checkbox button is-small has-background-black has-text-grey" title="Delete these cases from the database after a successful export">
                                    <input type="checkbox" id="checkClearAfterExport" class="mr-1"> Clear after export
                                </label>
                            </p>
                        </div>
                    </div>
                    <div class="level-item ml-4">
                        <span class="has-text-grey-light mr-2">Show</span>
                        <div class="select is-small is-dark">
                            <select id="itemsPerPageSelect">
                                <option value="10">10</option>
                                <option value="25">25</option>
                                <option value="50" selected>50</option>
                                <option value="100">100</option>
                            </select>
                        </div>
                        <span class="has-text-grey-light ml-2">per page</span>
                    </div>
                </div>
                <div class="level-right">
                    <div class="level-item">
                        <button class="button is-small is-dark" id="btnPrevPage" disabled>
                            <span class="icon"><i class="material-icons">chevron_left</i></span>
                        </button>
                        <span class="mx-3 has-text-grey-light" id="pageIndicator">Page 1</span>
                        <button class="button is-small is-dark" id="btnNextPage">
                            <span class="icon"><i class="material-icons">chevron_right</i></span>
                        </button>
                    </div>
                </div>
            </div>
            
            <div id="caseListContainer"></div>
            
            <div class="modal" id="newCaseModal">
                <div class="modal-background"></div>
                <div class="modal-card">
                    <header class="modal-card-head">
                        <p class="modal-card-title">Create New Case</p>
                        <button class="delete" aria-label="close"></button>
                    </header>
                    <section class="modal-card-body">
                        <div class="field">
                            <label class="label">Case Name</label>
                            <div class="control"><input class="input" type="text" id="newCaseName" placeholder="e.g. Phishing Campaign Dec 2025"></div>
                        </div>
                        <div class="field">
                            <label class="label">Description</label>
                            <div class="control"><textarea class="textarea" id="newCaseDesc" placeholder="Brief summary..."></textarea></div>
                        </div>
                    </section>
                    <footer class="modal-card-foot">
                        <button class="button is-success" id="btnSaveCase">Create</button>
                        <button class="button" id="btnCancelCase">Cancel</button>
                    </footer>
                </div>
            </div>
        `;

        this.attachMainListeners();
        await this.loadCases();
    }

    attachMainListeners() {
        // --- Tab Filtering Logic ---
        this.container.querySelectorAll('.tabs li').forEach(tab => {
            tab.onclick = () => {
                this.currentFilter = tab.dataset.filter;
                this.currentPage = 1;
                this.render(); // Re-render to update UI state
            };
        });

        // --- Export Logic ---
        document.getElementById('btnExportCases').onclick = () => {
            const clear = document.getElementById('checkClearAfterExport').checked;
            if (clear && !confirm("Warning: This will PERMANENTLY DELETE all cases in the current view after downloading. Proceed?")) {
                return;
            }
            
            // Redirecting to the handler URL triggers the browser download
            const exportUrl = `/cases/export?type=${this.currentFilter}&clear=${clear}`;
            window.location.href = exportUrl;

            // If we cleared the cases, refresh the list after a short delay
            if (clear) {
                setTimeout(() => this.loadCases(), 2000);
            }
        };

        // --- Create Case Modal Logic ---
        const modal = document.getElementById('newCaseModal');
        const closeModal = () => modal.classList.remove('is-active');

        document.getElementById('btnNewCase').onclick = () => modal.classList.add('is-active');
        document.getElementById('btnCancelCase').onclick = closeModal;
        modal.querySelector('.delete').onclick = closeModal;

        // --- Search Logic ---
        const runSearch = async () => {
            const query = document.getElementById('caseSearchInput').value.trim();
            if (!query) {
                this.currentPage = 1;
                return this.loadCases();
            }
            await this.searchCases(query);
        };
        document.getElementById('btnSearchCases').onclick = runSearch;
        document.getElementById('caseSearchInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') runSearch();
        });

        // --- Pagination Logic ---
        document.getElementById('itemsPerPageSelect').onchange = (e) => {
            this.itemsPerPage = parseInt(e.target.value);
            this.currentPage = 1;
            this.loadCases();
        };

        document.getElementById('btnPrevPage').onclick = () => {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.loadCases();
            }
        };

        document.getElementById('btnNextPage').onclick = () => {
            this.currentPage++;
            this.loadCases();
        };

        // --- Save Case Logic ---
        document.getElementById('btnSaveCase').onclick = async () => {
            const name = document.getElementById('newCaseName').value;
            const desc = document.getElementById('newCaseDesc').value;
            if (!name) return alert("Name is required");

            try {
                const res = await this.app._fetch('/cases/create', {
                    method: 'POST',
                    body: JSON.stringify({ name, description: desc, is_auto: false })
                });
                if (!res.ok) throw new Error(await res.text());
                closeModal();
                this.currentPage = 1;
                await this.loadCases();
            } catch (e) {
                alert("Error creating case: " + e.message);
            }
        };
    }

    async searchCases(query) {
        const container = document.getElementById('caseListContainer');
        container.innerHTML = '<div class="loader"></div>';
        this.updatePaginationControls(0, true); 

        try {
            const res = await this.app._fetch(`/cases/search?q=${encodeURIComponent(query)}`);
            const cases = await res.json();
            this.renderCaseList(cases);
        } catch (e) {
            container.innerHTML = `<p class="has-text-danger">Search failed: ${e.message}</p>`;
        }
    }

    async loadCases() {
    const container = document.getElementById('caseListContainer');
    container.innerHTML = '<div class="loader"></div>';
    
    try {
        const res = await this.app._fetch(`/cases/list?limit=${this.itemsPerPage}&page=${this.currentPage}&type=${this.currentFilter}`);
        let cases = await res.json();
        
        if (cases === null) {
            cases = [];
        }
        
        this.renderCaseList(cases);
        this.updatePaginationControls(cases.length); // This will now receive 0 instead of crashing

    } catch (e) {
        container.innerHTML = `<p class="has-text-danger">Error loading cases: ${e.message}</p>`;
    }
}

    updatePaginationControls(resultCount, isSearch = false) {
        const prevBtn = document.getElementById('btnPrevPage');
        const nextBtn = document.getElementById('btnNextPage');
        const indicator = document.getElementById('pageIndicator');
        const select = document.getElementById('itemsPerPageSelect');

        if (isSearch) {
             prevBtn.disabled = true;
             nextBtn.disabled = true;
             select.disabled = true;
             indicator.textContent = "Search Results";
             return;
        }

        select.disabled = false;
        indicator.textContent = `Page ${this.currentPage}`;
        prevBtn.disabled = (this.currentPage <= 1);
        nextBtn.disabled = (resultCount < this.itemsPerPage);
    }

    renderCaseList(cases) {
        const container = document.getElementById('caseListContainer');
        container.innerHTML = '';

        if (!cases || cases.length === 0) {
            container.innerHTML = '<div class="notification is-dark has-text-centered">No cases found in this category.</div>';
            return;
        }

        cases.forEach(c => {
            const statusColor = c.status === 'Open' ? 'is-primary' : 'is-warning';
            
            let desc = c.description || 'No description';
            if (desc.length > 250) {
                desc = desc.substring(0, 250) + '...';
            }

            const box = document.createElement('div');
            box.className = 'box has-background-black has-text-light mb-3';
            box.style.cursor = 'pointer';
            box.style.borderLeft = c.status === 'Open' ? '4px solid #158c95ff' : '4px solid rgb(83, 87, 106)';
            
            box.onclick = () => this.openCase(c);

            const iocCount = (c.ioc_count !== undefined) ? c.ioc_count : (c.iocs ? c.iocs.length : 0);
            
            // Add a badge for Automated cases
            const autoBadge = c.is_auto ? '<span class="tag is-info is-light is-small ml-2"><span class="icon is-small mr-1"><i class="material-icons" style="font-size:14px;">smart_toy</i></span>AUTO</span>' : '';

            box.innerHTML = `
                <article class="media is-vcentered">
                    <div class="media-left">
                        <span class="tag ${statusColor}">${escapeHtml(c.status)}</span>
                    </div>
                    <div class="media-content">
                        <div class="content">
                            <p>
                                <strong class="has-text-info is-size-5">${escapeHtml(c.name)}</strong> 
                                ${autoBadge}
                                <span class="has-text-info-light is-size-7 ml-2">by ${escapeHtml(c.created_by)}</span>
                                <br>
                                <span class="has-text-light is-size-7" style="word-break: break-word; display: block; margin-top: 4px;">
                                    ${escapeHtml(desc)}
                                </span>
                            </p>
                        </div>
                    </div>
                    <div class="media-right has-text-right">
                        <small class="has-text-grey is-size-7">${new Date(c.created_at).toLocaleDateString()}</small>
                        <br>
                        <span class="tag is-dark is-rounded mt-1">${iocCount} IOCs</span>
                    </div>
                </article>
            `;
            container.appendChild(box);
        });
    }

    async openCase(cSummary) {
        this.container.innerHTML = `
            <div class="mb-4">
                <button class="button is-small is-dark" id="btnBackList"><span class="icon"><i class="material-icons">arrow_back</i></span><span>Back to Cases</span></button>
            </div>
            <div class="has-text-centered p-6">
                <div class="loader" style="height: 50px; width: 50px; border-width: 4px; display:inline-block;"></div>
                <p class="mt-4 has-text-grey">Loading full case details...</p>
            </div>
        `;
        document.getElementById('btnBackList').onclick = () => this.render();

        try {
            const res = await this.app._fetch(`/cases/get?id=${cSummary.id}`);
            if (!res.ok) throw new Error(await res.text());
            
            const c = await res.json();
            this.currentCase = c;
            const isClosed = c.status === 'Closed';

            this.container.innerHTML = `
                <div class="mb-4">
                    <button class="button is-small is-dark" id="btnBackList"><span class="icon"><i class="material-icons">arrow_back</i></span><span>Back to Cases</span></button>
                </div>
                <div class="box has-background-custom">
                    <div class="level">
                        <div class="level-left" style="min-width: 0; flex-shrink: 1;">
                            <div style="max-width: 600px;">
                                <h2 class="title is-3 has-text-white" style="word-break: break-word;">${escapeHtml(c.name)}</h2>
                                <p class="subtitle is-6 has-text-grey-light">Created by ${escapeHtml(c.created_by)} on ${new Date(c.created_at).toLocaleString()} ${c.is_auto ? '(Automated)' : ''}</p>
                            </div>
                        </div>
                        <div class="level-right">
                            <div class="buttons">
                                <button class="button ${isClosed ? 'is-info' : 'is-warning'}" id="btnToggleStatus">
                                    <span class="icon"><i class="material-icons">${isClosed ? 'unarchive' : 'archive'}</i></span>
                                    <span>${isClosed ? 'Reopen Case' : 'Close Case'}</span>
                                </button>
                                <button class="button is-danger" id="btnDeleteCase">
                                    <span class="icon"><i class="material-icons">delete</i></span>
                                    <span>Delete Case</span>
                                </button>
                            </div>
                        </div>
                    </div>
                    <hr class="has-background-grey-dark">
                    
                    <div class="columns">
                        <div class="column is-two-thirds">
                            <h4 class="title is-5 has-text-info">IOCs</h4>
                            
                            <div class="field has-addons mb-3">
                                <div class="control is-expanded">
                                    <input class="input is-small" type="text" id="inputAddIOC" placeholder="Add IP, Domain, Hash...">
                                </div>
                                <div class="control">
                                    <button class="button is-info is-small" id="btnAddIOC">Add</button>
                                </div>
                            </div>

                            <div class="level is-mobile has-background-black-ter p-2" style="border-radius:4px; margin-bottom: 0.5rem;">
                                <div class="level-left">
                                    <label class="checkbox has-text-grey-light ml-2">
                                        <input type="checkbox" id="checkAllIOCs"> Select All
                                    </label>
                                </div>
                                <div class="level-right">
                                    <button class="button is-small is-warning is-light" id="btnOpenMispModal">
                                        <span class="icon is-small"><i class="material-icons">cloud_upload</i></span>
                                        <span>Send Selected to MISP</span>
                                    </button>
                                </div>
                            </div>

                            <div class="box has-background-dark p-2" id="iocListContainer" style="max-height: 400px; overflow-y: auto;">
                                ${(c.iocs || []).map(ioc => `
                                    <div class="level is-mobile mb-1 p-1" style="border-bottom: 1px solid #333;">
                                        <div class="level-left">
                                            <label class="checkbox mr-2">
                                                <input type="checkbox" class="ioc-checkbox" value="${escapeHtml(ioc)}">
                                            </label>
                                            <span class="has-text-light is-family-monospace">${escapeHtml(ioc)}</span>
                                        </div>
                                        <div class="level-right">
                                            <button class="delete is-small delete-ioc" data-val="${escapeHtml(ioc)}"></button>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>

                            <h4 class="title is-5 has-text-info mt-5">Comments</h4>
                            <div id="commentList" class="mb-4" style="max-height: 300px; overflow-y: auto;">
                                ${(c.comments || []).map(cm => `
                                    <article class="media">
                                        <div class="media-content">
                                            <div class="content">
                                                <p class="has-text-light">
                                                    <strong>${escapeHtml(cm.user)}</strong> <small>${new Date(cm.created_at).toLocaleString()}</small>
                                                    <br>
                                                    ${escapeHtml(cm.text)}
                                                </p>
                                            </div>
                                        </div>
                                    </article>
                                `).join('')}
                            </div>
                            <article class="media">
                                <div class="media-content">
                                    <div class="field">
                                        <p class="control">
                                            <textarea class="textarea has-background-dark has-text-white" id="inputComment" rows="2" placeholder="Add a comment..."></textarea>
                                        </p>
                                    </div>
                                    <div class="field">
                                        <p class="control">
                                            <button class="button is-info is-small" id="btnPostComment">Post comment</button>
                                        </p>
                                    </div>
                                </div>
                            </article>
                        </div>

                        <div class="column">
                            <div class="notification is-dark">
                                <h4 class="title is-5 has-text-warning">Case Info</h4>
                                <p class="has-text-grey-light block">${escapeHtml(c.description)}</p>
                                <p><strong>Status:</strong> ${escapeHtml(c.status)}</p>
                                <p><strong>ID:</strong> <span class="is-family-code is-size-7">${c.id}</span></p>
                                <p><strong>Type:</strong> ${c.is_auto ? 'Automated System Case' : 'User Created'}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="modal" id="mispModal">
                    <div class="modal-background"></div>
                    <div class="modal-card">
                        <header class="modal-card-head has-background-warning">
                            <p class="modal-card-title has-text-black">Send to MISP</p>
                            <button class="delete" aria-label="close"></button>
                        </header>
                        <section class="modal-card-body has-background-dark has-text-light">
                            <div class="notification is-warning is-light mb-4">
                                You are about to send <strong id="mispCountDisplay">0</strong> IOCs to MISP.
                            </div>
                            
                            <div class="field">
                                <label class="label has-text-light">Event Title / Info</label>
                                <div class="control">
                                    <input class="input has-background-black-ter has-text-white" type="text" id="mispEventTitle">
                                </div>
                                <p class="help has-text-grey">This will be the title of the MISP Event.</p>
                            </div>

                            <div class="field">
                                <label class="label has-text-light">Tags</label>
                                <div class="control">
                                    <input class="input has-background-black-ter has-text-white" type="text" id="mispTags" value="Application:Threatco, tlp:amber">
                                </div>
                                <p class="help has-text-grey">Comma separated tags (e.g. "phishing, apt28").</p>
                            </div>

                            <label class="label has-text-light">Selected IOCs Preview</label>
                            <div class="box has-background-black-ter p-2" id="mispPreviewList" style="max-height: 150px; overflow-y: auto; border: 1px solid #444;"></div>
                        </section>
                        <footer class="modal-card-foot has-background-black-ter" style="border-top: 1px solid #444;">
                            <button class="button is-warning" id="btnConfirmMisp">
                                <span class="icon"><i class="material-icons">cloud_upload</i></span>
                                <span>Send Events</span>
                            </button>
                            <button class="button is-dark" id="btnCancelMisp">Cancel</button>
                        </footer>
                    </div>
                </div>
            `;

            this.attachDetailListeners(c);

        } catch (e) {
            this.container.innerHTML = `<div class="notification is-warning">Error loading case details: ${e.message}</div>`;
        }
    }

    attachDetailListeners(c) {
        document.getElementById('btnBackList').onclick = () => this.render();

        const mispModal = document.getElementById('mispModal');
        const closeMisp = () => mispModal.classList.remove('is-active');
        document.getElementById('btnCancelMisp').onclick = closeMisp;
        mispModal.querySelector('.delete').onclick = closeMisp;

        document.getElementById('btnToggleStatus').onclick = async () => {
            const newStatus = this.currentCase.status === 'Open' ? 'Closed' : 'Open';
            this.currentCase.status = newStatus;
            await this.updateCase();
        };

        document.getElementById('btnDeleteCase').onclick = async () => {
            if (!confirm("Are you sure you want to permanently delete this case?")) return;
            try {
                const res = await this.app._fetch('/cases/delete', { method: 'POST', body: JSON.stringify({ id: c.id }) });
                if (!res.ok) throw new Error(await res.text());
                this.render();
            } catch (e) { alert("Delete failed: " + e.message); }
        };

        document.getElementById('btnAddIOC').onclick = () => {
            const val = document.getElementById('inputAddIOC').value.trim();
            if (!val) return;
            if (!this.currentCase.iocs) this.currentCase.iocs = [];
            if (!this.currentCase.iocs.includes(val)) {
                this.currentCase.iocs.push(val);
                this.updateCase();
            }
        };

        document.getElementById('checkAllIOCs').onchange = (e) => {
            document.querySelectorAll('.ioc-checkbox').forEach(cb => cb.checked = e.target.checked);
        };

        document.getElementById('iocListContainer').onclick = (e) => {
            if (e.target.classList.contains('delete-ioc')) {
                const val = e.target.dataset.val;
                this.currentCase.iocs = this.currentCase.iocs.filter(i => i !== val);
                this.updateCase();
            }
        };

        document.getElementById('btnPostComment').onclick = async () => {
            const text = document.getElementById('inputComment').value.trim();
            if (!text) return;
            const comment = { user: this.app.user.email, text: text, created_at: new Date().toISOString() };
            if (!this.currentCase.comments) this.currentCase.comments = [];
            this.currentCase.comments.push(comment);
            await this.updateCase();
        };

        document.getElementById('btnOpenMispModal').onclick = () => {
            const selected = Array.from(document.querySelectorAll('.ioc-checkbox:checked')).map(cb => cb.value);
            if (selected.length === 0) return alert("No IOCs selected.");

            document.getElementById('mispCountDisplay').textContent = selected.length;
            document.getElementById('mispEventTitle').value = `Case: ${this.currentCase.name}`;
            document.getElementById('mispPreviewList').innerHTML = selected.map(s => `<span class="tag is-dark m-1">${escapeHtml(s)}</span>`).join('');

            document.getElementById('mispModal').classList.add('is-active');

            const confirmBtn = document.getElementById('btnConfirmMisp');
            const newBtn = confirmBtn.cloneNode(true);
            confirmBtn.parentNode.replaceChild(newBtn, confirmBtn);
            newBtn.onclick = () => this.sendToMisp(selected);
        };
    }

    async sendToMisp(selectedIOCs) {
        const title = document.getElementById('mispEventTitle').value;
        const tagsVal = document.getElementById('mispTags').value;
        const btn = document.getElementById('btnConfirmMisp');

        if (!title) return alert("Event Title is required.");
        btn.classList.add('is-loading');

        const attributes = selectedIOCs.map(ioc => {
            let type = "other";
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ioc)) type = "ip-src";
            else if (/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/.test(ioc)) type = "domain";
            else if (ioc.length === 32) type = "md5";
            else if (ioc.length === 64) type = "sha256";
            return { value: ioc, type: type };
        });

        const payload = {
            event_info: title,
            tag_name: tagsVal,
            attributes: attributes
        };

        try {
            const res = await this.app._fetch('/misp/workflow/batch', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (!res.ok) throw new Error(await res.text());
            const json = await res.json();
            alert(`Success! Created MISP Event: ${json.message}`);
            document.getElementById('mispModal').classList.remove('is-active');
        } catch (e) {
            console.error(e);
            alert("Failed to send batch to MISP: " + e.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    async updateCase() {
        try {
            const res = await this.app._fetch('/cases/update', {
                method: 'POST',
                body: JSON.stringify(this.currentCase)
            });
            if (!res.ok) throw new Error(await res.text());
            this.openCase({ id: this.currentCase.id }); 
        } catch (e) {
            alert("Update failed: " + e.message);
        }
    }
}