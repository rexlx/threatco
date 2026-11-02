import { escapeHtml } from './utils.js';

export class CaseController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.currentCase = null;

        // Pagination & Filter State
        this.currentPage = 1;
        this.itemsPerPage = 50;
        this.currentFilter = 'all';

        // NEW: Track selected case IDs for grouping
        this.selectedCaseIds = new Set();

        // Cache user list for case assignment
        this.usersList = [];
    }

    async fetchUsers() {
        if (this.usersList && this.usersList.length > 0) {
            return this.usersList;
        }
        try {
            const res = await this.app._fetch('/getusers');
            if (res.ok) {
                this.usersList = await res.json() || [];
            } else {
                this.usersList = [];
            }
        } catch (e) {
            console.error("Failed to fetch users:", e);
            this.usersList = [];
        }
        return this.usersList;
    }

    getPriorityBadge(priority) {
        const p = priority || 'Medium';
        let cls = 'priority-medium';
        if (p === 'Critical') cls = 'priority-critical';
        else if (p === 'High') cls = 'priority-high';
        else if (p === 'Medium') cls = 'priority-medium';
        else if (p === 'Low') cls = 'priority-low';
        return `<span class="priority-pill ${cls}">[${escapeHtml(p)}]</span>`;
    }

    async render() {
        this.container.classList.remove('is-hidden');
        this.container.classList.remove('has-background-custom');
        this.container.classList.add('has-background-black');

        this.container.innerHTML = `
            <!-- Sticky Cases Header / Navigation Bar -->
            <div class="users-nav-bar cases-nav-bar mb-3" id="cases-top">
                <div class="users-nav-left">
                    <div class="users-nav-title-group">
                        <span class="users-nav-title">Case Management</span>
                        <span class="tag is-info is-dark is-rounded charts-count-badge" id="caseCountBadge">Page ${this.currentPage}</span>
                    </div>
                </div>

                <div class="users-nav-right">
                    <div class="field has-addons mb-0">
                        <div class="control">
                            <input class="input is-small terminal-search" type="text" id="caseSearchInput" placeholder="Search IOCs, name, desc..." autocomplete="off">
                        </div>
                        <div class="control">
                            <button class="button is-small is-dark" id="btnSearchCases" type="button" title="Search cases">
                                <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">search</i></span>
                            </button>
                        </div>
                    </div>
                    <button class="button is-small terminal-action-btn modal-btn-case" id="btnNewCase" type="button" title="Create a new case">
                        <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">add</i></span>
                        <span>New Case</span>
                    </button>
                    <button class="button is-small terminal-action-btn" id="btnGroupSelected" type="button" title="Merge IOCs from selected cases into a new case">
                        <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">layers</i></span>
                        <span>Group Selected</span>
                    </button>
                    <button type="button" class="button is-small is-dark is-outlined" id="btnRefreshCases" title="Refresh cases">↻ Refresh</button>
                </div>
            </div>

            <!-- Filter & Controls Sub-bar -->
            <div class="box p-3 mb-3 cases-filter-subbar">
                <div class="is-flex is-justify-content-between is-align-items-center is-flex-wrap-wrap" style="gap: 0.75rem;">
                    <!-- Filter Buttons -->
                    <div class="buttons are-small mb-0" id="caseFilterButtons">
                        <button class="button terminal-btn ${this.currentFilter === 'all' ? 'terminal-btn-active' : ''}" data-filter="all">All Cases</button>
                        <button class="button terminal-btn ${this.currentFilter === 'user' ? 'terminal-btn-active' : ''}" data-filter="user">User Cases</button>
                        <button class="button terminal-btn ${this.currentFilter === 'auto' ? 'terminal-btn-active' : ''}" data-filter="auto">Auto Cases</button>
                        <button class="button terminal-btn ${this.currentFilter === 'newest' ? 'terminal-btn-active' : ''}" data-filter="newest">Newest</button>
                        <button class="button terminal-btn ${this.currentFilter === 'most_comments' ? 'terminal-btn-active' : ''}" data-filter="most_comments">Most Comments</button>
                        <button class="button terminal-btn ${this.currentFilter === 'most_iocs' ? 'terminal-btn-active' : ''}" data-filter="most_iocs">Most IOCs</button>
                        <button class="button terminal-btn ${this.currentFilter === 'priority' ? 'terminal-btn-active' : ''}" data-filter="priority">By Priority</button>
                    </div>

                    <!-- Export & Pagination Controls -->
                    <div class="is-flex is-align-items-center is-flex-wrap-wrap" style="gap: 0.75rem;">
                        <div class="field has-addons mb-0">
                            <p class="control">
                                <button class="button is-small terminal-action-btn" id="btnExportCases" type="button" title="Export cases as CSV">
                                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">file_download</i></span>
                                    <span>Export CSV</span>
                                </button>
                            </p>
                            <p class="control">
                                <label class="checkbox button is-small terminal-action-btn" title="Delete these cases from the database after a successful export" style="cursor: pointer;">
                                    <input type="checkbox" id="checkClearAfterExport" class="mr-1"> Clear after export
                                </label>
                            </p>
                        </div>

                        <div class="is-flex is-align-items-center" style="gap: 0.35rem;">
                            <span class="is-size-7 has-text-grey" style="font-family: 'IBMPlexMono', monospace;">Show</span>
                            <div class="select is-small terminal-select">
                                <select id="itemsPerPageSelect">
                                    <option value="10" ${this.itemsPerPage === 10 ? 'selected' : ''}>10</option>
                                    <option value="25" ${this.itemsPerPage === 25 ? 'selected' : ''}>25</option>
                                    <option value="50" ${this.itemsPerPage === 50 ? 'selected' : ''}>50</option>
                                    <option value="100" ${this.itemsPerPage === 100 ? 'selected' : ''}>100</option>
                                </select>
                            </div>
                        </div>

                        <div class="is-flex is-align-items-center" style="gap: 0.35rem;">
                            <button class="button is-small terminal-action-btn" id="btnPrevPage" disabled title="Previous page">
                                <span class="icon is-small"><i class="material-icons">chevron_left</i></span>
                            </button>
                            <span class="is-size-7 px-2 has-text-grey-light" id="pageIndicator" style="font-family: 'IBMPlexMono', monospace;">Page ${this.currentPage}</span>
                            <button class="button is-small terminal-action-btn" id="btnNextPage" title="Next page">
                                <span class="icon is-small"><i class="material-icons">chevron_right</i></span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Cases Terminal Window -->
            <div class="users-window cases-window" id="casesViewer">
                <div class="terminal-titlebar">
                    <div class="terminal-dots">
                        <span class="terminal-dot dot-close"></span>
                        <span class="terminal-dot dot-min"></span>
                        <span class="terminal-dot dot-expand"></span>
                    </div>
                    <div class="terminal-title">
                        <span class="terminal-status-dot"></span>
                        <span>cases.registry.threatco</span>
                    </div>
                    <div class="terminal-actions">
                        <span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>DATABASE ONLINE</span>
                    </div>
                </div>

                <div class="terminal-table-container">
                    <table class="terminal-table users-table cases-table">
                        <thead>
                            <tr>
                                <th class="cases-th-select"><input type="checkbox" id="checkAllCases" title="Select all visible cases"></th>
                                <th class="cases-th-status">STATUS</th>
                                <th class="cases-th-priority">PRIORITY</th>
                                <th class="cases-th-title">CASE &amp; SUMMARY</th>
                                <th class="cases-th-assignee">ASSIGNED TO</th>
                                <th class="cases-th-iocs">IOCS</th>
                                <th class="cases-th-date">DATE</th>
                                <th class="cases-th-actions">ACTIONS</th>
                            </tr>
                        </thead>
                        <tbody id="caseListContainer">
                            <tr class="terminal-table-row">
                                <td colspan="8" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                                    <p class="has-text-info mb-2">Loading cases from database...</p>
                                    <progress class="progress is-small is-info" max="100"></progress>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="terminal-statusbar">
                    <span id="caseStatusbarText">Showing page ${this.currentPage} &bull; Filter: ${this.currentFilter}</span>
                    <span class="is-pulled-right">threatco cases &bull; incident response</span>
                </div>
            </div>

            <!-- Create New Case Modal (Terminal Modal) -->
            <div class="modal terminal-modal" id="newCaseModal">
                <div class="modal-background"></div>
                <div class="modal-card details-modal-card" style="max-width: 620px;">
                    <header class="modal-card-head terminal-titlebar details-modal-titlebar">
                        <div class="terminal-dots">
                            <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                            <span class="terminal-dot dot-min"></span>
                            <span class="terminal-dot dot-expand"></span>
                        </div>
                        <div class="terminal-title details-modal-title-wrap">
                            <span class="terminal-status-dot details-status-dot"></span>
                            <span class="modal-card-title details-modal-title">Create New Case</span>
                        </div>
                        <div class="terminal-actions details-modal-actions">
                            <span class="system-status-pill details-status-pill">
                                <span class="status-indicator-dot dot-details"></span>CASE REGISTRY
                            </span>
                            <button class="button is-small terminal-action-btn modal-close-btn delete" aria-label="close" title="Close modal">
                                <span class="icon is-small"><i class="material-icons">close</i></span>
                            </button>
                        </div>
                    </header>
                    <section class="modal-card-body details-modal-body">
                        <div class="modal-subform-container">
                            <div class="field mb-3">
                                <label class="label terminal-form-label">Case Name *</label>
                                <div class="control">
                                    <input class="input terminal-input" type="text" id="newCaseName" placeholder="e.g. Phishing Campaign Dec 2025">
                                </div>
                            </div>
                            <div class="field mb-3">
                                <label class="label terminal-form-label">Priority</label>
                                <div class="control">
                                    <div class="select is-fullwidth terminal-select">
                                        <select id="newCasePriority">
                                            <option value="Low">Low</option>
                                            <option value="Medium" selected>Medium</option>
                                            <option value="High">High</option>
                                            <option value="Critical">Critical</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <div class="field mb-3">
                                <label class="label terminal-form-label">Assign To</label>
                                <div class="control">
                                    <div class="select is-fullwidth terminal-select">
                                        <select id="newCaseAssignee">
                                            <option value="">Unassigned</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <div class="field mb-3">
                                <label class="label terminal-form-label">Description</label>
                                <div class="control">
                                    <textarea class="textarea terminal-textarea" id="newCaseDesc" rows="3" placeholder="Brief summary..."></textarea>
                                </div>
                            </div>
                        </div>
                    </section>
                    <footer class="modal-card-foot details-modal-foot">
                        <div class="details-foot-left">
                            <button type="button" class="button terminal-action-btn modal-btn-case" id="btnSaveCase">
                                <span class="icon is-small"><i class="material-icons">save</i></span>
                                <span>Create Case</span>
                            </button>
                        </div>
                        <div class="details-foot-right">
                            <button type="button" class="button terminal-action-btn" id="btnCancelCase">Cancel</button>
                        </div>
                    </footer>
                </div>
            </div>
        `;

        this.attachMainListeners();
        await this.loadCases();
    }

    attachMainListeners() {
        // --- Tab Filtering Logic ---
        const filterBtns = this.container.querySelectorAll('#caseFilterButtons button');
        filterBtns.forEach(btn => {
            btn.onclick = () => {
                this.currentFilter = btn.dataset.filter;
                this.currentPage = 1;
                this.selectedCaseIds.clear(); // Clear selections when changing view
                filterBtns.forEach(b => b.classList.remove('terminal-btn-active'));
                btn.classList.add('terminal-btn-active');
                this.loadCases();
            };
        });

        // --- Refresh Button Logic ---
        const refreshBtn = document.getElementById('btnRefreshCases');
        if (refreshBtn) {
            refreshBtn.onclick = async () => {
                refreshBtn.classList.add('is-loading');
                await this.loadCases();
                refreshBtn.classList.remove('is-loading');
            };
        }

        // --- Group Selected Logic ---
        const groupBtn = document.getElementById('btnGroupSelected');
        if (groupBtn) {
            groupBtn.onclick = () => this.handleGroupSelected();
        }

        // --- Export Logic ---
        const exportBtn = document.getElementById('btnExportCases');
        if (exportBtn) {
            exportBtn.onclick = () => {
                const clearCheck = document.getElementById('checkClearAfterExport');
                const clear = clearCheck ? clearCheck.checked : false;
                if (clear && !confirm("Warning: This will PERMANENTLY DELETE all cases in the current view after downloading. Proceed?")) {
                    return;
                }
                const exportUrl = `/cases/export?type=${this.currentFilter}&clear=${clear}`;
                window.location.href = exportUrl;
                if (clear) {
                    setTimeout(() => this.loadCases(), 2000);
                }
            };
        }

        // --- Create Case Modal Logic ---
        const modal = document.getElementById('newCaseModal');
        const closeModal = () => {
            if (modal) modal.classList.remove('is-active');
            // Reset modal save button to default behavior
            const saveBtn = document.getElementById('btnSaveCase');
            if (saveBtn) saveBtn.onclick = () => this.saveNewCase();
        };

        const newCaseBtn = document.getElementById('btnNewCase');
        if (newCaseBtn) {
            newCaseBtn.onclick = async () => {
                document.getElementById('newCaseName').value = '';
                document.getElementById('newCaseDesc').value = '';
                document.getElementById('newCasePriority').value = 'Medium';

                const users = await this.fetchUsers();
                const assigneeSelect = document.getElementById('newCaseAssignee');
                if (assigneeSelect) {
                    assigneeSelect.innerHTML = '<option value="">Unassigned</option>' +
                        users.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('');
                }
                modal.classList.add('is-active');
            };
        }

        if (modal) {
            modal.querySelectorAll('.delete, .modal-background, #btnCancelCase, .modal-close-dot, .modal-close-btn').forEach(el => {
                el.onclick = closeModal;
            });
        }

        // --- Search Logic ---
        const runSearch = async () => {
            const searchInput = document.getElementById('caseSearchInput');
            const query = searchInput ? searchInput.value.trim() : '';
            if (!query) {
                this.currentPage = 1;
                return this.loadCases();
            }
            await this.searchCases(query);
        };

        const searchBtn = document.getElementById('btnSearchCases');
        if (searchBtn) searchBtn.onclick = runSearch;

        const searchInput = document.getElementById('caseSearchInput');
        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') runSearch();
            });
        }

        // --- Pagination Logic ---
        const perPageSelect = document.getElementById('itemsPerPageSelect');
        if (perPageSelect) {
            perPageSelect.onchange = (e) => {
                this.itemsPerPage = parseInt(e.target.value, 10);
                this.currentPage = 1;
                this.loadCases();
            };
        }

        const prevBtn = document.getElementById('btnPrevPage');
        if (prevBtn) {
            prevBtn.onclick = () => {
                if (this.currentPage > 1) {
                    this.currentPage--;
                    this.loadCases();
                }
            };
        }

        const nextBtn = document.getElementById('btnNextPage');
        if (nextBtn) {
            nextBtn.onclick = () => {
                this.currentPage++;
                this.loadCases();
            };
        }

        // --- Save Case Logic (Default) ---
        const saveBtn = document.getElementById('btnSaveCase');
        if (saveBtn) saveBtn.onclick = () => this.saveNewCase();
    }

    /**
     * Helper to create a case, optionally with a list of IOCs.
     */
    async saveNewCase(predefinedIocs = []) {
        const name = document.getElementById('newCaseName')?.value || '';
        const desc = document.getElementById('newCaseDesc')?.value || '';
        const priority = document.getElementById('newCasePriority')?.value || 'Medium';
        const assigned_to = document.getElementById('newCaseAssignee')?.value || '';
        if (!name) return alert("Name is required");

        try {
            const res = await this.app._fetch('/cases/create', {
                method: 'POST',
                body: JSON.stringify({ name, description: desc, is_auto: false, priority, assigned_to })
            });
            if (!res.ok) throw new Error(await res.text());

            const newCase = await res.json();

            // If grouping, update the newly created case with aggregated IOCs
            if (predefinedIocs.length > 0) {
                newCase.iocs = predefinedIocs;
                await this.app._fetch('/cases/update', {
                    method: 'POST',
                    body: JSON.stringify(newCase)
                });
            }

            const modal = document.getElementById('newCaseModal');
            if (modal) modal.classList.remove('is-active');
            this.currentPage = 1;
            this.selectedCaseIds.clear();
            await this.loadCases();
        } catch (e) {
            alert("Error creating case: " + e.message);
        }
    }

    /**
     * Logic for grouping multiple selected cases.
     */
    async handleGroupSelected() {
        if (this.selectedCaseIds.size < 2) {
            return alert("Please select at least two cases to group.");
        }

        const ids = Array.from(this.selectedCaseIds);
        const aggregatedIocs = new Set();
        const btn = document.getElementById('btnGroupSelected');

        if (btn) btn.classList.add('is-loading');

        try {
            // Fetch full details for each selected case to gather IOCs
            for (const id of ids) {
                const res = await this.app._fetch(`/cases/get?id=${id}`);
                if (res.ok) {
                    const c = await res.json();
                    if (c.iocs) {
                        c.iocs.forEach(ioc => aggregatedIocs.add(ioc));
                    }
                }
            }

            if (btn) btn.classList.remove('is-loading');

            // Set up modal for creation
            const nameEl = document.getElementById('newCaseName');
            const descEl = document.getElementById('newCaseDesc');
            if (nameEl) nameEl.value = `Grouped Case - ${new Date().toLocaleDateString()}`;
            if (descEl) descEl.value = `Aggregated IOCs from ${ids.length} related cases.`;

            // Override modal save button for this specific operation
            const saveBtn = document.getElementById('btnSaveCase');
            if (saveBtn) {
                saveBtn.onclick = () => this.saveNewCase(Array.from(aggregatedIocs));
            }
            const modal = document.getElementById('newCaseModal');
            if (modal) modal.classList.add('is-active');

        } catch (e) {
            if (btn) btn.classList.remove('is-loading');
            alert("Failed to group cases: " + e.message);
        }
    }

    async searchCases(query) {
        const container = document.getElementById('caseListContainer');
        if (!container) return;
        container.innerHTML = `
            <tr class="terminal-table-row">
                <td colspan="8" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                    <p class="has-text-info mb-2">Searching cases...</p>
                    <progress class="progress is-small is-info" max="100"></progress>
                </td>
            </tr>
        `;
        this.updatePaginationControls(0, true);

        try {
            const res = await this.app._fetch(`/cases/search?q=${encodeURIComponent(query)}`);
            const cases = await res.json();
            this.renderCaseList(cases || []);
        } catch (e) {
            container.innerHTML = `
                <tr class="terminal-table-row">
                    <td colspan="8" class="terminal-placeholder has-text-danger" style="text-align: center; padding: 2rem;">
                        Search failed: ${escapeHtml(e.message)}
                    </td>
                </tr>
            `;
        }
    }

    async loadCases() {
        const container = document.getElementById('caseListContainer');
        if (!container) return;
        container.innerHTML = `
            <tr class="terminal-table-row">
                <td colspan="8" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                    <p class="has-text-info mb-2">Loading cases from database...</p>
                    <progress class="progress is-small is-info" max="100"></progress>
                </td>
            </tr>
        `;

        try {
            const res = await this.app._fetch(`/cases/list?limit=${this.itemsPerPage}&page=${this.currentPage}&type=${this.currentFilter}`);
            let cases = await res.json();

            if (cases === null) {
                cases = [];
            }

            this.renderCaseList(cases);
            this.updatePaginationControls(cases.length);

        } catch (e) {
            container.innerHTML = `
                <tr class="terminal-table-row">
                    <td colspan="8" class="terminal-placeholder has-text-danger" style="text-align: center; padding: 2rem;">
                        Error loading cases: ${escapeHtml(e.message)}
                    </td>
                </tr>
            `;
        }
    }

    updatePaginationControls(resultCount, isSearch = false) {
        const prevBtn = document.getElementById('btnPrevPage');
        const nextBtn = document.getElementById('btnNextPage');
        const indicator = document.getElementById('pageIndicator');
        const select = document.getElementById('itemsPerPageSelect');

        if (isSearch) {
            if (prevBtn) prevBtn.disabled = true;
            if (nextBtn) nextBtn.disabled = true;
            if (select) select.disabled = true;
            if (indicator) indicator.textContent = "Search Results";
            return;
        }

        if (select) select.disabled = false;
        if (indicator) indicator.textContent = `Page ${this.currentPage}`;
        if (prevBtn) prevBtn.disabled = (this.currentPage <= 1);
        if (nextBtn) nextBtn.disabled = (resultCount < this.itemsPerPage);
    }

    renderCaseList(cases) {
        const container = document.getElementById('caseListContainer');
        if (!container) return;
        container.innerHTML = '';

        const badge = document.getElementById('caseCountBadge');
        if (badge) {
            badge.textContent = `Page ${this.currentPage} • ${cases ? cases.length : 0} cases`;
        }
        const statusText = document.getElementById('caseStatusbarText');
        if (statusText) {
            statusText.textContent = `Page ${this.currentPage} • Filter: ${this.currentFilter} • ${cases ? cases.length : 0} items loaded`;
        }

        if (!cases || cases.length === 0) {
            container.innerHTML = `
                <tr class="terminal-table-row">
                    <td colspan="8" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                        No cases found in this category.
                    </td>
                </tr>
            `;
            return;
        }

        cases.forEach(c => {
            let desc = c.description || 'No description provided.';
            if (desc.length > 180) desc = desc.substring(0, 180) + '...';

            const iocCount = (c.ioc_count !== undefined) ? c.ioc_count : (c.iocs ? c.iocs.length : 0);
            const priorityBadge = this.getPriorityBadge(c.priority);
            const assignedText = c.assigned_to ? c.assigned_to : 'Unassigned';
            const isClosed = c.status === 'Closed';

            const tr = document.createElement('tr');
            tr.className = 'terminal-table-row';
            tr.onclick = () => this.openCase(c);

            tr.innerHTML = `
                <td class="cases-cell-select" onclick="event.stopPropagation();">
                    <input type="checkbox" class="case-select-checkbox" data-id="${escapeHtml(c.id)}" ${this.selectedCaseIds.has(c.id) ? 'checked' : ''}>
                </td>
                <td class="cases-cell-status">
                    <span class="status-pill ${isClosed ? 'status-closed' : 'status-open'}">${escapeHtml(c.status || 'Open')}</span>
                </td>
                <td class="cases-cell-priority">
                    ${priorityBadge}
                </td>
                <td class="cases-cell-title">
                    <div>
                        <a class="case-item-title">${escapeHtml(c.name || 'Untitled Case')}</a>
                        ${c.is_auto ? '<span class="tag is-dark is-small is-family-code ml-1" style="border: 1px solid rgba(56, 189, 248, 0.25); color: #94a3b8; height: 1.5em; padding: 0 4px;">AUTO</span>' : ''}
                        <span class="is-size-7 has-text-grey ml-2" style="font-family: 'IBMPlexMono', monospace;">by ${escapeHtml(c.created_by || 'unknown')}</span>
                    </div>
                    <div class="case-item-desc">${escapeHtml(desc)}</div>
                </td>
                <td class="cases-cell-assignee">
                    <span class="tag is-dark is-family-code is-small" style="background: #09121d; border: 1px solid rgba(56, 189, 248, 0.2); color: #cbd5e1;">
                        <span class="icon is-small mr-1" style="opacity: 0.7;"><i class="material-icons" style="font-size: 13px;">person_outline</i></span>
                        ${escapeHtml(assignedText)}
                    </span>
                </td>
                <td class="cases-cell-iocs">
                    <span class="tag is-dark is-rounded is-family-code is-small" style="background-color: #0b141c; border: 1px solid rgba(56, 189, 248, 0.25); color: #38bdf8;">
                        ${iocCount} IOCs
                    </span>
                </td>
                <td class="cases-cell-date" title="${new Date(c.created_at).toLocaleString()}">
                    ${new Date(c.created_at).toLocaleDateString()}
                </td>
                <td class="cases-cell-actions" onclick="event.stopPropagation();">
                    <div class="user-action-group">
                        <button class="button is-small terminal-action-btn view-case-btn" data-id="${escapeHtml(c.id)}" title="View Case Details">
                            <span class="icon is-small"><i class="material-icons">visibility</i></span>
                        </button>
                        <button class="button is-small terminal-action-btn terminal-btn-danger delete-case-quick-btn" data-id="${escapeHtml(c.id)}" title="Delete Case">
                            <span class="icon is-small"><i class="material-icons">delete</i></span>
                        </button>
                    </div>
                </td>
            `;

            const checkbox = tr.querySelector('.case-select-checkbox');
            if (checkbox) {
                checkbox.onclick = (e) => {
                    e.stopPropagation();
                    if (checkbox.checked) {
                        this.selectedCaseIds.add(c.id);
                    } else {
                        this.selectedCaseIds.delete(c.id);
                    }
                };
            }

            const viewBtn = tr.querySelector('.view-case-btn');
            if (viewBtn) {
                viewBtn.onclick = (e) => {
                    e.stopPropagation();
                    this.openCase(c);
                };
            }

            const delBtn = tr.querySelector('.delete-case-quick-btn');
            if (delBtn) {
                delBtn.onclick = async (e) => {
                    e.stopPropagation();
                    if (!confirm(`Are you sure you want to permanently delete case "${c.name}"?`)) return;
                    try {
                        const res = await this.app._fetch('/cases/delete', { method: 'POST', body: JSON.stringify({ id: c.id }) });
                        if (!res.ok) throw new Error(await res.text());
                        await this.loadCases();
                    } catch (err) {
                        alert("Delete failed: " + err.message);
                    }
                };
            }

            container.appendChild(tr);
        });

        const checkAll = document.getElementById('checkAllCases');
        if (checkAll) {
            checkAll.checked = false;
            checkAll.onchange = (e) => {
                const isChecked = e.target.checked;
                container.querySelectorAll('.case-select-checkbox').forEach(cb => {
                    cb.checked = isChecked;
                    const cid = cb.dataset.id;
                    if (isChecked) this.selectedCaseIds.add(cid);
                    else this.selectedCaseIds.delete(cid);
                });
            };
        }
    }

    async openCase(cSummary) {
        this.container.innerHTML = `
            <div class="mb-4">
                <button class="button is-small terminal-action-btn" id="btnBackList">
                    <span class="icon is-small"><i class="material-icons">arrow_back</i></span>
                    <span>Back to Cases</span>
                </button>
            </div>
            <div class="has-text-centered p-6">
                <div class="loader" style="height: 50px; width: 50px; border-width: 4px; display:inline-block;"></div>
                <p class="mt-4 has-text-grey" style="font-family: 'IBMPlexMono', monospace;">Loading full case details...</p>
            </div>
        `;
        document.getElementById('btnBackList').onclick = () => this.render();

        try {
            const [res, users] = await Promise.all([
                this.app._fetch(`/cases/get?id=${cSummary.id}`),
                this.fetchUsers()
            ]);
            if (!res.ok) throw new Error(await res.text());

            const c = await res.json();
            this.currentCase = c;
            const isClosed = c.status === 'Closed';

            this.container.innerHTML = `
                <!-- Sticky Header for Case Detail View -->
                <div class="users-nav-bar cases-nav-bar mb-4" id="cases-detail-top">
                    <div class="users-nav-left">
                        <button class="button is-small terminal-action-btn" id="btnBackList" title="Back to Cases">
                            <span class="icon is-small"><i class="material-icons">arrow_back</i></span>
                            <span>Back to Cases</span>
                        </button>
                        <div class="users-nav-title-group ml-2">
                            <span class="users-nav-title">${escapeHtml(c.name)}</span>
                            ${this.getPriorityBadge(c.priority)}
                            <span class="status-pill ${isClosed ? 'status-closed' : 'status-open'} ml-1">${escapeHtml(c.status)}</span>
                        </div>
                    </div>
                    <div class="users-nav-right">
                        <button class="button is-small terminal-action-btn" id="btnExportCaseJson" title="Export case as JSON">
                            <span class="icon is-small"><i class="material-icons">file_download</i></span>
                            <span>Export JSON</span>
                        </button>
                        <button class="button is-small terminal-action-btn ${isClosed ? 'terminal-btn-primary' : 'terminal-btn-warning'}" id="btnToggleStatus">
                            <span class="icon is-small"><i class="material-icons">${isClosed ? 'unarchive' : 'archive'}</i></span>
                            <span>${isClosed ? 'Reopen Case' : 'Close Case'}</span>
                        </button>
                        <button class="button is-small terminal-action-btn terminal-btn-danger" id="btnDeleteCase">
                            <span class="icon is-small"><i class="material-icons">delete</i></span>
                            <span>Delete Case</span>
                        </button>
                    </div>
                </div>

                <div class="p-3" style="background: #000000; border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 8px;">
                    <div class="level mb-3">
                        <div class="level-left" style="min-width: 0; flex-shrink: 1;">
                            <div>
                                <h2 class="title is-4 has-text-white mb-1" style="word-break: break-word;">${escapeHtml(c.name)}</h2>
                                <p class="subtitle is-7 has-text-grey-light" style="font-family: 'IBMPlexMono', monospace;">
                                    Created by <span class="has-text-info">${escapeHtml(c.created_by)}</span> on ${new Date(c.created_at).toLocaleString()} ${c.is_auto ? '(Automated)' : ''}
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="columns">
                        <div class="column is-two-thirds">
                            <h4 class="title is-6 has-text-info mb-2" style="font-family: 'IBMPlexMono', monospace;">INDICATORS / IOCS</h4>
                            
                            <div class="field has-addons mb-3">
                                <div class="control is-expanded">
                                    <input class="input is-small terminal-input" type="text" id="inputAddIOC" placeholder="Add IP, Domain, Hash, or CVE...">
                                </div>
                                <div class="control">
                                    <button class="button is-small terminal-action-btn modal-btn-case" id="btnAddIOC">Add</button>
                                </div>
                            </div>

                            <div class="level is-mobile p-2 mb-2" style="background: #09121d; border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 4px;">
                                <div class="level-left">
                                    <label class="checkbox has-text-grey-light ml-2 is-size-7" style="font-family: 'IBMPlexMono', monospace; cursor: pointer;">
                                        <input type="checkbox" id="checkAllIOCs"> Select All
                                    </label>
                                </div>
                                <div class="level-right">
                                    <button class="button is-small terminal-action-btn terminal-btn-warning" id="btnOpenMispModal">
                                        <span class="icon is-small"><i class="material-icons">cloud_upload</i></span>
                                        <span>Send Selected to MISP</span>
                                    </button>
                                </div>
                            </div>

                            <div class="box p-2 mb-4" id="iocListContainer" style="background: #050b12; border: 1px solid rgba(56, 189, 248, 0.18); max-height: 380px; overflow-y: auto;">
                                ${(c.iocs && c.iocs.length > 0) ? (c.iocs || []).map(ioc => `
                                    <div class="level is-mobile mb-1 p-2" style="border-bottom: 1px solid rgba(255, 255, 255, 0.06); border-radius: 3px;">
                                        <div class="level-left">
                                            <label class="checkbox mr-2" style="cursor: pointer;">
                                                <input type="checkbox" class="ioc-checkbox" value="${escapeHtml(ioc)}">
                                            </label>
                                            <span class="has-text-info-light is-family-code is-size-7">${escapeHtml(ioc)}</span>
                                        </div>
                                        <div class="level-right">
                                            <button class="delete is-small delete-ioc" data-val="${escapeHtml(ioc)}" title="Remove IOC"></button>
                                        </div>
                                    </div>
                                `).join('') : '<p class="has-text-grey is-size-7 is-italic p-2">No indicators associated with this case.</p>'}
                            </div>

                            <h4 class="title is-6 has-text-info mb-2 mt-4" style="font-family: 'IBMPlexMono', monospace;">COMMENTS &amp; TIMELINE</h4>
                            <div id="commentList" class="mb-3 p-2" style="background: #050b12; border: 1px solid rgba(56, 189, 248, 0.18); border-radius: 4px; max-height: 280px; overflow-y: auto;">
                                ${(c.comments && c.comments.length > 0) ? (c.comments || []).map(cm => `
                                    <div class="mb-2 p-2" style="background: #08101a; border-left: 3px solid #38bdf8; border-radius: 3px;">
                                        <div class="is-flex is-justify-content-between is-size-7 mb-1" style="font-family: 'IBMPlexMono', monospace;">
                                            <strong class="has-text-info">${escapeHtml(cm.user)}</strong>
                                            <span class="has-text-grey">${new Date(cm.created_at).toLocaleString()}</span>
                                        </div>
                                        <p class="has-text-light is-size-7" style="word-break: break-word;">${escapeHtml(cm.text)}</p>
                                    </div>
                                `).join('') : '<p class="has-text-grey is-size-7 is-italic p-2">No comments yet.</p>'}
                            </div>

                            <div class="field mb-2">
                                <div class="control">
                                    <textarea class="textarea terminal-textarea" id="inputComment" rows="2" placeholder="Add a comment..."></textarea>
                                </div>
                            </div>
                            <div class="field">
                                <div class="control">
                                    <button class="button is-small terminal-action-btn modal-btn-case" id="btnPostComment">
                                        <span class="icon is-small"><i class="material-icons">send</i></span>
                                        <span>Post Comment</span>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="column">
                            <div class="box p-3" style="background: #070d14; border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 6px;">
                                <h4 class="title is-6 has-text-warning mb-3" style="font-family: 'IBMPlexMono', monospace;">CASE METADATA</h4>
                                <p class="has-text-grey-light is-size-7 mb-3" style="word-break: break-word;">${escapeHtml(c.description || 'No description.')}</p>
                                
                                <div class="is-size-7 mb-2" style="font-family: 'IBMPlexMono', monospace;">
                                    <span class="has-text-grey">STATUS:</span> <span class="status-pill ${isClosed ? 'status-closed' : 'status-open'} ml-1">${escapeHtml(c.status)}</span>
                                </div>
                                <div class="is-size-7 mb-2" style="font-family: 'IBMPlexMono', monospace;">
                                    <span class="has-text-grey">CASE ID:</span> <span class="has-text-light ml-1" style="word-break: break-all;">${c.id}</span>
                                </div>
                                <div class="is-size-7 mb-3" style="font-family: 'IBMPlexMono', monospace;">
                                    <span class="has-text-grey">TYPE:</span> <span class="has-text-info ml-1">${c.is_auto ? 'Automated System Case' : 'User Created'}</span>
                                </div>

                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Priority</label>
                                    <div class="control">
                                        <div class="select is-small is-fullwidth terminal-select">
                                            <select id="selectCasePriority">
                                                <option value="Low" ${c.priority === 'Low' ? 'selected' : ''}>Low</option>
                                                <option value="Medium" ${(!c.priority || c.priority === 'Medium') ? 'selected' : ''}>Medium</option>
                                                <option value="High" ${c.priority === 'High' ? 'selected' : ''}>High</option>
                                                <option value="Critical" ${c.priority === 'Critical' ? 'selected' : ''}>Critical</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Assigned To</label>
                                    <div class="control">
                                        <div class="select is-small is-fullwidth terminal-select">
                                            <select id="selectCaseAssignee">
                                                <option value="" ${!c.assigned_to ? 'selected' : ''}>Unassigned</option>
                                                ${users.map(u => `
                                                    <option value="${escapeHtml(u)}" ${c.assigned_to === u ? 'selected' : ''}>${escapeHtml(u)}</option>
                                                `).join('')}
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                ${c.is_auto ? `
                                    <button class="button is-small terminal-action-btn is-fullwidth mt-3" id="btnPromoteCase">
                                        <span class="icon is-small"><i class="material-icons">upgrade</i></span>
                                        <span>Promote to User Case</span>
                                    </button>
                                ` : ''}

                                ${c.response_id ? `
                                    <button class="button is-small terminal-action-btn terminal-btn-primary is-fullwidth mt-2" id="btnViewSourceResponse">
                                        <span class="icon is-small"><i class="material-icons">description</i></span>
                                        <span>View Source Response</span>
                                    </button>
                                ` : ''}
                            </div>
                        </div>
                    </div>

                    <!-- AI Report Section -->
                    <div class="box p-3 mt-4" id="caseAiReportSection" style="background: #070d14; border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 6px;">
                        <div class="level mb-3">
                            <div class="level-left">
                                <h4 class="title is-6 has-text-info mb-0" style="font-family: 'IBMPlexMono', monospace;">
                                    <span class="icon mr-1"><i class="material-icons" style="font-size: 16px;">auto_awesome</i></span>
                                    <span>AI Threat &amp; Vulnerability Report</span>
                                </h4>
                            </div>
                            <div class="level-right">
                                <div class="buttons">
                                    ${c.ai_report ? `
                                        <button class="button is-small terminal-action-btn" id="btnOpenCaseAiModal">
                                            <span class="icon is-small"><i class="material-icons">open_in_full</i></span>
                                            <span>Open Modal</span>
                                        </button>
                                    ` : ''}
                                    <button class="button is-small terminal-action-btn modal-btn-case" id="btnGenerateCaseAiReport">
                                        <span class="icon is-small"><i class="material-icons">${c.ai_report ? 'refresh' : 'auto_awesome'}</i></span>
                                        <span>${c.ai_report ? 'Rerun AI Report' : 'Generate AI Report'}</span>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div id="caseAiReportViewport">
                            ${c.ai_report ? `
                                <div class="box p-2" style="background: #ffffff; border-radius: 6px; border: 1px solid #3e8ed0;">
                                    <iframe id="caseAiReportIframe" sandbox="allow-popups allow-popups-to-escape-sandbox" style="width: 100%; height: 500px; border: none; background: #fff; border-radius: 4px;"></iframe>
                                </div>
                            ` : `
                                <div class="notification terminal-form-notification is-dark has-text-grey-light is-italic">
                                    No AI Report linked to this case yet. Click <strong>Generate AI Report</strong> to generate an analysis based on the case IOCs/CVE.
                                </div>
                            `}
                        </div>
                    </div>
                </div>

                <!-- Case AI Modal (Terminal Modal) -->
                <div class="modal terminal-modal" id="caseAiModal">
                    <div class="modal-background"></div>
                    <div class="modal-card details-modal-card" style="width: 92%; max-width: 1200px;">
                        <header class="modal-card-head terminal-titlebar details-modal-titlebar">
                            <div class="terminal-dots">
                                <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                                <span class="terminal-dot dot-min"></span>
                                <span class="terminal-dot dot-expand"></span>
                            </div>
                            <div class="terminal-title details-modal-title-wrap">
                                <span class="terminal-status-dot details-status-dot"></span>
                                <span class="modal-card-title details-modal-title">AI Threat &amp; Vulnerability Report</span>
                            </div>
                            <div class="terminal-actions details-modal-actions">
                                <span class="system-status-pill details-status-pill">
                                    <span class="status-indicator-dot dot-details"></span>REPORT VIEW
                                </span>
                                <button class="button is-small terminal-action-btn modal-close-btn delete" aria-label="close" id="btnCloseCaseAiModal" title="Close modal">
                                    <span class="icon is-small"><i class="material-icons">close</i></span>
                                </button>
                            </div>
                        </header>
                        <section class="modal-card-body details-modal-body p-0" style="height: 75vh; background: #ffffff;">
                            <iframe id="caseAiReportModalIframe" sandbox="allow-popups allow-popups-to-escape-sandbox" style="width:100%; height:100%; border:none; background:#ffffff;"></iframe>
                        </section>
                        <footer class="modal-card-foot details-modal-foot">
                            <div class="details-foot-left">
                                <button type="button" class="button terminal-action-btn modal-btn-case" id="btnModalRerunCaseAiReport">
                                    <span class="icon is-small"><i class="material-icons">refresh</i></span>
                                    <span>Rerun Report</span>
                                </button>
                            </div>
                            <div class="details-foot-right">
                                <button type="button" class="button terminal-action-btn" id="btnModalCloseCaseAiModal">Close</button>
                            </div>
                        </footer>
                    </div>
                </div>

                <!-- MISP Export Modal (Terminal Modal) -->
                <div class="modal terminal-modal" id="mispModal">
                    <div class="modal-background"></div>
                    <div class="modal-card details-modal-card" style="max-width: 600px;">
                        <header class="modal-card-head terminal-titlebar details-modal-titlebar">
                            <div class="terminal-dots">
                                <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                                <span class="terminal-dot dot-min"></span>
                                <span class="terminal-dot dot-expand"></span>
                            </div>
                            <div class="terminal-title details-modal-title-wrap">
                                <span class="terminal-status-dot details-status-dot"></span>
                                <span class="modal-card-title details-modal-title">Send Indicators to MISP</span>
                            </div>
                            <div class="terminal-actions details-modal-actions">
                                <span class="system-status-pill details-status-pill">
                                    <span class="status-indicator-dot dot-details"></span>MISP SYNC
                                </span>
                                <button class="button is-small terminal-action-btn modal-close-btn delete" aria-label="close" title="Close modal">
                                    <span class="icon is-small"><i class="material-icons">close</i></span>
                                </button>
                            </div>
                        </header>
                        <section class="modal-card-body details-modal-body">
                            <div class="modal-subform-container">
                                <div class="notification terminal-form-notification is-warning mb-3">
                                    You are about to send <strong id="mispCountDisplay">0</strong> IOCs to MISP.
                                </div>
                                
                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Event Title / Info *</label>
                                    <div class="control">
                                        <input class="input terminal-input" type="text" id="mispEventTitle">
                                    </div>
                                    <p class="terminal-form-help">This will be the title of the MISP Event.</p>
                                </div>

                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Tags</label>
                                    <div class="control">
                                        <input class="input terminal-input" type="text" id="mispTags" value="Application:Threatco, tlp:amber">
                                    </div>
                                    <p class="terminal-form-help">Comma separated tags (e.g. "phishing, apt28").</p>
                                </div>

                                <label class="label terminal-form-label mb-1">Selected IOCs Preview</label>
                                <div class="box p-2 mb-2" id="mispPreviewList" style="background: #080c18; border: 1px solid rgba(var(--modal-accent-rgb), 0.28); max-height: 140px; overflow-y: auto;"></div>
                            </div>
                        </section>
                        <footer class="modal-card-foot details-modal-foot">
                            <div class="details-foot-left">
                                <button type="button" class="button terminal-action-btn modal-btn-archive" id="btnConfirmMisp">
                                    <span class="icon is-small"><i class="material-icons">cloud_upload</i></span>
                                    <span>Send Events</span>
                                </button>
                            </div>
                            <div class="details-foot-right">
                                <button type="button" class="button terminal-action-btn" id="btnCancelMisp">Cancel</button>
                            </div>
                        </footer>
                    </div>
                </div>
            `;

            this.attachDetailListeners(c);

        } catch (e) {
            this.container.innerHTML = `<div class="notification terminal-form-notification is-danger">Error loading case details: ${escapeHtml(e.message)}</div>`;
        }
    }

    attachDetailListeners(c) {
        const backBtn = document.getElementById('btnBackList');
        if (backBtn) backBtn.onclick = () => this.render();

        const prioritySelect = document.getElementById('selectCasePriority');
        if (prioritySelect) {
            prioritySelect.onchange = async (e) => {
                this.currentCase.priority = e.target.value;
                await this.updateCase();
            };
        }

        const assigneeSelect = document.getElementById('selectCaseAssignee');
        if (assigneeSelect) {
            assigneeSelect.onchange = async (e) => {
                this.currentCase.assigned_to = e.target.value;
                await this.updateCase();
            };
        }

        const mainIframe = document.getElementById('caseAiReportIframe');
        if (mainIframe && c.ai_report) {
            mainIframe.srcdoc = c.ai_report;
        }

        const runCaseAiReport = async (force = false) => {
            const genBtn = document.getElementById('btnGenerateCaseAiReport');
            const modalGenBtn = document.getElementById('btnModalRerunCaseAiReport');
            if (genBtn) genBtn.classList.add('is-loading');
            if (modalGenBtn) modalGenBtn.classList.add('is-loading');

            try {
                const res = await this.app._fetch('/cases/aireport', {
                    method: 'POST',
                    body: JSON.stringify({ id: c.id, force: force })
                });

                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();

                if (data.ai_report) {
                    this.currentCase.ai_report = data.ai_report;
                    const iframe = document.getElementById('caseAiReportIframe');
                    const modalIframe = document.getElementById('caseAiReportModalIframe');
                    if (iframe) iframe.srcdoc = data.ai_report;
                    if (modalIframe) modalIframe.srcdoc = data.ai_report;

                    const viewport = document.getElementById('caseAiReportViewport');
                    if (viewport && !iframe) {
                        viewport.innerHTML = `
                            <div class="box p-2" style="background: #ffffff; border-radius: 6px; border: 1px solid #3e8ed0;">
                                <iframe id="caseAiReportIframe" sandbox="allow-popups allow-popups-to-escape-sandbox" style="width: 100%; height: 500px; border: none; background: #fff; border-radius: 4px;"></iframe>
                            </div>
                        `;
                        const newIframe = document.getElementById('caseAiReportIframe');
                        if (newIframe) newIframe.srcdoc = data.ai_report;
                    }

                    if (genBtn) {
                        genBtn.innerHTML = `<span class="icon is-small"><i class="material-icons">refresh</i></span><span>Rerun AI Report</span>`;
                    }
                }
            } catch (err) {
                alert("Failed to generate AI report: " + err.message);
            } finally {
                if (genBtn) genBtn.classList.remove('is-loading');
                if (modalGenBtn) modalGenBtn.classList.remove('is-loading');
            }
        };

        const btnGen = document.getElementById('btnGenerateCaseAiReport');
        if (btnGen) btnGen.onclick = () => runCaseAiReport(this.currentCase.ai_report ? true : false);

        const btnModalRerun = document.getElementById('btnModalRerunCaseAiReport');
        if (btnModalRerun) btnModalRerun.onclick = () => runCaseAiReport(true);

        const aiModal = document.getElementById('caseAiModal');
        const openModalBtn = document.getElementById('btnOpenCaseAiModal');
        if (openModalBtn && aiModal) {
            openModalBtn.onclick = () => {
                const modalIframe = document.getElementById('caseAiReportModalIframe');
                if (modalIframe && this.currentCase.ai_report) {
                    modalIframe.srcdoc = this.currentCase.ai_report;
                }
                aiModal.classList.add('is-active');
            };
        }

        const closeAiModal = () => {
            if (aiModal) aiModal.classList.remove('is-active');
        };
        const closeBtn1 = document.getElementById('btnCloseCaseAiModal');
        const closeBtn2 = document.getElementById('btnModalCloseCaseAiModal');
        if (closeBtn1) closeBtn1.onclick = closeAiModal;
        if (closeBtn2) closeBtn2.onclick = closeAiModal;
        if (aiModal) {
            aiModal.querySelectorAll('.delete, .modal-background, .modal-close-dot, .modal-close-btn, #btnModalCloseCaseAiModal').forEach(el => {
                el.onclick = closeAiModal;
            });
        }

        const mispModal = document.getElementById('mispModal');
        const closeMisp = () => {
            if (mispModal) mispModal.classList.remove('is-active');
        };
        const cancelMispBtn = document.getElementById('btnCancelMisp');
        if (cancelMispBtn) cancelMispBtn.onclick = closeMisp;
        if (mispModal) {
            mispModal.querySelectorAll('.delete, .modal-background, .modal-close-dot, .modal-close-btn, #btnCancelMisp').forEach(el => {
                el.onclick = closeMisp;
            });
        }

        const promoteBtn = document.getElementById('btnPromoteCase');
        if (promoteBtn) {
            promoteBtn.onclick = async () => {
                if (!confirm("Are you sure you want to promote this to a User Case? This will move it out of the automated category.")) {
                    return;
                }
                this.currentCase.is_auto = false;
                await this.updateCase();
            };
        }

        const toggleStatusBtn = document.getElementById('btnToggleStatus');
        if (toggleStatusBtn) {
            toggleStatusBtn.onclick = async () => {
                const newStatus = this.currentCase.status === 'Open' ? 'Closed' : 'Open';
                this.currentCase.status = newStatus;
                await this.updateCase();
            };
        }

        const deleteCaseBtn = document.getElementById('btnDeleteCase');
        if (deleteCaseBtn) {
            deleteCaseBtn.onclick = async () => {
                if (!confirm("Are you sure you want to permanently delete this case?")) return;
                try {
                    const res = await this.app._fetch('/cases/delete', { method: 'POST', body: JSON.stringify({ id: c.id }) });
                    if (!res.ok) throw new Error(await res.text());
                    this.render();
                } catch (e) { alert("Delete failed: " + e.message); }
            };
        }

        const exportJsonBtn = document.getElementById('btnExportCaseJson');
        if (exportJsonBtn) {
            exportJsonBtn.onclick = () => {
                const exportObj = {
                    ...this.currentCase,
                    ai_report: this.currentCase.ai_report ? "present" : ""
                };
                const caseData = JSON.stringify(exportObj, null, 4);
                const blob = new Blob([caseData], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');

                const safeName = (this.currentCase.name || 'case').replace(/[^a-z0-9]/gi, '_').toLowerCase();
                const date = new Date().toISOString().split('T')[0];

                a.href = url;
                a.download = `case_${safeName}_${date}.json`;
                document.body.appendChild(a);
                a.click();

                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            };
        }

        if (c.response_id) {
            const btn = document.getElementById('btnViewSourceResponse');
            if (btn) {
                btn.onclick = () => {
                    document.dispatchEvent(new CustomEvent('req-open-details', { detail: c.response_id }));
                };
            }
        }

        const addIocBtn = document.getElementById('btnAddIOC');
        if (addIocBtn) {
            addIocBtn.onclick = () => {
                const input = document.getElementById('inputAddIOC');
                const val = input ? input.value.trim() : '';
                if (!val) return;
                if (!this.currentCase.iocs) this.currentCase.iocs = [];
                if (!this.currentCase.iocs.includes(val)) {
                    this.currentCase.iocs.push(val);
                    this.updateCase();
                }
            };
        }

        const checkAllIOCs = document.getElementById('checkAllIOCs');
        if (checkAllIOCs) {
            checkAllIOCs.onchange = (e) => {
                document.querySelectorAll('.ioc-checkbox').forEach(cb => cb.checked = e.target.checked);
            };
        }

        const iocListContainer = document.getElementById('iocListContainer');
        if (iocListContainer) {
            iocListContainer.onclick = (e) => {
                if (e.target.classList.contains('delete-ioc')) {
                    const val = e.target.dataset.val;
                    this.currentCase.iocs = this.currentCase.iocs.filter(i => i !== val);
                    this.updateCase();
                }
            };
        }

        const postCommentBtn = document.getElementById('btnPostComment');
        if (postCommentBtn) {
            postCommentBtn.onclick = async () => {
                const input = document.getElementById('inputComment');
                const text = input ? input.value.trim() : '';
                if (!text) return;
                const comment = { user: this.app.user.email, text: text, created_at: new Date().toISOString() };
                if (!this.currentCase.comments) this.currentCase.comments = [];
                this.currentCase.comments.push(comment);
                await this.updateCase();
            };
        }

        const openMispModalBtn = document.getElementById('btnOpenMispModal');
        if (openMispModalBtn) {
            openMispModalBtn.onclick = () => {
                const selected = Array.from(document.querySelectorAll('.ioc-checkbox:checked')).map(cb => cb.value);
                if (selected.length === 0) return alert("No IOCs selected.");

                document.getElementById('mispCountDisplay').textContent = selected.length;
                document.getElementById('mispEventTitle').value = `Case: ${this.currentCase.name}`;
                document.getElementById('mispPreviewList').innerHTML = selected.map(s => `<span class="tag is-dark m-1 is-family-code is-small" style="background:#0c101e; border:1px solid rgba(56, 189, 248, 0.25); color:#38bdf8;">${escapeHtml(s)}</span>`).join('');

                const mispModalEl = document.getElementById('mispModal');
                if (mispModalEl) mispModalEl.classList.add('is-active');

                const confirmBtn = document.getElementById('btnConfirmMisp');
                if (confirmBtn) {
                    const newBtn = confirmBtn.cloneNode(true);
                    confirmBtn.parentNode.replaceChild(newBtn, confirmBtn);
                    newBtn.onclick = () => this.sendToMisp(selected);
                }
            };
        }
    }

    async sendToMisp(selectedIOCs) {
        const titleEl = document.getElementById('mispEventTitle');
        const tagsEl = document.getElementById('mispTags');
        const title = titleEl ? titleEl.value.trim() : '';
        const tagsVal = tagsEl ? tagsEl.value.trim() : '';
        const btn = document.getElementById('btnConfirmMisp');

        if (!title) return alert("Event Title is required.");
        if (btn) btn.classList.add('is-loading');

        const attributes = selectedIOCs.map(ioc => {
            let type = "other";
            const val = ioc.trim();
            if (/^CVE-\d{4}-\d+/i.test(val)) type = "vulnerability";
            else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) type = "ip-src";
            else if (/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/.test(val)) type = "domain";
            else if (val.length === 32) type = "md5";
            else if (val.length === 64) type = "sha256";
            return { value: val, type: type };
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
            const mispModal = document.getElementById('mispModal');
            if (mispModal) mispModal.classList.remove('is-active');
        } catch (e) {
            console.error(e);
            alert("Failed to send batch to MISP: " + e.message);
        } finally {
            if (btn) btn.classList.remove('is-loading');
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
