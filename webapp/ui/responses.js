export class ResponseController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.currentOptions = { start: 0, limit: 100 }; // Store current state
    }

    render() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
        <!-- Sticky Responses Header / Navigation Bar -->
        <div class="users-nav-bar responses-nav-bar mb-3" id="responses-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title" id="responseViewTitle">Responses</span>
                    <span class="tag is-info is-dark is-rounded charts-count-badge" id="responseCountBadge">0 records</span>
                </div>
            </div>

            <div class="users-nav-right">
                <div class="field has-addons mb-0">
                    <div class="control">
                        <input class="input is-small terminal-search" type="text" id="filterVendor" placeholder="Vendor or ID..." autocomplete="off">
                    </div>
                    <div class="control">
                        <button class="button is-small is-dark" id="applyResponseFilters" type="button" title="Apply filter">
                            <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">filter_list</i></span>
                            <span>Filter</span>
                        </button>
                    </div>
                </div>
                <button class="button is-small is-dark is-outlined" id="exportResponsesBtn" type="button" title="Export responses as CSV">
                    <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">file_download</i></span>
                    <span>Export</span>
                </button>
                <button type="button" class="button is-small is-dark is-outlined" id="refreshResponsesBtn" title="Refresh responses">↻ Refresh</button>
            </div>
        </div>

        <!-- Filter Sub-bar for Options -->
        <div class="box p-3 mb-3" style="background: rgba(11, 20, 28, 0.96); border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 8px;">
            <div class="field is-grouped is-grouped-multiline is-align-items-center mb-0">
                <p class="control">
                    <input class="input is-small" type="number" id="filterLimit" placeholder="Limit" value="100" style="width: 80px; background: #060b11; color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.35); font-family: 'IBMPlexMono', monospace;">
                </p>
                <p class="control">
                    <label class="checkbox" style="font-family: 'IBMPlexMono', monospace; font-size: 0.78rem; color: #94a3b8; cursor: pointer;">
                        <input type="checkbox" id="filterMatched"> only matches
                    </label>
                </p>
                <p class="control">
                    <label class="checkbox" style="font-family: 'IBMPlexMono', monospace; font-size: 0.78rem; color: #94a3b8; cursor: pointer;">
                        <input type="checkbox" id="filterArchived"> archived
                    </label>
                </p>
                <p class="control">
                    <button class="button is-small terminal-action-btn" id="applySubBarFilters" type="button" title="Apply filter settings">
                        <span class="icon is-small"><i class="material-icons" style="font-size: 14px;">check</i></span>
                        <span>Apply</span>
                    </button>
                </p>
            </div>
        </div>

        <!-- Responses Terminal Window -->
        <div class="users-window responses-window" id="responsesViewer">
            <div class="terminal-titlebar">
                <div class="terminal-dots">
                    <span class="terminal-dot dot-close"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div>
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span>responses.telemetry.threatco</span>
                </div>
                <div class="terminal-actions">
                    <span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>CACHE ONLINE</span>
                </div>
            </div>

            <div id="responseTableContainer">
                <div class="terminal-table-container">
                    <table class="terminal-table users-table responses-table">
                        <thead>
                            <tr>
                                <th class="resp-th-time">TIME</th>
                                <th class="resp-th-vendor">VENDOR</th>
                                <th class="resp-th-value">VALUE</th>
                                <th class="resp-th-actions">ACTIONS</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr class="terminal-table-row">
                                <td colspan="4" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                                    <p class="has-text-info mb-2">Fetching initial responses...</p>
                                    <progress class="progress is-small is-info" max="100"></progress>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="terminal-statusbar">
                <span id="responseStatusText">Showing cached telemetry records</span>
                <span class="is-pulled-right">threatco telemetry • cache</span>
            </div>
        </div>

        <!-- Terminal Modern Pagination -->
        <nav class="pagination is-centered terminal-pagination mt-4" role="navigation" aria-label="pagination">
            <a class="pagination-previous" id="prevPageBtn" disabled>« Previous</a>
            <a class="pagination-next" id="nextPageBtn" disabled>Next »</a>
            <ul class="pagination-list" id="paginationList"></ul>
        </nav>`;

    const filterMatchedEl = document.getElementById('filterMatched');
    const filterArchivedEl = document.getElementById('filterArchived');
    const filterLimitEl = document.getElementById('filterLimit');
    const filterVendorEl = document.getElementById('filterVendor');

    // Restore previous filter state if present
    if (this.currentOptions.limit && filterLimitEl) {
        filterLimitEl.value = this.currentOptions.limit;
    }
    if (this.currentOptions.matched && filterMatchedEl) {
        filterMatchedEl.checked = true;
    }
    if (this.currentOptions.archived && filterArchivedEl) {
        filterArchivedEl.checked = true;
    }
    if ((this.currentOptions.id || this.currentOptions.vendor) && filterVendorEl) {
        filterVendorEl.value = this.currentOptions.id || this.currentOptions.vendor;
    }

    // 1. Checkboxes listeners - immediately fires on toggle
    filterArchivedEl?.addEventListener('change', () => {
        this.applyFilters();
    });

    filterMatchedEl?.addEventListener('change', () => {
        this.applyFilters();
    });

    // 2. Limit change listener
    filterLimitEl?.addEventListener('change', () => {
        this.applyFilters();
    });

    // 3. Apply button listeners
    document.getElementById('applyResponseFilters')?.addEventListener('click', () => {
        this.applyFilters();
    });

    document.getElementById('applySubBarFilters')?.addEventListener('click', () => {
        this.applyFilters();
    });

    // Enter key triggers filter
    filterVendorEl?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            this.applyFilters();
        }
    });

    // Attach Listener for Export CSV Button
    document.getElementById('exportResponsesBtn')?.addEventListener('click', () => {
        const options = this.getFilterOptions();
        const params = new URLSearchParams();

        if (options.id) params.append('id', options.id);
        if (options.vendor) params.append('vendor', options.vendor);
        if (options.matched) params.append('matched', 'true');
        if (options.archived) params.append('archived', 'true');

        window.location.href = `/exportresponses?${params.toString()}`;
    });

    // Refresh Button Listener
    const refreshBtn = document.getElementById('refreshResponsesBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            this.fetch(this.currentOptions);
        });
    }

    // Initial Fetch
    this.fetch(this.currentOptions);
}

    getFilterOptions() {
        const rawInput = document.getElementById('filterVendor')?.value.trim() || '';
        const limitVal = document.getElementById('filterLimit')?.value || '100';
        const matched = document.getElementById('filterMatched')?.checked || false;
        const archived = document.getElementById('filterArchived')?.checked || false;

        const options = {
            start: 0,
            limit: parseInt(limitVal, 10) || 100,
            matched: matched,
            archived: archived,
            vendor: null,
            id: null
        };

        const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (rawInput) {
            if (uuidPattern.test(rawInput)) {
                options.id = rawInput;
            } else {
                options.vendor = rawInput;
            }
        }

        return options;
    }

    applyFilters() {
        const options = this.getFilterOptions();
        this.fetch(options);
    }

    async fetch(options = {}) {
        // Update local state
        this.currentOptions = { ...this.currentOptions, ...options };

        const tableContainer = document.getElementById('responseTableContainer');
        if (!tableContainer) return;

        tableContainer.innerHTML = '<div class="terminal-table-container"><table class="terminal-table users-table responses-table"><thead><tr><th class="resp-th-time">TIME</th><th class="resp-th-vendor">VENDOR</th><th class="resp-th-value">VALUE</th><th class="resp-th-actions">ACTIONS</th></tr></thead><tbody><tr class="terminal-table-row"><td colspan="4" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;"><p class="has-text-info mb-2">Fetching responses...</p><progress class="progress is-small is-info" max="100"></progress></td></tr></tbody></table></div>';

        // Fetch data
        const { html, total } = await this.app.fetchResponseCache(this.currentOptions);

        // Render Table
        tableContainer.innerHTML = html;

        // UPDATE TITLE AND BADGE WITH COUNT
        const titleEl = document.getElementById('responseViewTitle');
        if (titleEl) titleEl.textContent = `Responses (${total})`;

        const countBadge = document.getElementById('responseCountBadge');
        if (countBadge) countBadge.textContent = `${total} records`;

        const statusEl = document.getElementById('responseStatusText');
        if (statusEl) {
            const { start, limit, archived } = this.currentOptions;
            const recordsLabel = archived ? 'archived telemetry records' : 'telemetry records';
            if (total === 0) {
                statusEl.textContent = archived ? 'No archived telemetry records found' : 'No telemetry records found';
            } else {
                const startItem = start + 1;
                const endItem = Math.min(start + limit, total);
                statusEl.textContent = `Showing ${startItem}–${endItem} of ${total} ${recordsLabel}`;
            }
        }

        // Render Pagination
        this.renderPagination(total);

        // Attach Table Listeners (Details and Delete)
        this.attachTableListeners(tableContainer);
    }

    renderPagination(totalCount) {
        const { start, limit } = this.currentOptions;
        const currentPage = Math.floor(start / limit) + 1;
        const totalPages = Math.ceil(totalCount / limit);

        const list = document.getElementById('paginationList');
        const prevBtn = document.getElementById('prevPageBtn');
        const nextBtn = document.getElementById('nextPageBtn');

        list.innerHTML = '';

        // Handle Prev/Next Buttons
        if (currentPage > 1) {
            prevBtn.removeAttribute('disabled');
            prevBtn.classList.remove('is-disabled');
            prevBtn.onclick = () => this.goToPage(currentPage - 1);
        } else {
            prevBtn.setAttribute('disabled', true);
            prevBtn.classList.add('is-disabled');
            prevBtn.onclick = null;
        }

        if (currentPage < totalPages) {
            nextBtn.removeAttribute('disabled');
            nextBtn.classList.remove('is-disabled');
            nextBtn.onclick = () => this.goToPage(currentPage + 1);
        } else {
            nextBtn.setAttribute('disabled', true);
            nextBtn.classList.add('is-disabled');
            nextBtn.onclick = null;
        }

        // Generate Page Numbers (Sliding Window)
        const windowSize = 2; // pages around current
        const pages = [];

        pages.push(1); // Always first page

        for (let i = Math.max(2, currentPage - windowSize); i <= Math.min(totalPages - 1, currentPage + windowSize); i++) {
            pages.push(i);
        }

        if (totalPages > 1) {
            pages.push(totalPages); // Always last page
        }

        const uniquePages = [...new Set(pages)].sort((a, b) => a - b);

        let lastP = 0;
        uniquePages.forEach(p => {
            if (lastP > 0 && p - lastP > 1) {
                const li = document.createElement('li');
                li.innerHTML = `<span class="pagination-ellipsis">&hellip;</span>`;
                list.appendChild(li);
            }

            const li = document.createElement('li');
            const a = document.createElement('a');
            a.className = `pagination-link ${p === currentPage ? 'is-current' : ''}`;
            a.textContent = p;
            a.setAttribute('aria-label', `Goto page ${p}`);

            if (p !== currentPage) {
                a.onclick = () => this.goToPage(p);
            }

            li.appendChild(a);
            list.appendChild(li);
            lastP = p;
        });
    }

    goToPage(pageNum) {
        const newStart = (pageNum - 1) * this.currentOptions.limit;
        this.fetch({ ...this.currentOptions, start: newStart });
    }

    attachTableListeners(container) {
        // Handle all anchor tags in the table
        container.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', async (event) => {
                // If the link is meant to open in a new tab (like the AI Report),
                // or specifically targets the /aireport endpoint, let the browser handle it.
                if (link.target === '_blank' || link.href.includes('/aireport')) {
                    return; 
                }

                // Otherwise, prevent default behavior and trigger the Event Details modal
                event.preventDefault();
                const url = new URL(link.href, window.location.origin);
                const id = url.pathname.split('/').pop();
                
                // Ensure we have a valid ID and aren't just capturing the base path
                if (id && id !== 'events') {
                    const customEvent = new CustomEvent('req-open-details', { detail: id });
                    document.dispatchEvent(customEvent);
                }
            });
        });

        // Handle delete buttons in the table
        container.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', async (event) => {
                event.preventDefault();
                event.stopPropagation();
                
                const id = btn.getAttribute('data-id');
                if (!confirm(`Are you sure you want to delete response ${id}?`)) return;

                btn.classList.add('is-loading');
                try {
                    const resp = await fetch('/deleteresponse', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            id: id, 
                            archived: this.currentOptions.archived || false 
                        })
                    });

                    if (resp.ok) {
                        // Refresh the table data upon successful deletion
                        await this.fetch(this.currentOptions);
                    } else {
                        alert('Failed to delete: ' + await resp.text());
                        btn.classList.remove('is-loading');
                    }
                } catch (err) {
                    console.error('Delete error:', err);
                    btn.classList.remove('is-loading');
                }
            });
        });
    }
}