export class ResponseController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.currentOptions = { start: 0, limit: 100, timeRange: '24h' }; // Store current state
    }

    render() {
    this.container.classList.remove('is-hidden');
    this.container.innerHTML = `
        <h1 class="title has-text-info" id="responseViewTitle">Responses</h1>
        <div class="field is-grouped is-grouped-multiline">
            <p class="control is-expanded">
                <input class="input" type="text" id="filterVendor" placeholder="Vendor or ID">
            </p>
            <p class="control">
                <input class="input" type="number" id="filterLimit" placeholder="Limit" value="100" style="width: 90px;">
            </p>
            <p class="control">
                <span class="select">
                    <select id="filterTimeRange" title="Time Range">
                        <option value="24h" selected>Last 24 Hours</option>
                        <option value="15m">Last 15 Minutes</option>
                        <option value="1h">Last 1 Hour</option>
                        <option value="6h">Last 6 Hours</option>
                        <option value="7d">Last 7 Days</option>
                        <option value="30d">Last 30 Days</option>
                        <option value="all">All Time</option>
                        <option value="custom">Custom Range</option>
                    </select>
                </span>
            </p>
            <p class="control is-hidden" id="customTimeRangeSince">
                <input class="input" type="datetime-local" id="filterSince" placeholder="Start Time" title="Start Time">
            </p>
            <p class="control is-hidden" id="customTimeRangeUntil">
                <input class="input" type="datetime-local" id="filterUntil" placeholder="End Time" title="End Time">
            </p>
            <p class="control">
                <label class="checkbox">
                    <input type="checkbox" id="filterMatched"> only matches
                </label>
            </p>
            <p class="control">
                <label class="checkbox">
                    <input type="checkbox" id="filterArchived"> archived
                </label>
            </p>
            <p class="control">
                <button class="button is-info" id="applyResponseFilters" type="button">
                    <span class="icon-text">
                        <span class="icon"><i class="material-icons">filter_list</i></span>
                        <span>apply</span>
                    </span>
                </button>
            </p>
            <p class="control">
                <button class="button is-info" id="exportResponsesBtn" type="button">
                    <span class="icon-text">
                        <span class="icon"><i class="material-icons">file_download</i></span>
                        <span>export</span>
                    </span>
                </button>
            </p>
        </div>
        <hr class="has-background-grey-dark">
        <div id="responseTableContainer"><p class="has-text-info">Fetching initial responses...</p></div>
        <nav class="pagination is-centered is-rounded mt-4" role="navigation" aria-label="pagination">
            <a class="pagination-previous" id="prevPageBtn" disabled>Previous</a>
            <a class="pagination-next" id="nextPageBtn" disabled>Next</a>
            <ul class="pagination-list" id="paginationList"></ul>
        </nav>`;

    const timeRangeSelect = document.getElementById('filterTimeRange');
    const customSinceEl = document.getElementById('customTimeRangeSince');
    const customUntilEl = document.getElementById('customTimeRangeUntil');

    const updateCustomTimeVisibility = () => {
        if (timeRangeSelect.value === 'custom') {
            customSinceEl.classList.remove('is-hidden');
            customUntilEl.classList.remove('is-hidden');
        } else {
            customSinceEl.classList.add('is-hidden');
            customUntilEl.classList.add('is-hidden');
        }
    };
    timeRangeSelect.addEventListener('change', updateCustomTimeVisibility);

    // Restore previous filter state if present
    if (this.currentOptions.timeRange) {
        timeRangeSelect.value = this.currentOptions.timeRange;
    }
    if (this.currentOptions.since) {
        document.getElementById('filterSince').value = this.currentOptions.since;
    }
    if (this.currentOptions.until) {
        document.getElementById('filterUntil').value = this.currentOptions.until;
    }
    if (this.currentOptions.limit) {
        document.getElementById('filterLimit').value = this.currentOptions.limit;
    }
    if (this.currentOptions.matched) {
        document.getElementById('filterMatched').checked = true;
    }
    if (this.currentOptions.archived) {
        document.getElementById('filterArchived').checked = true;
    }
    if (this.currentOptions.id || this.currentOptions.vendor) {
        document.getElementById('filterVendor').value = this.currentOptions.id || this.currentOptions.vendor;
    }
    updateCustomTimeVisibility();

    // Attach Listener for Filter Button
    document.getElementById('applyResponseFilters').addEventListener('click', () => {
        const rawInput = document.getElementById('filterVendor').value.trim();
        const limitVal = document.getElementById('filterLimit').value;
        const matched = document.getElementById('filterMatched').checked;
        const archived = document.getElementById('filterArchived').checked;
        const timeRange = document.getElementById('filterTimeRange').value;
        const sinceVal = document.getElementById('filterSince').value;
        const untilVal = document.getElementById('filterUntil').value;

        const options = {
            start: 0,
            limit: parseInt(limitVal, 10) || 100,
            matched: matched,
            archived: archived,
            vendor: null,
            id: null,
            timeRange: timeRange,
            since: timeRange === 'custom' && sinceVal ? sinceVal : null,
            until: timeRange === 'custom' && untilVal ? untilVal : null
        };

        const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (rawInput) {
            if (uuidPattern.test(rawInput)) {
                options.id = rawInput;
            } else {
                options.vendor = rawInput;
            }
        }

        this.fetch(options);
    });

    // Attach Listener for Export CSV Button
    document.getElementById('exportResponsesBtn').addEventListener('click', () => {
        const rawInput = document.getElementById('filterVendor').value.trim();
        const matched = document.getElementById('filterMatched').checked;
        const archived = document.getElementById('filterArchived').checked;
        const timeRange = document.getElementById('filterTimeRange').value;
        const sinceVal = document.getElementById('filterSince').value;
        const untilVal = document.getElementById('filterUntil').value;

        const params = new URLSearchParams();
        const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (rawInput) {
            if (uuidPattern.test(rawInput)) {
                params.append('id', rawInput);
            } else {
                params.append('vendor', rawInput);
            }
        }

        if (matched) params.append('matched', 'true');
        if (archived) params.append('archived', 'true');
        if (timeRange) params.append('time_range', timeRange);
        if (timeRange === 'custom') {
            if (sinceVal) params.append('since', sinceVal);
            if (untilVal) params.append('until', untilVal);
        }

        window.location.href = `/exportresponses?${params.toString()}`;
    });

    // Initial Fetch
    this.fetch(this.currentOptions);
}

    async fetch(options = {}) {
        // Update local state
        this.currentOptions = { ...this.currentOptions, ...options };

        const tableContainer = document.getElementById('responseTableContainer');
        if (!tableContainer) return;

        tableContainer.innerHTML = '<p class="has-text-info">Fetching...</p><progress class="progress is-small is-info" max="100"></progress>';

        // Fetch data
        const { html, total } = await this.app.fetchResponseCache(this.currentOptions);

        // Render Table
        tableContainer.innerHTML = html;

        // UPDATE TITLE WITH COUNT
        const titleEl = document.getElementById('responseViewTitle');
        if (titleEl) titleEl.textContent = `Responses (${total})`;

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
            prevBtn.onclick = () => this.goToPage(currentPage - 1);
        } else {
            prevBtn.setAttribute('disabled', true);
            prevBtn.onclick = null;
        }

        if (currentPage < totalPages) {
            nextBtn.removeAttribute('disabled');
            nextBtn.onclick = () => this.goToPage(currentPage + 1);
        } else {
            nextBtn.setAttribute('disabled', true);
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