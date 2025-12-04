export class ResponseController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.currentOptions = { start: 0, limit: 100 }; // Store current state
    }

    render() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
            <h1 class="title has-text-info" id="responseViewTitle">Responses</h1>
            <div class="field is-grouped">
                <p class="control is-expanded"><input class="input" type="text" id="filterVendor" placeholder="Vendor or ID"></p>
                <p class="control"><input class="input" type="number" id="filterLimit" placeholder="Limit" value="100"></p>
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
                <p class="control"><button class="button is-info" id="applyResponseFilters" type="button"><span class="icon-text"><span class="icon"><i class="material-icons">filter_list</i></span><span>apply</span></span></button></p>
                <p class="control"><button class="button is-info" id="exportResponsesBtn" type="button"><span class="icon-text"><span class="icon"><i class="material-icons">file_download</i></span><span>export</span></span></button></p>
            </div>
            <hr class="has-background-grey-dark">
            <div id="responseTableContainer"><p class="has-text-info">Fetching initial responses...</p></div>
            <nav class="pagination is-centered is-rounded mt-4" role="navigation" aria-label="pagination">
                <a class="pagination-previous" id="prevPageBtn" disabled>Previous</a>
                <a class="pagination-next" id="nextPageBtn" disabled>Next</a>
                <ul class="pagination-list" id="paginationList">
                    </ul>
            </nav>`;

        // Attach Listener for Filter Button
        document.getElementById('applyResponseFilters').addEventListener('click', () => {
            const rawInput = document.getElementById('filterVendor').value.trim();
            const limitVal = document.getElementById('filterLimit').value;
            const matched = document.getElementById('filterMatched').checked;
            const archived = document.getElementById('filterArchived').checked;

            // Reset to start 0 on new filter
            const options = {
                start: 0,
                limit: parseInt(limitVal, 10) || 100,
                matched: matched,     // Passes true or false
                archived: archived,   // Passes true or false
                vendor: null,         // Reset vendor
                id: null              // Reset ID
            };

            // UUID Regex
            const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            if (rawInput) {
                if (uuidPattern.test(rawInput)) {
                    options.id = rawInput;
                } else {
                    options.vendor = rawInput;
                }
            }

            // if (matched) options.matched = true;
            // if (archived) options.archived = true;

            this.fetch(options);
        });

        // Attach Listener for Export CSV Button
        document.getElementById('exportResponsesBtn').addEventListener('click', () => {
            const rawInput = document.getElementById('filterVendor').value.trim();
            const matched = document.getElementById('filterMatched').checked;
            const archived = document.getElementById('filterArchived').checked;

            const params = new URLSearchParams();

            // Reuse logic to determine if input is UUID or Vendor
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

            // Trigger the download by navigating to the URL
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
        container.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', async (event) => {
                event.preventDefault();
                const id = new URL(link.href).pathname.split('/').pop();
                if (id) {
                    const customEvent = new CustomEvent('req-open-details', { detail: id });
                    document.dispatchEvent(customEvent);
                }
            });
        });

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
                        body: JSON.stringify({ id: id, archived: this.currentOptions.archived || false })
                    });

                    if (resp.ok) {
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