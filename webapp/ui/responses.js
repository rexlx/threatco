export class ResponseController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
    }

    render() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
            <h1 class="title has-text-info">Responses</h1>
            <div class="field is-grouped">
                <p class="control is-expanded"><input class="input" type="text" id="filterVendor" placeholder="Vendor or ID"></p>
                <p class="control"><input class="input" type="number" id="filterStart" placeholder="Start (e.g., 0)"></p>
                <p class="control"><input class="input" type="number" id="filterLimit" placeholder="Limit (e.g., 100)"></p>
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
                <p class="control"><button class="button is-info" id="applyResponseFilters" type="button"><span class="icon-text"><span class="icon"><i class="material-icons">filter_list</i></span><span>Apply</span></span></button></p>
            </div>
            <hr class="has-background-grey-dark">
            <div id="responseTableContainer"><p class="has-text-info">Fetching initial responses...</p></div>`;

        // Attach Listener for Filter Button
        document.getElementById('applyResponseFilters').addEventListener('click', () => {
            const rawInput = document.getElementById('filterVendor').value.trim();
            const start = document.getElementById('filterStart').value;
            const limit = document.getElementById('filterLimit').value;
            const matched = document.getElementById('filterMatched').checked;
            const archived = document.getElementById('filterArchived').checked;

            const options = {};

            // UUID Regex (8-4-4-4-12 hex characters)
            const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

            if (rawInput) {
                if (uuidPattern.test(rawInput)) {
                    // It looks like a UUID, so we filter by ID
                    options.id = rawInput;
                } else {
                    // It's just text, so we filter by Vendor
                    options.vendor = rawInput;
                }
            }

            if (start) options.start = parseInt(start, 10);
            if (limit) options.limit = parseInt(limit, 10);
            if (matched) options.matched = true;
            if (archived) options.archived = true;
            
            this.fetch(options);
        });

        // Initial Fetch
        this.fetch();
    }

    async fetch(options = {}) {
        const tableContainer = document.getElementById('responseTableContainer');
        if (!tableContainer) return;
        
        tableContainer.innerHTML = '<p class="has-text-info">Fetching...</p><progress class="progress is-small is-info" max="100"></progress>';
        
        const cacheHtml = await this.app.fetchResponseCache(options);
        tableContainer.innerHTML = cacheHtml;

        tableContainer.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', async (event) => {
                event.preventDefault();
                const id = new URL(link.href).pathname.split('/').pop();
                if (id) {
                    const customEvent = new CustomEvent('req-open-details', { detail: id });
                    document.dispatchEvent(customEvent);
                }
            });
        });

        tableContainer.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', async (event) => {
                event.preventDefault();
                event.stopPropagation(); 
                
                const id = btn.getAttribute('data-id');
                if (!confirm(`Are you sure you want to delete response ${id}?`)) {
                    return;
                }

                btn.classList.add('is-loading');

                try {
                    const resp = await fetch('/deleteresponse', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ 
                            id: id, 
                            archived: options.archived || false 
                        })
                    });

                    if (resp.ok) {
                        await this.fetch(options);
                    } else {
                        const errText = await resp.text();
                        alert('Failed to delete: ' + errText);
                        btn.classList.remove('is-loading');
                    }
                } catch (err) {
                    console.error('Delete error:', err);
                    alert('An error occurred while deleting.');
                    btn.classList.remove('is-loading');
                }
            });
        });
    }
}