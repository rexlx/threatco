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
                <p class="control is-expanded"><input class="input" type="text" id="filterVendor" placeholder="Vendor"></p>
                <p class="control"><input class="input" type="number" id="filterStart" placeholder="Start (e.g., 0)"></p>
                <p class="control"><input class="input" type="number" id="filterLimit" placeholder="Limit (e.g., 100)"></p>
                <p class="control">
                    <label class="checkbox">
                        <input type="checkbox" id="filterMatched"> only matches
                    </label>
                </p>
                <p class="control"><button class="button is-info" id="applyResponseFilters" type="button"><span class="icon-text"><span class="icon"><i class="material-icons">filter_list</i></span><span>Apply</span></span></button></p>
            </div>
            <hr class="has-background-grey-dark">
            <div id="responseTableContainer"><p class="has-text-info">Fetching initial responses...</p></div>`;

        // Attach Listener for Filter Button
        document.getElementById('applyResponseFilters').addEventListener('click', () => {
            const vendor = document.getElementById('filterVendor').value;
            const start = document.getElementById('filterStart').value;
            const limit = document.getElementById('filterLimit').value;
            const matched = document.getElementById('filterMatched').checked;

            const options = {};
            if (vendor) options.vendor = vendor;
            if (start) options.start = parseInt(start, 10);
            if (limit) options.limit = parseInt(limit, 10);
            if (matched) options.matched = true;
            
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

        // Re-attach listeners to the new links in the HTML returned by the server
        tableContainer.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', async (event) => {
                event.preventDefault();
                const id = new URL(link.href).pathname.split('/').pop();
                if (id) {
                    // Dispatch event to open modal (handled in renderer.js)
                    const customEvent = new CustomEvent('req-open-details', { detail: id });
                    document.dispatchEvent(customEvent);
                }
            });
        });
    }
}
