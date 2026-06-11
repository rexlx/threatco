/**
 * webapp/ui/feed.js
 * Controller handling rendering and UI logic for the CISA/NIST vulnerability feed.
 */
export class FeedController {
    /**
     * @param {string} containerId - The DOM ID of the container element ('feedContainer')
     * @param {Application} app - The core Application instance
     */
    constructor(containerId, app) {
        this.containerId = containerId;
        this.app = app;
        this.feedItems = []; // Store raw items for dynamic filtering
        this.currentFilter = 'All'; // Track current filter state
    }

    /**
     * Fetches raw feed data and initializes the layout.
     */
    async render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        // Show loading state matching existing styling conventions
        container.innerHTML = `
            <div class="box has-background-custom">
                <p class="has-text-grey-light">Loading vulnerabilities from cache...</p>
                <progress class="progress is-small is-info mt-2" max="100"></progress>
            </div>
        `;

        // Fetch and cache raw data via the Application instance wrapper
        this.feedItems = await this.app.fetchVulnerabilityFeed();

        if (!this.feedItems || this.feedItems.length === 0) {
            container.innerHTML = `
                <div class="box has-background-custom">
                    <p class="has-text-warning">No vulnerability feed items found or cache is rebuilding.</p>
                </div>
            `;
            return;
        }

        // Dynamically extract unique sources from the feed dataset
        const dynamicSources = [...new Set(
            this.feedItems
                .map(item => item.source)
                .filter(source => typeof source === 'string' && source.trim() !== '')
        )].sort();

        // Build the option elements markup for our dropdown filter
        const filterOptionsHtml = [
            '<option value="All">All Sources</option>',
            ...dynamicSources.map(source => `<option value="${source}">${source}</option>`)
        ].join('');

        // Render template scaffolding frame with the dynamic filter control
        container.innerHTML = `
            <div class="is-flex is-justify-content-between is-align-items-center mb-4">
                <div>
                    <h1 class="title has-text-info mb-1">Vulnerability Intel Feed</h1>
                    <p class="subtitle is-size-6 has-text-grey-light mb-0">Aggregated live alerts from centralized caches. Updated periodically.</p>
                </div>
                <div class="field mb-0">
                    <div class="control has-icons-left">
                        <div class="select is-small">
                            <select id="feedSourceFilter">
                                ${filterOptionsHtml}
                            </select>
                        </div>
                        <span class="icon is-small is-left">
                            <i class="material-icons">filter_list</i>
                        </span>
                    </div>
                </div>
            </div>
            <div class="feed-list-wrapper" id="feedListItems"></div>
        `;

        // Bind event handler to the dynamic filter dropdown
        const filterSelect = document.getElementById('feedSourceFilter');
        if (filterSelect) {
            // Re-apply previous filter value if it matches an option, fallback to 'All'
            if (this.currentFilter !== 'All' && !dynamicSources.includes(this.currentFilter)) {
                this.currentFilter = 'All';
            }
            filterSelect.value = this.currentFilter;
            
            filterSelect.addEventListener('change', (e) => {
                this.currentFilter = e.target.value;
                this.updateList();
            });
        }

        // Initially render the items list
        this.updateList();
    }

    /**
     * Filters, maps, and injects item list HTML depending on filter criteria.
     */
    updateList() {
        const listContainer = document.getElementById('feedListItems');
        if (!listContainer) return;

        // Filter feed items safely by testing source matching
        const filteredItems = this.feedItems.filter(item => {
            if (this.currentFilter === 'All') return true;
            return item.source === this.currentFilter;
        });

        if (filteredItems.length === 0) {
            listContainer.innerHTML = `
                <div class="box has-background-custom">
                    <p class="has-text-grey-light is-italic">No vulnerabilities match the selected source filter.</p>
                </div>
            `;
            return;
        }

        // Map matching items to Bulma markup components
        listContainer.innerHTML = filteredItems.map(item => {
            // Tag colors depending on threat Intel source
            let tagColor = 'is-link';
            if (item.source === 'CISA') tagColor = 'is-danger';
            else if (item.source === 'NIST') tagColor = 'is-info';
            
            // Defensively check for arrays to prevent rendering pipeline breakage
            let iocHtml = '';
            if (item.iocs && Array.isArray(item.iocs) && item.iocs.length > 0) {
                iocHtml = `
                    <div class="ioc-enrichment-box mt-3 p-3 has-background-dark style-radius" style="border-left: 3px solid #ffdd57; border-radius: 4px;">
                        <strong class="is-size-7 has-text-warning uppercase tracking-wider block mb-2">Correlated MISP Indicators:</strong>
                        <div class="tags">
                            ${item.iocs.map(ioc => `<span class="tag is-dark has-text-info is-family-code">${ioc}</span>`).join('')}
                        </div>
                    </div>
                `;
            } else {
                iocHtml = `
                    <div class="mt-2 is-size-7 has-text-grey-light is-italic">
                        No known open-source technical indicators associated in current pool.
                    </div>
                `;
            }
            
            return `
                <div class="box has-background-custom mb-3">
                    <div class="columns is-mobile is-vcentered">
                        <div class="column">
                            <span class="tag ${tagColor} is-light mb-1">${item.source}</span>
                            <h4 class="title is-size-5 mb-1">
                                <a href="${item.url}" target="_blank" rel="noopener noreferrer" class="has-text-info">
                                    ${item.title || 'Unknown Identifier'}
                                </a>
                            </h4>
                            <p class="has-text-white-ter is-size-6">${item.description || 'No description provided.'}</p>
                            
                            ${iocHtml}
                            
                            ${item.published ? `<p class="is-size-7 has-text-grey-light mt-2">Cached/Published: ${new Date(item.published).toLocaleString()}</p>` : ''}
                        </div>
                        <div class="column is-narrow">
                            <a href="${item.url}" target="_blank" rel="noopener noreferrer" class="button is-small is-info is-outlined">
                                <span class="icon"><i class="material-icons">open_in_new</i></span>
                            </a>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }
}