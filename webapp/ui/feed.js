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
    }

    /**
     * Renders the cached vulnerability feed view inside the container.
     */
    async render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        // Show loading state matching existing styling conventions
        container.innerHTML = `
            <div class="box has-background-custom">
                <p class="has-text-grey-light">Loading vulnerabilities from CISA & NIST cache...</p>
                <progress class="progress is-small is-info mt-2" max="100"></progress>
            </div>
        `;

        // Fetch data via the Application instance wrapper
        const feedItems = await this.app.fetchVulnerabilityFeed();

        if (!feedItems || feedItems.length === 0) {
            container.innerHTML = `
                <div class="box has-background-custom">
                    <p class="has-text-warning">No vulnerability feed items found or cache is rebuilding.</p>
                </div>
            `;
            return;
        }

        // Map items to Bulma components with hyperlinks to external advisories
        const itemsHtml = feedItems.map(item => {
            // Tag colors depending on threat Intel source
            const tagColor = item.source === 'CISA' ? 'is-danger' : 'is-link';
            
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

        // Inject completed frame markup into view slot
        container.innerHTML = `
            <h1 class="title has-text-info mb-4">Vulnerability Intel Feed</h1>
            <p class="subtitle is-size-6 has-text-grey-light mb-5">Aggregated live alerts from CISA and NIST. Updated every 4 hours.</p>
            <div class="feed-list-wrapper">
                ${itemsHtml}
            </div>
        `;
    }
}