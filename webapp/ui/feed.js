/**
 * webapp/ui/feed.js
 * Controller handling rendering and UI logic for the CISA/NIST vulnerability feed.
 * Updates the layout to sit the colored CWE indicator tiles directly next to the source tags.
 */
import { escapeHtml } from './utils.js';
import { Contextualizer } from '../parser.js';

export class FeedController {
    /**
     * @param {string} containerId - The DOM ID of the container element ('feedContainer')
     * @param {Application} app - The core Application instance
     */
    constructor(containerId, app) {
        this.containerId = containerId;
        this.app = app;
        this.contextualizer = new Contextualizer();
        this.feedItems = []; // Store raw items for dynamic filtering
        this.currentFilter = 'All'; // Track current filter state

        // Standardized 25-item tracking dictionary for tooltips
        this.cweDescriptions = {
            "CWE-20":   "Improper Input Validation",
            "CWE-22":   "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "CWE-78":   "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "CWE-79":   "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "CWE-89":   "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "CWE-94":   "Improper Control of Generation of Code ('Code Injection')",
            "CWE-119":  "Improper Restriction of Operations within the Bounds of a Memory Buffer",
            "CWE-120":  "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
            "CWE-125":  "Out-of-bounds Read",
            "CWE-190":  "Integer Overflow or Wraparound",
            "CWE-200":  "Exposure of Sensitive Information to an Unauthorized Actor",
            "CWE-269":  "Improper Privilege Management",
            "CWE-276":  "Incorrect Default Permissions",
            "CWE-287":  "Improper Authentication",
            "CWE-295":  "Improper Certificate Validation",
            "CWE-306":  "Missing Authentication for Critical Function",
            "CWE-352":  "Cross-Site Request Forgery (CSRF)",
            "CWE-416":  "Use After Free",
            "CWE-434":  "Unrestricted Upload of File with Dangerous Type",
            "CWE-502":  "Deserialization of Untrusted Data",
            "CWE-522":  "Insufficiently Protected Credentials (or Use of Hard-Coded Credentials)",
            "CWE-611":  "Improper Restriction of XML External Entity Reference ('XXE')",
            "CWE-732":  "Incorrect Permission Assignment for Critical Resource",
            "CWE-787":  "Out-of-bounds Write",
            "CWE-862":  "Missing Authorization",
            "CWE-863":  "Incorrect Authorization"
        };
    }

    /**
     * Fetches raw feed data and initializes the layout.
     */
    async render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;
        container.classList.remove('is-hidden');
        // container.classList.remove('has-background-custom');
        // container.classList.add('has-background-black');

        // Show loading state matching terminal window conventions
        container.innerHTML = `
            <div class="users-nav-bar feed-nav-bar mb-3" id="feed-top">
                <div class="users-nav-left">
                    <div class="users-nav-title-group">
                        <span class="users-nav-title">Vulnerability Intel Feed</span>
                        <span class="tag is-info is-dark is-rounded charts-count-badge" id="feedCountBadge">Checking...</span>
                    </div>
                </div>
                <div class="users-nav-right">
                    <button type="button" class="button is-small is-dark is-outlined" disabled>↻ Refresh</button>
                </div>
            </div>

            <div class="users-window feed-window" id="feedViewer">
                <div class="terminal-titlebar">
                    <!-- <div class="terminal-dots">
                    <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div> -->
                    <div class="terminal-title">
                        <span class="terminal-status-dot"></span>
                        <span>vulnerability feed</span>
                    </div>
                    <div class="terminal-actions">
                        <span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>SYNCING...</span>
                    </div>
                </div>

                <div class="terminal-table-container">
                    <table class="terminal-table users-table feed-table">
                        <thead>
                            <tr>
                                <th class="feed-th-source">SOURCE</th>
                                <th class="feed-th-vuln">VULNERABILITY &amp; INTEL</th>
                                <th class="feed-th-date">PUBLISHED</th>
                                <th class="feed-th-actions">ACTIONS</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr class="terminal-table-row">
                                <td colspan="4" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                                    <p class="has-text-info mb-2">Loading vulnerabilities from cache...</p>
                                    <progress class="progress is-small is-info" max="100"></progress>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="terminal-statusbar">
                    <span>Querying vulnerability telemetry cache...</span>
                    <span class="is-pulled-right">threatco intel &bull; cve feed</span>
                </div>
            </div>
        `;

        // Fetch and cache raw data via the Application instance wrapper
        this.feedItems = await this.app.fetchVulnerabilityFeed();

        if (!this.feedItems || this.feedItems.length === 0) {
            container.innerHTML = `
                <div class="users-nav-bar feed-nav-bar mb-3" id="feed-top">
                    <div class="users-nav-left">
                        <div class="users-nav-title-group">
                            <span class="users-nav-title">Vulnerability Intel Feed</span>
                            <span class="tag is-warning is-dark is-rounded charts-count-badge" id="feedCountBadge">0 alerts</span>
                        </div>
                    </div>
                    <div class="users-nav-right">
                        <button type="button" class="button is-small is-dark is-outlined" id="feedRefreshBtn" title="Retry fetching feed">↻ Refresh</button>
                    </div>
                </div>

                <div class="users-window feed-window" id="feedViewer">
                    <div class="terminal-titlebar">
                        <!-- <div class="terminal-dots">
                    <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div> -->
                        <div class="terminal-title">
                            <span class="terminal-status-dot"></span>
                            <span>vulnerability feed</span>
                        </div>
                        <div class="terminal-actions">
                            <span class="system-status-pill status-warning"><span class="status-indicator-dot dot-warning"></span>NO DATA</span>
                        </div>
                    </div>

                    <div class="terminal-table-container">
                        <table class="terminal-table users-table feed-table">
                            <thead>
                                <tr>
                                    <th class="feed-th-source">SOURCE</th>
                                    <th class="feed-th-vuln">VULNERABILITY &amp; INTEL</th>
                                    <th class="feed-th-date">PUBLISHED</th>
                                    <th class="feed-th-actions">ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="terminal-table-row">
                                    <td colspan="4" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                                        No vulnerability feed items found or cache is rebuilding.
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="terminal-statusbar">
                        <span>0 records found in telemetry cache</span>
                        <span class="is-pulled-right">threatco intel &bull; cve feed</span>
                    </div>
                </div>
            `;
            const refreshBtn = document.getElementById('feedRefreshBtn');
            if (refreshBtn) {
                refreshBtn.addEventListener('click', async () => {
                    refreshBtn.classList.add('is-loading');
                    await this.render();
                });
            }
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
            ...dynamicSources.map(source => `<option value="${escapeHtml(source)}">${escapeHtml(source)}</option>`)
        ].join('');

        // Render template scaffolding frame with the dynamic filter control, terminal window, and modals
        container.innerHTML = `
            <div class="users-nav-bar feed-nav-bar mb-3" id="feed-top">
                <div class="users-nav-left">
                    <div class="users-nav-title-group">
                        <span class="users-nav-title">Vulnerability Intel Feed</span>
                        <span class="tag is-info is-dark is-rounded charts-count-badge" id="feedCountBadge">${this.feedItems.length} alerts</span>
                    </div>
                </div>
                <div class="users-nav-right">
                    <div class="field mb-0">
                        <div class="control has-icons-left">
                            <div class="select is-small terminal-select">
                                <select id="feedSourceFilter">
                                    ${filterOptionsHtml}
                                </select>
                            </div>
                            <span class="icon is-small is-left">
                                <i class="material-icons" style="font-size: 14px;">filter_list</i>
                            </span>
                        </div>
                    </div>
                    <button type="button" class="button is-small is-dark is-outlined" id="feedRefreshBtn" title="Refresh vulnerability feed">↻ Refresh</button>
                </div>
            </div>

            <div class="users-window feed-window" id="feedViewer">
                <div class="terminal-titlebar">
                    <!-- <div class="terminal-dots">
                    <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div> -->
                    <div class="terminal-title">
                        <span class="terminal-status-dot"></span>
                        <span>vulnerability feed</span>
                    </div>
                    <div class="terminal-actions">
                        <span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>INTEL LIVE</span>
                    </div>
                </div>

                <div class="terminal-table-container">
                    <table class="terminal-table users-table feed-table">
                        <thead>
                            <tr>
                                <th class="feed-th-source">SOURCE</th>
                                <th class="feed-th-vuln">VULNERABILITY &amp; INTEL</th>
                                <th class="feed-th-date">PUBLISHED</th>
                                <th class="feed-th-actions">ACTIONS</th>
                            </tr>
                        </thead>
                        <tbody id="feedTableBody"></tbody>
                    </table>
                </div>

                <div class="terminal-statusbar">
                    <span id="feedStatusbarText">Showing ${this.feedItems.length} of ${this.feedItems.length} alerts</span>
                    <span class="is-pulled-right">threatco intel &bull; cve feed</span>
                </div>
            </div>

            <!-- Feed Case Modal (Terminal Modal) -->
            <div class="modal terminal-modal" id="feedCaseModal">
                <div class="modal-background"></div>
                <div class="modal-card details-modal-card">
                    <header class="modal-card-head terminal-titlebar details-modal-titlebar">
                        <!-- <div class="terminal-dots">
                    <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div> -->
                        <div class="terminal-title details-modal-title-wrap">
                            <span class="terminal-status-dot details-status-dot"></span>
                            <span class="modal-card-title details-modal-title" id="feedCaseModalTitle">Open Case for Vulnerability</span>
                        </div>
                        <div class="terminal-actions details-modal-actions">
                            <span class="system-status-pill details-status-pill">
                                <span class="status-indicator-dot dot-details"></span>FEED INTEL
                            </span>
                            <button class="button is-small terminal-action-btn modal-close-btn delete" aria-label="close" title="Close modal">
                                <span class="icon is-small"><i class="material-icons">close</i></span>
                            </button>
                        </div>
                    </header>
                    <section class="modal-card-body details-modal-body">
                        <div class="modal-subform-container">
                            <form id="feedCaseForm" novalidate>
                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Target Case</label>
                                    <div class="control">
                                        <div class="select is-fullwidth terminal-select">
                                            <select id="feedTargetCaseId">
                                                <option value="">-- Create New Case --</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <div id="feedNewCaseFields">
                                    <div class="field mb-3">
                                        <label class="label terminal-form-label">Case Name *</label>
                                        <div class="control">
                                            <input class="input terminal-input" type="text" id="feedCaseName" placeholder="e.g. Investigation: CVE-2024-XXXX">
                                        </div>
                                    </div>
                                    <div class="field mb-3">
                                        <label class="label terminal-form-label">Description</label>
                                        <div class="control">
                                            <textarea class="textarea terminal-textarea" id="feedCaseDesc" rows="3" placeholder="Case details..."></textarea>
                                        </div>
                                    </div>
                                </div>
                                <div class="field mb-3">
                                    <div class="is-flex is-justify-content-space-between is-align-items-center mb-1">
                                        <label class="label terminal-form-label mb-0">Associated Indicators / CVE</label>
                                        <span class="terminal-form-help">Line breaks or commas separated</span>
                                    </div>
                                    <div class="control">
                                        <textarea class="textarea terminal-textarea font-mono" id="feedCaseIocs" rows="2" placeholder="Indicators..."></textarea>
                                    </div>
                                </div>
                                <div id="feedCaseResult" class="mt-2"></div>
                                <div class="buttons is-right mt-3">
                                    <button type="button" class="button terminal-action-btn" id="feedCaseCancelBtn">Cancel</button>
                                    <button type="submit" class="button terminal-action-btn modal-btn-case" id="feedCaseSubmitBtn">
                                        <span class="icon is-small"><i class="material-icons">work</i></span>
                                        <span>Create / Update Case</span>
                                    </button>
                                </div>
                            </form>
                        </div>
                    </section>
                </div>
            </div>

            <!-- Feed AI Report Modal (Terminal Modal) -->
            <div class="modal terminal-modal" id="feedAiReportModal">
                <div class="modal-background"></div>
                <div class="modal-card details-modal-card" style="max-width: 580px;">
                    <header class="modal-card-head terminal-titlebar details-modal-titlebar">
                        <!-- <div class="terminal-dots">
                    <span class="terminal-dot dot-close modal-close-dot" title="Close modal"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div> -->
                        <div class="terminal-title details-modal-title-wrap">
                            <span class="terminal-status-dot details-status-dot"></span>
                            <span class="modal-card-title details-modal-title">Cached AI Report Available</span>
                        </div>
                        <div class="terminal-actions details-modal-actions">
                            <span class="system-status-pill details-status-pill">
                                <span class="status-indicator-dot dot-details"></span>REPORT CACHE
                            </span>
                            <button class="button is-small terminal-action-btn modal-close-btn delete" aria-label="close" id="feedAiReportModalClose" title="Close modal">
                                <span class="icon is-small"><i class="material-icons">close</i></span>
                            </button>
                        </div>
                    </header>
                    <section class="modal-card-body details-modal-body">
                        <div class="modal-subform-container">
                            <p class="is-size-6 mb-3" style="color: #cbd5e1;">
                                An AI Report for <strong id="feedAiReportCveText" style="color: var(--modal-accent-light, #fbbf24);">CVE-XXXX-YYYY</strong> was previously generated on <span id="feedAiReportDateText" class="has-text-weight-bold" style="color: #f1f5f9;">--</span>.
                            </p>
                            <p class="is-size-6" style="color: #94a3b8;">
                                Would you like to view the cached report or rerun the report to fetch fresh data?
                            </p>
                        </div>
                    </section>
                    <footer class="modal-card-foot details-modal-foot">
                        <div class="details-foot-left">
                            <button type="button" class="button terminal-action-btn modal-btn-copy" id="feedAiReportViewBtn" title="Open cached AI report">
                                <span class="icon is-small"><i class="material-icons">visibility</i></span>
                                <span>View Cached Report</span>
                            </button>
                            <button type="button" class="button terminal-action-btn modal-btn-archive" id="feedAiReportRerunBtn" title="Regenerate fresh AI report">
                                <span class="icon is-small"><i class="material-icons">refresh</i></span>
                                <span>Rerun Report</span>
                            </button>
                        </div>
                        <div class="details-foot-right">
                            <button type="button" class="button terminal-action-btn" id="feedAiReportCancelBtn">Cancel</button>
                        </div>
                    </footer>
                </div>
            </div>
        `;

        // Bind event handler to the dynamic filter dropdown
        const filterSelect = document.getElementById('feedSourceFilter');
        if (filterSelect) {
            if (this.currentFilter !== 'All' && !dynamicSources.includes(this.currentFilter)) {
                this.currentFilter = 'All';
            }
            filterSelect.value = this.currentFilter;
            
            filterSelect.addEventListener('change', (e) => {
                this.currentFilter = e.target.value;
                this.updateList();
            });
        }

        // Bind refresh button
        const refreshBtn = document.getElementById('feedRefreshBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', async () => {
                refreshBtn.classList.add('is-loading');
                await this.render();
            });
        }

        // Initially render the items list
        this.updateList();
    }

    updateList() {
        const tableBody = document.getElementById('feedTableBody');
        if (!tableBody) return;

        // Filter feed items safely by testing source matching
        const filteredItems = this.feedItems.filter(item => {
            if (this.currentFilter === 'All') return true;
            return item.source === this.currentFilter;
        });

        // Update count badge & statusbar text
        const badge = document.getElementById('feedCountBadge');
        if (badge) {
            badge.textContent = this.currentFilter === 'All'
                ? `${filteredItems.length} alerts`
                : `${filteredItems.length} / ${this.feedItems.length} alerts`;
        }

        const statusText = document.getElementById('feedStatusbarText');
        if (statusText) {
            statusText.textContent = `Showing ${filteredItems.length} of ${this.feedItems.length} alerts • Filter: ${this.currentFilter}`;
        }

        if (filteredItems.length === 0) {
            tableBody.innerHTML = `
                <tr class="terminal-table-row">
                    <td colspan="4" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                        No vulnerabilities match the selected source filter.
                    </td>
                </tr>
            `;
            return;
        }

        // Map matching items to terminal table rows
        tableBody.innerHTML = filteredItems.map((item, index) => {
            const cveMatch = item.title ? item.title.match(/CVE-\d{4}-\d+/i) : null;
            const cveIdentifier = cveMatch ? cveMatch[0].toUpperCase() : (item.title || '');

            // Tag colors depending on threat Intel source
            let tagColor = 'is-link';
            if (item.source === 'CISA') tagColor = 'is-danger';
            else if (item.source === 'NIST' || item.source === 'NIST/CIRCL') tagColor = 'is-info';
            else if (item.source === 'Red Hat') tagColor = 'is-danger is-light';
            else if (item.source === 'Canonical') tagColor = 'is-warning is-light';
            
            // Generate inline CWE elements if present on the record
            let cweHtml = '';
            if (item.cwes && Array.isArray(item.cwes) && item.cwes.length > 0) {
                cweHtml = item.cwes.map(cwe => {
                    if (!cwe || cwe.trim() === "") return '';

                    const description = this.cweDescriptions[cwe] || "Advisory-specified technical weakness category.";
                    const numericId = cwe.replace(/\D/g, '');
                    const externalUrl = numericId ? `https://cwe.mitre.org/data/definitions/${numericId}.html` : 'https://cwe.mitre.org/';

                    // Contextual risk-based color-coding
                    let cweColorStyle = 'background-color: #3273dc; color: #fff;'; 
                    if (['CWE-787', 'CWE-119', 'CWE-94', 'CWE-89'].includes(cwe)) {
                        cweColorStyle = 'background-color: #83021b; color: #fff;'; 
                    } else if (['CWE-20', 'CWE-22', 'CWE-287', 'CWE-416'].includes(cwe)) {
                        cweColorStyle = 'background-color: #ffdd57; color: #4a4a4a;'; 
                    }

                    return `
                        <a href="${externalUrl}" 
                           target="_blank" 
                           rel="noopener noreferrer" 
                           class="tag font-weight-bold is-family-code mr-1 mb-1" 
                           style="${cweColorStyle} font-size: 0.7rem; border-radius: 3px; display: inline-block; cursor: pointer; text-decoration: none !important;"
                           title="${escapeHtml(cwe)}: ${escapeHtml(description)} (Click to view official MITRE details)">
                            ${escapeHtml(cwe)}
                        </a>
                    `;
                }).join('');
            }

            // Generate Campaign tags if present
            let campaignHtml = '';
            if (item.campaigns && Array.isArray(item.campaigns) && item.campaigns.length > 0) {
                campaignHtml = `
                    <div class="is-flex is-align-items-center is-flex-wrap-wrap mt-2">
                        <span class="is-flex is-align-items-center mr-2 mb-1">
                            <span class="icon is-small has-text-danger mr-1">
                                <i class="material-icons" style="font-size: 14px;">flag</i>
                            </span>
                            <strong class="is-size-7 has-text-danger uppercase mr-2" style="letter-spacing: 0.5px; font-family: 'IBMPlexMono', monospace;">
                                Campaigns / Actors:
                            </strong>
                        </span>
                        <div class="tags mb-0">
                            ${item.campaigns.map(camp => `
                                <span class="tag is-danger is-light is-family-code is-small mb-1" style="border: 1px solid rgba(255, 56, 96, 0.3); height: 1.6em;">
                                    ${escapeHtml(camp)}
                                </span>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            // Generate CAPEC Attack Pattern tags if present from CIRCL
            let capecHtml = '';
            if (item.capec && Array.isArray(item.capec) && item.capec.length > 0) {
                capecHtml = `
                    <div class="is-flex is-align-items-center is-flex-wrap-wrap mt-2">
                        <span class="is-flex is-align-items-center mr-2 mb-1">
                            <span class="icon is-small has-text-info mr-1">
                                <i class="material-icons" style="font-size: 14px;">security</i>
                            </span>
                            <strong class="is-size-7 has-text-info uppercase mr-2" style="letter-spacing: 0.5px; font-family: 'IBMPlexMono', monospace;">
                                CAPEC Patterns:
                            </strong>
                        </span>
                        <div class="tags mb-0">
                            ${item.capec.map(capec => {
                                const capecId = typeof capec === 'string' ? capec : (capec.id || 'CAPEC');
                                const capecName = typeof capec === 'object' && capec.name ? `: ${capec.name}` : '';
                                const numericCapec = capecId.replace(/\D/g, '');
                                const capecUrl = numericCapec ? `https://capec.mitre.org/data/definitions/${numericCapec}.html` : 'https://capec.mitre.org/';
                                return `
                                    <a href="${capecUrl}" 
                                       target="_blank" 
                                       rel="noopener noreferrer" 
                                       class="tag is-info is-light is-family-code is-small mb-1" 
                                       style="border: 1px solid rgba(50, 115, 220, 0.3); height: 1.6em; text-decoration: none !important;">
                                        ${escapeHtml(capecId)}${escapeHtml(capecName)}
                                    </a>
                                `;
                            }).join('')}
                        </div>
                    </div>
                `;
            }

            // Defensively check for arrays to prevent rendering pipeline breakage
            let iocHtml = '';
            if (item.iocs && Array.isArray(item.iocs) && item.iocs.length > 0) {
                // Separate Event ID from actual IOC indicators
                const eventIdEntry = item.iocs.find(ioc => typeof ioc === 'string' && ioc.startsWith('Event ID:'));
                const eventId = eventIdEntry ? eventIdEntry.replace('Event ID:', '').trim() : null;

                // Filter out the Event ID and exact duplicate of the full title
                const indicators = item.iocs.filter(ioc => 
                    typeof ioc === 'string' && 
                    !ioc.startsWith('Event ID:') && 
                    ioc !== item.title
                );

                iocHtml = `
                    <div class="is-flex is-align-items-center is-flex-wrap-wrap mt-2">
                        <span class="is-flex is-align-items-center mr-2 mb-1">
                            <span class="icon is-small has-text-warning mr-1">
                                <i class="material-icons" style="font-size: 14px;">hub</i>
                            </span>
                            <strong class="is-size-7 has-text-warning uppercase mr-2" style="letter-spacing: 0.5px; font-family: 'IBMPlexMono', monospace;">
                                Indicators / IOCs:
                            </strong>
                            ${eventId ? `
                                <span class="tag is-dark is-small is-family-code" style="border: 1px solid rgba(255, 221, 87, 0.35); color: #ffdd57; height: 1.6em; padding: 0 6px;">
                                    MISP Event #${escapeHtml(eventId)}
                                </span>
                            ` : ''}
                        </span>

                        <div class="tags mb-0">
                            ${indicators.length > 0 ? indicators.map(ioc => `
                                <span class="tag is-dark is-family-code is-small mb-1" style="background-color: #0b141c; border: 1px solid rgba(56, 189, 248, 0.25); color: #38bdf8; height: 1.6em;">
                                    <span class="icon is-small mr-1" style="opacity: 0.7;"><i class="material-icons" style="font-size: 11px;">crisis_alert</i></span>
                                    ${escapeHtml(ioc)}
                                </span>
                            `).join('') : '<span class="is-size-7 has-text-grey-light is-italic">No additional IOCs</span>'}
                        </div>
                    </div>
                `;
            }

            // Published date formatting
            let pubTimeRFC = '';
            let pubTimeFormatted = '—';
            if (item.published) {
                const pubDate = new Date(item.published);
                if (!isNaN(pubDate.getTime())) {
                    pubTimeRFC = pubDate.toISOString();
                    pubTimeFormatted = pubDate.toLocaleDateString() + ' ' + pubDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                }
            }
            
            return `
                <tr class="terminal-table-row">
                    <td class="feed-cell-source">
                        <span class="tag ${tagColor} is-family-code is-small" style="font-weight: 600; width: 100%; border-radius: 4px;">
                            ${escapeHtml(item.source)}
                        </span>
                    </td>
                    <td class="feed-cell-vuln">
                        <div class="is-flex is-align-items-center is-flex-wrap-wrap mb-1">
                            ${cweHtml}
                            ${item.case_id ? `
                                <span class="tag is-warning is-light mb-1 ml-1 is-family-code is-small" style="border: 1px solid rgba(255, 221, 87, 0.4); height: 1.6em;" title="Associated with Case: ${escapeHtml(item.case_name || item.case_id)}${item.matched_by ? ' (Matched via ' + escapeHtml(item.matched_by) + ')' : ''}">
                                    <span class="icon is-small mr-1"><i class="material-icons" style="font-size: 12px;">work</i></span>
                                    ${escapeHtml(item.case_name || 'Case: ' + item.case_id)}
                                    ${item.matched_by ? `<span class="is-size-7 ml-1 has-text-grey-dark">(${escapeHtml(item.matched_by)})</span>` : ''}
                                </span>
                            ` : ''}
                        </div>

                        <div>
                            <a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer" class="feed-item-title">
                                ${escapeHtml(item.title || 'Unknown Identifier')}
                            </a>
                        </div>
                        
                        <div class="feed-item-desc">${escapeHtml(item.description || 'No description provided.')}</div>
                        
                        ${campaignHtml}
                        ${capecHtml}
                        ${iocHtml}
                    </td>
                    <td class="feed-cell-date" title="${escapeHtml(pubTimeRFC)}">${escapeHtml(pubTimeFormatted)}</td>
                    <td class="feed-cell-actions">
                        <div class="user-action-group">
                            ${item.case_id ? `
                                <button class="button is-small terminal-action-btn terminal-btn-warning btn-feed-view-case" data-case-id="${escapeHtml(item.case_id)}" title="View associated case: ${escapeHtml(item.case_name || item.case_id)}${item.matched_by ? ' (Matched via ' + escapeHtml(item.matched_by) + ')' : ''}">
                                    <span class="icon is-small"><i class="material-icons">visibility</i></span>
                                </button>
                            ` : ''}
                            <button class="button is-small terminal-action-btn terminal-btn-primary btn-feed-ai-report" data-cve="${escapeHtml(cveIdentifier)}" title="Generate AI Report">
                                <span class="icon is-small"><i class="material-icons">auto_awesome</i></span>
                            </button>
                            <button class="button is-small terminal-action-btn modal-btn-case btn-feed-open-case" data-index="${index}" title="Open or update case for this CVE">
                                <span class="icon is-small"><i class="material-icons">work_outline</i></span>
                            </button>
                            <a href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer" class="button is-small terminal-action-btn" title="Open reference link">
                                <span class="icon is-small"><i class="material-icons">open_in_new</i></span>
                            </a>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        tableBody.querySelectorAll('.btn-feed-view-case').forEach(btn => {
            btn.onclick = (e) => {
                const caseId = e.currentTarget.dataset.caseId;
                if (caseId) {
                    document.dispatchEvent(new CustomEvent('req-open-case', { detail: caseId }));
                }
            };
        });

        tableBody.querySelectorAll('.btn-feed-ai-report').forEach(btn => {
            btn.onclick = async (e) => {
                const cve = e.currentTarget.dataset.cve;
                if (!cve) return;
                await this.handleAiReportClick(cve);
            };
        });

        tableBody.querySelectorAll('.btn-feed-open-case').forEach(btn => {
            btn.onclick = (e) => {
                const idx = parseInt(e.currentTarget.dataset.index, 10);
                const item = filteredItems[idx];
                if (item) {
                    this.openCaseModal(item);
                }
            };
        });
    }

    async handleAiReportClick(cve) {
        try {
            const res = await fetch(`/aireport/check?id=${encodeURIComponent(cve)}`);
            if (res.ok) {
                const data = await res.json();
                if (data.exists) {
                    this.showAiReportModal(cve, data.created_at);
                    return;
                }
            }
        } catch (err) {
            console.warn("Failed to check AI report cache status:", err);
        }
        window.open(`/aireport?id=${encodeURIComponent(cve)}`, '_blank');
    }

    showAiReportModal(cve, createdAt) {
        const modal = document.getElementById('feedAiReportModal');
        if (!modal) {
            window.open(`/aireport?id=${encodeURIComponent(cve)}`, '_blank');
            return;
        }

        const cveText = document.getElementById('feedAiReportCveText');
        const dateText = document.getElementById('feedAiReportDateText');
        if (cveText) cveText.textContent = cve;
        if (dateText) {
            dateText.textContent = createdAt ? new Date(createdAt).toLocaleString() : 'a previous session';
        }

        const viewBtn = document.getElementById('feedAiReportViewBtn');
        const rerunBtn = document.getElementById('feedAiReportRerunBtn');
        const cancelBtn = document.getElementById('feedAiReportCancelBtn');
        const closeBtn = document.getElementById('feedAiReportModalClose');

        const closeModal = () => modal.classList.remove('is-active');

        if (viewBtn) {
            viewBtn.onclick = () => {
                closeModal();
                window.open(`/aireport?id=${encodeURIComponent(cve)}`, '_blank');
            };
        }

        if (rerunBtn) {
            rerunBtn.onclick = () => {
                closeModal();
                window.open(`/aireport?id=${encodeURIComponent(cve)}&force=true`, '_blank');
            };
        }

        if (cancelBtn) cancelBtn.onclick = closeModal;
        if (closeBtn) closeBtn.onclick = closeModal;

        modal.querySelectorAll('.delete, .modal-background, .modal-close-dot, .modal-close-btn, #feedAiReportCancelBtn').forEach(el => {
            el.onclick = closeModal;
        });

        const onEsc = (e) => {
            if (e.key === 'Escape' && modal.classList.contains('is-active')) {
                closeModal();
                document.removeEventListener('keydown', onEsc);
            }
        };
        document.addEventListener('keydown', onEsc);

        modal.classList.add('is-active');
    }

    async openCaseModal(item) {
        const modal = document.getElementById('feedCaseModal');
        if (!modal) return;

        const cveMatch = item.title ? item.title.match(/CVE-\d{4}-\d+/i) : null;
        const primaryCve = cveMatch ? cveMatch[0].toUpperCase() : (item.title ? item.title.split(':')[0].trim() : 'CVE');
        const defaultName = `Case: ${primaryCve}`;
        const defaultDesc = `${item.description || 'No description provided.'}\n\nSource: ${item.source || 'Intel Feed'}\nReference: ${item.url || 'N/A'}`;

        const iocSet = new Set();
        if (primaryCve) iocSet.add(primaryCve);
        if (item.iocs && Array.isArray(item.iocs)) {
            item.iocs.forEach(raw => {
                if (!raw || raw.startsWith('Event ID:')) return;
                // Parse through contextualizer if available
                if (this.contextualizer) {
                    const parsed = this.contextualizer.extractAll(raw);
                    let foundAny = false;
                    for (const [kind, matches] of Object.entries(parsed)) {
                        if (kind === 'base_domain') continue;
                        for (const m of matches) {
                            if (m.value) {
                                iocSet.add(m.value.trim());
                                foundAny = true;
                            }
                        }
                    }
                    if (!foundAny && raw.trim()) iocSet.add(raw.trim());
                } else if (raw.trim()) {
                    iocSet.add(raw.trim());
                }
            });
        }
        const iocList = Array.from(iocSet);

        // Fetch user cases to populate select options
        let userCases = [];
        try {
            const res = await this.app._fetch('/cases/list?limit=100&type=user');
            if (res.ok) {
                userCases = await res.json() || [];
            }
        } catch (e) {
            console.error("Failed to fetch cases for modal:", e);
        }

        const select = document.getElementById('feedTargetCaseId');
        const newFields = document.getElementById('feedNewCaseFields');
        const caseNameInput = document.getElementById('feedCaseName');
        const caseDescText = document.getElementById('feedCaseDesc');
        const caseIocsInput = document.getElementById('feedCaseIocs');
        const resultBox = document.getElementById('feedCaseResult');

        if (select) {
            select.innerHTML = `
                <option value="">-- Create New Case --</option>
                ${userCases.filter(c => c.status === 'Open').map(c => `
                    <option value="${c.id}">${escapeHtml(c.name)}</option>
                `).join('')}
            `;
            select.value = '';
        }

        if (newFields) newFields.style.display = 'block';
        if (caseNameInput) caseNameInput.value = defaultName;
        if (caseDescText) caseDescText.value = defaultDesc;
        if (caseIocsInput) caseIocsInput.value = iocList.join('\n');
        if (resultBox) resultBox.innerHTML = '';

        const closeModal = () => {
            modal.classList.remove('is-active');
        };

        modal.querySelectorAll('.delete, .modal-background, #feedCaseCancelBtn, .modal-close-dot, .modal-close-btn').forEach(el => {
            el.onclick = closeModal;
        });

        const onEsc = (e) => {
            if (e.key === 'Escape' && modal.classList.contains('is-active')) {
                closeModal();
                document.removeEventListener('keydown', onEsc);
            }
        };
        document.addEventListener('keydown', onEsc);

        if (select) {
            select.onchange = () => {
                newFields.style.display = select.value ? 'none' : 'block';
            };
        }

        const form = document.getElementById('feedCaseForm');
        if (form) {
            form.onsubmit = async (e) => {
                e.preventDefault();
                const submitBtn = document.getElementById('feedCaseSubmitBtn');
                submitBtn.classList.add('is-loading');

                const targetId = select ? select.value : '';

                // Parse IOCs from textarea (newlines, commas, semicolons)
                const rawText = caseIocsInput ? caseIocsInput.value : '';
                const parsedIocs = rawText
                    .split(/[\r\n,;]+/)
                    .map(s => s.trim())
                    .filter(s => s.length > 0);
                const finalIocs = Array.from(new Set(parsedIocs.length > 0 ? parsedIocs : iocList));

                try {
                    let cachedAiReport = null;
                    if (primaryCve) {
                        try {
                            const checkRes = await this.app._fetch(`/aireport/check?id=${encodeURIComponent(primaryCve)}`);
                            if (checkRes.ok) {
                                const checkData = await checkRes.json();
                                if (checkData.exists) {
                                    const repRes = await fetch(`/aireport?id=${encodeURIComponent(primaryCve)}`);
                                    if (repRes.ok) {
                                        cachedAiReport = await repRes.text();
                                    }
                                }
                            }
                        } catch (e) {
                            console.warn("Could not check/fetch cached AI report for case creation:", e);
                        }
                    }

                    if (targetId) {
                        // Append IOCs to existing case
                        const getRes = await this.app._fetch(`/cases/get?id=${targetId}`);
                        if (!getRes.ok) throw new Error("Could not retrieve target case.");
                        const caseData = await getRes.json();

                        if (!caseData.iocs) caseData.iocs = [];
                        finalIocs.forEach(ioc => {
                            if (!caseData.iocs.includes(ioc)) {
                                caseData.iocs.push(ioc);
                            }
                        });

                        if (cachedAiReport && !caseData.ai_report) {
                            caseData.ai_report = cachedAiReport;
                        }

                        const updateRes = await this.app._fetch('/cases/update', {
                            method: 'POST',
                            body: JSON.stringify(caseData)
                        });
                        if (!updateRes.ok) throw new Error(await updateRes.text());
                    } else {
                        // Create new case
                        const name = caseNameInput ? caseNameInput.value.trim() : '';
                        const desc = caseDescText ? caseDescText.value.trim() : '';
                        if (!name) throw new Error("Case Name is required.");

                        const createRes = await this.app._fetch('/cases/create', {
                            method: 'POST',
                            body: JSON.stringify({
                                name: name,
                                description: desc,
                                is_auto: false,
                                iocs: finalIocs,
                                ai_report: cachedAiReport || ''
                            })
                        });
                        if (!createRes.ok) throw new Error(await createRes.text());
                    }

                    resultBox.innerHTML = `<div class="notification terminal-form-notification is-success">Successfully saved to case!</div>`;
                    setTimeout(() => {
                        submitBtn.classList.remove('is-loading');
                        closeModal();
                    }, 1200);

                } catch (err) {
                    submitBtn.classList.remove('is-loading');
                    resultBox.innerHTML = `<div class="notification terminal-form-notification is-danger">${escapeHtml(err.message)}</div>`;
                }
            };
        }

        modal.classList.add('is-active');
    }
}