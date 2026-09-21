/**
 * webapp/ui/feed.js
 * Controller handling rendering and UI logic for the CISA/NIST vulnerability feed.
 * Updates the layout to sit the colored CWE indicator tiles directly next to the source tags.
 */
import { escapeHtml } from './utils.js';

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

            <div class="modal" id="feedCaseModal">
                <div class="modal-background"></div>
                <div class="modal-card">
                    <header class="modal-card-head">
                        <p class="modal-card-title">Open Case for Vulnerability</p>
                        <button class="delete" aria-label="close"></button>
                    </header>
                    <section class="modal-card-body">
                        <form id="feedCaseForm">
                            <div class="field">
                                <label class="label">Target Case</label>
                                <div class="control">
                                    <div class="select is-fullwidth">
                                        <select id="feedTargetCaseId">
                                            <option value="">-- Create New Case --</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <div id="feedNewCaseFields">
                                <div class="field">
                                    <label class="label">Case Name</label>
                                    <div class="control">
                                        <input class="input" type="text" id="feedCaseName" placeholder="e.g. Investigation: CVE-2024-XXXX">
                                    </div>
                                </div>
                                <div class="field">
                                    <label class="label">Description</label>
                                    <div class="control">
                                        <textarea class="textarea" id="feedCaseDesc" rows="3" placeholder="Case details..."></textarea>
                                    </div>
                                </div>
                            </div>
                            <div class="field">
                                <label class="label">Associated IOCs / CVE</label>
                                <div class="control">
                                    <input class="input" type="text" id="feedCaseIocs" readonly style="background-color: #111927; color: #38bdf8; border: 1px solid #1e293b;">
                                </div>
                            </div>
                            <div id="feedCaseResult" class="mt-3"></div>
                            <div class="buttons is-right mt-4">
                                <button type="button" class="button" id="feedCaseCancelBtn">Cancel</button>
                                <button type="submit" class="button is-success" id="feedCaseSubmitBtn">
                                    <span class="icon"><i class="material-icons">work</i></span>
                                    <span>Create / Update Case</span>
                                </button>
                            </div>
                        </form>
                    </section>
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

        // Initially render the items list
        this.updateList();
    }


    updateList() {
        const listContainer = document.getElementById(this.containerId ? 'feedListItems' : 'feedListItems');
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
        listContainer.innerHTML = filteredItems.map((item, index) => {
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
                        cweColorStyle = 'background-color: #ff3860; color: #fff;'; 
                    } else if (['CWE-20', 'CWE-22', 'CWE-287', 'CWE-416'].includes(cwe)) {
                        cweColorStyle = 'background-color: #ffdd57; color: #4a4a4a;'; 
                    }

                    return `
                        <a href="${externalUrl}" 
                           target="_blank" 
                           rel="noopener noreferrer" 
                           class="tag font-weight-bold is-family-code ml-1 mb-1" 
                           style="${cweColorStyle} font-size: 0.7rem; border-radius: 3px; display: inline-block; cursor: pointer;"
                           title="${cwe}: ${description} (Click to view official MITRE details)">
                            ${cwe}
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
                            <strong class="is-size-7 has-text-danger uppercase mr-2" style="letter-spacing: 0.5px;">
                                Campaigns / Actors:
                            </strong>
                        </span>
                        <div class="tags mb-0">
                            ${item.campaigns.map(camp => `
                                <span class="tag is-danger is-light is-family-code is-small mb-1" style="border: 1px solid rgba(255, 56, 96, 0.3); height: 1.6em;">
                                    ${camp}
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
                            <strong class="is-size-7 has-text-info uppercase mr-2" style="letter-spacing: 0.5px;">
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
                                       style="border: 1px solid rgba(50, 115, 220, 0.3); height: 1.6em; text-decoration: none;">
                                        ${capecId}${capecName}
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
                const eventIdEntry = item.iocs.find(ioc => ioc.startsWith('Event ID:'));
                const eventId = eventIdEntry ? eventIdEntry.replace('Event ID:', '').trim() : null;

                // Filter out the Event ID and redundant CVE strings
                const indicators = item.iocs.filter(ioc => 
                    !ioc.startsWith('Event ID:') && 
                    ioc !== item.title && 
                    !ioc.startsWith('CVE-')
                );

                iocHtml = `
                    <div class="is-flex is-align-items-center is-flex-wrap-wrap mt-2">
                        <span class="is-flex is-align-items-center mr-2 mb-1">
                            <span class="icon is-small has-text-warning mr-1">
                                <i class="material-icons" style="font-size: 14px;">hub</i>
                            </span>
                            <strong class="is-size-7 has-text-warning uppercase mr-2" style="letter-spacing: 0.5px;">
                                Indicators / IOCs:
                            </strong>
                            ${eventId ? `
                                <span class="tag is-dark is-small is-family-code" style="border: 1px solid rgba(255, 221, 87, 0.35); color: #ffdd57; height: 1.6em; padding: 0 6px;">
                                    Misp Event #${eventId}
                                </span>
                            ` : ''}
                        </span>

                        <div class="tags mb-0">
                            ${indicators.length > 0 ? indicators.map(ioc => `
                                <span class="tag is-dark is-family-code is-small mb-1" style="background-color: #111927; border: 1px solid #1e293b; color: #38bdf8; height: 1.6em;">
                                    <span class="icon is-small mr-1" style="opacity: 0.6;"><i class="material-icons" style="font-size: 11px;">crisis_alert</i></span>
                                    ${ioc}
                                </span>
                            `).join('') : '<span class="is-size-7 has-text-grey-light is-italic">No additional IOCs</span>'}
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
                            <div class="is-flex is-align-items-center is-flex-wrap-wrap mb-2">
                                <span class="tag ${tagColor} is-light mb-1">${item.source}</span>
                                ${cweHtml}
                            </div>

                            <h4 class="title is-size-5 mb-1">
                                <a href="${item.url}" target="_blank" rel="noopener noreferrer" class="has-text-info">
                                    ${item.title || 'Unknown Identifier'}
                                </a>
                            </h4>
                            
                            <p class="has-text-white-ter is-size-6 mt-1">${item.description || 'No description provided.'}</p>
                            
                            ${campaignHtml}
                            ${capecHtml}
                            ${iocHtml}
                            
                            ${item.published ? `<p class="is-size-7 has-text-grey-light mt-2">Cached/Published: ${new Date(item.published).toLocaleString()}</p>` : ''}
                        </div>
                        <div class="column is-narrow">
                            <div class="buttons">
                                ${item.case_id ? `
                                    <button class="button is-small is-warning is-outlined btn-feed-view-case mr-1 mb-0" data-case-id="${item.case_id}" title="View existing associated case">
                                        <span class="icon"><i class="material-icons">visibility</i></span>
                                    </button>
                                ` : ''}
                                <a href="/aireport?id=${encodeURIComponent(cveIdentifier)}" target="_blank" class="button is-small is-primary is-light mr-1 mb-0" title="Generate AI Report">
                                    <span class="icon"><i class="material-icons">auto_awesome</i></span>
                                </a>
                                <button class="button is-small is-success is-outlined btn-feed-open-case mr-1 mb-0" data-index="${index}" title="Open or update case for this CVE">
                                    <span class="icon"><i class="material-icons">work_outline</i></span>

                                </button>
                                <a href="${item.url}" target="_blank" rel="noopener noreferrer" class="button is-small is-info is-outlined mb-0" title="Open reference link">
                                    <span class="icon"><i class="material-icons">open_in_new</i></span>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        listContainer.querySelectorAll('.btn-feed-view-case').forEach(btn => {
            btn.onclick = (e) => {
                const caseId = e.currentTarget.dataset.caseId;
                if (caseId) {
                    document.dispatchEvent(new CustomEvent('req-open-case', { detail: caseId }));
                }
            };
        });

        listContainer.querySelectorAll('.btn-feed-open-case').forEach(btn => {
            btn.onclick = (e) => {
                const idx = parseInt(e.currentTarget.dataset.index);
                const item = filteredItems[idx];
                if (item) {
                    this.openCaseModal(item);
                }
            };
        });
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
        if (item.title && item.title !== primaryCve) iocSet.add(item.title);
        if (item.iocs && Array.isArray(item.iocs)) {
            item.iocs.forEach(ioc => {
                if (ioc && !ioc.startsWith('Event ID:')) iocSet.add(ioc);
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
        if (caseIocsInput) caseIocsInput.value = iocList.join(', ');
        if (resultBox) resultBox.innerHTML = '';

        const closeModal = () => {
            modal.classList.remove('is-active');
        };

        modal.querySelectorAll('.delete, .modal-background, #feedCaseCancelBtn').forEach(el => {
            el.onclick = closeModal;
        });

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
                try {
                    if (targetId) {
                        // Append IOCs to existing case
                        const getRes = await this.app._fetch(`/cases/get?id=${targetId}`);
                        if (!getRes.ok) throw new Error("Could not retrieve target case.");
                        const caseData = await getRes.json();

                        if (!caseData.iocs) caseData.iocs = [];
                        iocList.forEach(ioc => {
                            if (!caseData.iocs.includes(ioc)) {
                                caseData.iocs.push(ioc);
                            }
                        });

                        const updateRes = await this.app._fetch('/cases/update', {
                            method: 'POST',
                            body: JSON.stringify(caseData)
                        });
                        if (!updateRes.ok) throw new Error(await updateRes.text());
                    } else {
                        // Create new case
                        const name = caseNameInput.value.trim();
                        const desc = caseDescText.value.trim();
                        if (!name) throw new Error("Case Name is required.");

                        const createRes = await this.app._fetch('/cases/create', {
                            method: 'POST',
                            body: JSON.stringify({
                                name: name,
                                description: desc,
                                is_auto: false,
                                iocs: iocList
                            })
                        });
                        if (!createRes.ok) throw new Error(await createRes.text());
                    }

                    resultBox.innerHTML = `<div class="notification is-success is-light">Successfully saved to case!</div>`;
                    setTimeout(() => {
                        submitBtn.classList.remove('is-loading');
                        closeModal();
                    }, 1200);

                } catch (err) {
                    submitBtn.classList.remove('is-loading');
                    resultBox.innerHTML = `<div class="notification is-danger is-dark">${escapeHtml(err.message)}</div>`;
                }
            };
        }

        modal.classList.add('is-active');
    }
}