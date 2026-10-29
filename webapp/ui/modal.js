import { escapeHtml } from './utils.js';
import { Contextualizer } from '../parser.js';

export class ModalManager {
    constructor(modalId, app) {
        this.modal = document.getElementById(modalId);
        this.app = app;
        this.contextualizer = new Contextualizer();
        
        // Cache elements
        this.title = document.getElementById('detailsModalTitle');
        this.modalBody = document.getElementById('detailsModalBody');
        this.rawContent = document.getElementById('detailsModalContent');
        this.content = this.rawContent; // Backward compatibility alias
        this.formContainer = document.getElementById('detailsModalForm');
        this.footer = document.getElementById('detailsModalFoot');
        this.archiveButton = document.getElementById('archiveButton');
        this.copyButton = document.getElementById('copyButton');
        this.mispButton = document.getElementById('mispButton');
        this.addToCaseButton = document.getElementById('addToCaseButton');
        
        this.attachListeners();
    }

    showRawView() {
        if (this.rawContent) this.rawContent.classList.remove('is-hidden');
        if (this.formContainer) {
            this.formContainer.classList.add('is-hidden');
            this.formContainer.innerHTML = '';
        }
        if (this.footer) {
            this.footer.classList.remove('is-hidden');
            this.footer.style.setProperty('display', 'flex', 'important');
        }
        if (this.modalBody) this.modalBody.scrollTop = 0;
    }

    showFormView(html) {
        if (this.rawContent) this.rawContent.classList.add('is-hidden');
        if (this.formContainer) {
            this.formContainer.classList.remove('is-hidden');
            this.formContainer.innerHTML = html;
        }
        if (this.footer) {
            this.footer.classList.add('is-hidden');
            this.footer.style.setProperty('display', 'none', 'important');
        }
        if (this.modalBody) this.modalBody.scrollTop = 0;
    }

    attachListeners() {
        // Close actions (traffic light dot, modal close button, bulma delete, and backdrop)
        this.modal.querySelectorAll('.delete, .modal-background, .modal-close-dot, .modal-close-btn').forEach(el => {
            el.addEventListener('click', () => this.close());
        });

        // Close on Escape key press
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.modal && this.modal.classList.contains('is-active')) {
                this.close();
            }
        });

        // Archive
        if (this.archiveButton) {
            this.archiveButton.addEventListener('click', async (e) => {
                const id = e.currentTarget.dataset.id;
                if (id) {
                    await this.app.archiveResult(id);
                    this.close();
                }
            });
        }

        // Copy raw JSON
        if (this.copyButton) {
            this.copyButton.addEventListener('click', () => {
                const textToCopy = this.rawContent ? this.rawContent.textContent : (this.content ? this.content.textContent : '');
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalHTML = this.copyButton.innerHTML;
                    this.copyButton.innerHTML = `<span class="icon is-small"><i class="material-icons">check</i></span><span>Copied!</span>`;
                    this.copyButton.classList.add('is-copied');
                    setTimeout(() => {
                        this.copyButton.innerHTML = originalHTML;
                        this.copyButton.classList.remove('is-copied');
                    }, 2000);
                }).catch(err => console.error('Failed to copy text: ', err));
            });
        }

        // MISP Button triggers the form render
        if (this.mispButton) {
            this.mispButton.addEventListener('click', () => this.renderMispForm());
        }

        // Add to Case Button listener
        if (this.addToCaseButton) {
            this.addToCaseButton.addEventListener('click', () => this.renderCaseForm());
        }
    }

    show(result, details) {
        let displayId = result.id || result;
        if (typeof displayId === 'string' && displayId.length > 24) {
            displayId = `${displayId.substring(0, 10)}...${displayId.substring(displayId.length - 10)}`;
        }
        
        this.title.textContent = `Details for ${displayId}`;
        this.title.title = `Full ID: ${result.id || result}`;
        if (this.archiveButton) this.archiveButton.dataset.id = result.id || result;

        this.showRawView();

        try {
            if (this.rawContent) {
                this.rawContent.textContent = JSON.stringify(details, null, 2);
            }
        } catch (e) {
            if (this.rawContent) {
                this.rawContent.textContent = "Error: Could not display details.";
            }
        }
        if (this.modalBody) this.modalBody.scrollTop = 0;
        this.modal.classList.add('is-active');
    }

    close() {
        this.modal.classList.remove('is-active');
        if (this.rawContent) this.rawContent.textContent = '';
        if (this.formContainer) {
            this.formContainer.innerHTML = '';
            this.formContainer.classList.add('is-hidden');
        }
        this.showRawView();
    }

    /**
     * Extracts and validates IOCs from event focus data using webapp/parser.js Contextualizer.
     * Prevents deep-scanning into raw vendor enrichment trees (e.g., hundreds of MISP attributes).
     */
    extractEventContext(currentData) {
        let eventSource = null;
        const candidateStrings = [];
        const seenStrings = new Set();

        const addCandidate = (val) => {
            if (!val || typeof val !== 'string') return;
            const cleaned = val.trim();
            if (cleaned && cleaned !== 'N/A' && !seenStrings.has(cleaned)) {
                seenStrings.add(cleaned);
                candidateStrings.push(cleaned);
            }
        };

        // Unpack top-level array wrappers without traversing deep vendor trees
        const topLevelItems = [];
        const unwrap = (data) => {
            if (!data) return;
            if (Array.isArray(data)) {
                for (const item of data) {
                    if (Array.isArray(item)) unwrap(item);
                    else if (item && typeof item === 'object') topLevelItems.push(item);
                }
            } else if (typeof data === 'object') {
                topLevelItems.push(data);
            }
        };
        unwrap(currentData);

        for (const item of topLevelItems) {
            // Find the primary event descriptor (ProxyRequest, SummarizedEvent, or Case)
            if (!eventSource && (item.value || item.info || item.from)) {
                eventSource = item;
            }

            // Extract the searched/matched indicator at top-level
            if (item.value && typeof item.value === 'string') {
                addCandidate(item.value);
            }

            // Extract explicit top-level IOC list if present on the event
            if (Array.isArray(item.iocs)) {
                for (const i of item.iocs) addCandidate(i);
            }
        }

        // Validate and classify indicators using parser.js Contextualizer
        const validatedIocs = [];
        const seenValidated = new Set();
        let detectedType = '';

        for (const raw of candidateStrings) {
            const parsed = this.contextualizer.extractAll(raw);
            let hasMatch = false;

            for (const [kind, matches] of Object.entries(parsed)) {
                if (kind === 'base_domain') continue; // Avoid redundant second-level domains
                for (const m of matches) {
                    const cleanVal = (m.value || '').trim();
                    if (cleanVal && !seenValidated.has(cleanVal)) {
                        seenValidated.add(cleanVal);
                        validatedIocs.push(cleanVal);
                        if (!detectedType) detectedType = m.type || kind;
                        hasMatch = true;
                    }
                }
            }

            // Fallback for custom values where the parser regex didn't explicitly capture it
            if (!hasMatch && !seenValidated.has(raw)) {
                seenValidated.add(raw);
                validatedIocs.push(raw);
            }
        }

        // Fallback: If no top-level indicator was found, scan event description/info text
        if (validatedIocs.length === 0 && eventSource) {
            const textToScan = [eventSource.info, eventSource.description].filter(Boolean).join(' ');
            if (textToScan) {
                const parsed = this.contextualizer.extractAll(textToScan);
                for (const [kind, matches] of Object.entries(parsed)) {
                    if (kind === 'base_domain') continue;
                    for (const m of matches) {
                        const cleanVal = (m.value || '').trim();
                        if (cleanVal && !seenValidated.has(cleanVal)) {
                            seenValidated.add(cleanVal);
                            validatedIocs.push(cleanVal);
                            if (!detectedType) detectedType = m.type || kind;
                        }
                    }
                }
            }
        }

        return {
            eventSource,
            iocs: validatedIocs,
            primaryIoc: validatedIocs.length > 0 ? validatedIocs[0] : (eventSource?.value || ''),
            type: detectedType || eventSource?.type || ''
        };
    }

    async renderCaseForm() {
        const currentData = this.app.focus;
        const currentResponseId = this.archiveButton?.dataset?.id || '';

        // Extract and validate indicators using parser.js Contextualizer
        const { eventSource, iocs: detectedIocs, primaryIoc } = this.extractEventContext(currentData);

        // Fetch existing open cases to populate dropdown
        let cases = [];
        try {
            const res = await this.app._fetch('/cases/list?limit=100&type=user');
            if (res.ok) {
                cases = await res.json() || [];
            }
        } catch (e) {
            console.error("Failed to load cases", e);
        }

        // Fetch system users to populate assignee dropdown
        let users = [];
        try {
            const res = await this.app._fetch('/getusers');
            if (res.ok) {
                users = await res.json() || [];
            }
        } catch (e) {
            console.error("Failed to load users", e);
        }

        let defaultName = primaryIoc ? `Investigation: ${primaryIoc}` : (currentResponseId ? `Investigation: ${currentResponseId.substring(0, 8)}` : '');
        let defaultDesc = '';
        if (eventSource?.info) {
            defaultDesc = `Telemetry Source: ${eventSource.from || 'Investigation'}\nEvent Info: ${eventSource.info}`;
        } else if (currentResponseId) {
            defaultDesc = `Investigation created from event response ${currentResponseId}.`;
        }

        // Render Comprehensive Case Form
        this.showFormView(`
            <div class="modal-subform-container">
                <div class="modal-subform-header">
                    <div class="modal-subform-title">
                        <span class="icon"><i class="material-icons">work_outline</i></span>
                        <span>Case Management</span>
                    </div>
                    <div class="modal-ioc-tag">
                        ${detectedIocs.length > 0 ? `
                            <span class="modal-ioc-label">DETECTED IOCS (${detectedIocs.length}):</span>
                            <code class="modal-ioc-val">${escapeHtml(detectedIocs.slice(0, 3).join(', '))}${detectedIocs.length > 3 ? '...' : ''}</code>
                        ` : `
                            <span class="modal-ioc-label">EVENT ID:</span>
                            <code class="modal-ioc-val">${escapeHtml(currentResponseId || 'N/A')}</code>
                        `}
                    </div>
                </div>
                
                <form id="addToCaseForm" novalidate>
                    <!-- Destination Case Selector -->
                    <div class="field mb-3">
                        <label class="label terminal-form-label">Destination Case</label>
                        <div class="control">
                            <div class="select is-fullwidth terminal-select">
                                <select id="targetCaseId">
                                    <option value="">-- Create New Case --</option>
                                    ${cases.filter(c => c.status === 'Open').map(c => `
                                        <option value="${escapeHtml(c.id)}" data-priority="${escapeHtml(c.priority || 'Medium')}" data-assignee="${escapeHtml(c.assigned_to || '')}">
                                            ${escapeHtml(c.name)} [${escapeHtml(c.priority || 'Medium')}]
                                        </option>
                                    `).join('')}
                                </select>
                            </div>
                        </div>
                    </div>

                    <!-- NEW CASE SPECIFIC FIELDS -->
                    <div id="newCaseFields">
                        <div class="field mb-3">
                            <label class="label terminal-form-label">Case Name *</label>
                            <div class="control">
                                <input class="input terminal-input" type="text" id="modalCaseName" value="${escapeHtml(defaultName)}" placeholder="e.g., APT29 C2 Infrastructure">
                            </div>
                        </div>

                        <div class="columns is-variable is-2 mb-2">
                            <div class="column is-6">
                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Priority</label>
                                    <div class="control">
                                        <div class="select is-fullwidth terminal-select">
                                            <select id="modalCasePriority">
                                                <option value="Low">Low</option>
                                                <option value="Medium" selected>Medium</option>
                                                <option value="High">High</option>
                                                <option value="Critical">Critical</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="column is-6">
                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Assign To</label>
                                    <div class="control">
                                        <div class="select is-fullwidth terminal-select">
                                            <select id="modalCaseAssignee">
                                                <option value="">-- Unassigned --</option>
                                                ${users.map(u => `
                                                    <option value="${escapeHtml(u)}" ${u === this.app.user?.email ? 'selected' : ''}>
                                                        ${escapeHtml(u)}
                                                    </option>
                                                `).join('')}
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="field mb-3">
                            <label class="label terminal-form-label">Description</label>
                            <div class="control">
                                <textarea class="textarea terminal-textarea" id="modalCaseDesc" rows="2" placeholder="Case summary, scope, or initial observations...">${escapeHtml(defaultDesc)}</textarea>
                            </div>
                        </div>
                    </div>

                    <!-- EXISTING CASE UPDATE FIELDS -->
                    <div id="existingCaseFields" style="display: none;">
                        <div class="columns is-variable is-2 mb-2">
                            <div class="column is-6">
                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Update Priority (Optional)</label>
                                    <div class="control">
                                        <div class="select is-fullwidth terminal-select">
                                            <select id="modalExistingPriority">
                                                <option value="">-- Keep Current Priority --</option>
                                                <option value="Low">Low</option>
                                                <option value="Medium">Medium</option>
                                                <option value="High">High</option>
                                                <option value="Critical">Critical</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="column is-6">
                                <div class="field mb-3">
                                    <label class="label terminal-form-label">Reassign To (Optional)</label>
                                    <div class="control">
                                        <div class="select is-fullwidth terminal-select">
                                            <select id="modalExistingAssignee">
                                                <option value="">-- Keep Current Assignee --</option>
                                                ${users.map(u => `
                                                    <option value="${escapeHtml(u)}">${escapeHtml(u)}</option>
                                                `).join('')}
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- IOCs / Indicators (editable for both new and existing cases) -->
                    <div class="field mb-3">
                        <div class="is-flex is-justify-content-space-between is-align-items-center mb-1">
                            <label class="label terminal-form-label mb-0" id="modalIocLabel">Indicators of Compromise (IOCs)</label>
                            <span class="terminal-form-help">Line breaks or commas separated</span>
                        </div>
                        <div class="control">
                            <textarea class="textarea terminal-textarea font-mono" id="modalCaseIOCs" rows="2" placeholder="e.g. 192.168.1.1&#10;malicious-domain.com">${escapeHtml(detectedIocs.join('\n'))}</textarea>
                        </div>
                    </div>

                    <!-- Investigation Comment / Timeline Note -->
                    <div class="field mb-3">
                        <label class="label terminal-form-label">Investigation Note / Comment (Optional)</label>
                        <div class="control">
                            <input class="input terminal-input" type="text" id="modalCaseComment" placeholder="Add an investigation note to the case history...">
                        </div>
                    </div>

                    <div id="caseFormResult" class="mt-2"></div>

                    <div class="buttons is-right mt-3">
                        <button type="button" class="button terminal-action-btn" id="caseCancelBtn">Cancel</button>
                        <button type="submit" class="button terminal-action-btn modal-btn-case" id="caseSubmitBtn">
                            <span id="caseSubmitText">Create Case</span>
                            <span class="icon is-small"><i class="material-icons" id="caseSubmitIcon">add</i></span>
                        </button>
                    </div>
                </form>
            </div>
        `);

        // Toggle form mode based on case selection
        const select = document.getElementById('targetCaseId');
        const newFields = document.getElementById('newCaseFields');
        const existingFields = document.getElementById('existingCaseFields');
        const submitText = document.getElementById('caseSubmitText');
        const submitIcon = document.getElementById('caseSubmitIcon');
        const iocLabel = document.getElementById('modalIocLabel');

        select?.addEventListener('change', () => {
            const isExisting = Boolean(select.value);
            if (newFields) newFields.style.display = isExisting ? 'none' : 'block';
            if (existingFields) existingFields.style.display = isExisting ? 'block' : 'none';
            if (submitText) {
                submitText.textContent = isExisting ? 'Add to Case' : 'Create Case';
            }
            if (submitIcon) {
                submitIcon.textContent = isExisting ? 'save' : 'add';
            }
            if (iocLabel) {
                iocLabel.textContent = isExisting ? 'Indicators to Append (IOCs)' : 'Indicators of Compromise (IOCs)';
            }
        });

        document.getElementById('caseCancelBtn')?.addEventListener('click', () => this.resetStylesAndShowDetails());

        const handleCaseSubmit = async (e) => {
            if (e) {
                e.preventDefault();
                e.stopPropagation();
            }

            const submitBtn = document.getElementById('caseSubmitBtn');
            const resultBox = document.getElementById('caseFormResult');
            if (resultBox) resultBox.innerHTML = '';

            const selectedCaseId = select ? select.value : '';

            // Parse IOCs from textarea (newline, comma, semicolon separated)
            const rawIocs = document.getElementById('modalCaseIOCs')?.value || '';
            const parsedIocs = rawIocs
                .split(/[\r\n,;]+/)
                .map(s => s.trim())
                .filter(s => s.length > 0);
            const uniqueIocs = Array.from(new Set(parsedIocs));

            // Extract optional comment
            const noteText = document.getElementById('modalCaseComment')?.value?.trim() || '';
            const currentUser = this.app.user?.email || 'analyst';

            if (!selectedCaseId) {
                // New Case mode: validate required case name
                const name = document.getElementById('modalCaseName')?.value?.trim();
                if (!name) {
                    if (resultBox) {
                        resultBox.innerHTML = `<div class="notification terminal-form-notification is-danger">Case Name is required.</div>`;
                    }
                    document.getElementById('modalCaseName')?.focus();
                    return;
                }
            }

            if (submitBtn) {
                submitBtn.classList.add('is-loading');
                submitBtn.disabled = true;
            }

            try {
                if (selectedCaseId) {
                    // Update existing case
                    const caseRes = await this.app._fetch(`/cases/get?id=${encodeURIComponent(selectedCaseId)}`);
                    if (!caseRes.ok) {
                        throw new Error(`Failed to fetch case: ${await caseRes.text()}`);
                    }
                    const caseData = await caseRes.json();
                    
                    if (!caseData.iocs) caseData.iocs = [];
                    let addedCount = 0;
                    for (const ioc of uniqueIocs) {
                        if (!caseData.iocs.includes(ioc)) {
                            caseData.iocs.push(ioc);
                            addedCount++;
                        }
                    }

                    // Optional priority update
                    const newPriority = document.getElementById('modalExistingPriority')?.value;
                    if (newPriority) {
                        caseData.priority = newPriority;
                    }

                    // Optional assignee update
                    const newAssignee = document.getElementById('modalExistingAssignee')?.value;
                    if (newAssignee) {
                        caseData.assigned_to = newAssignee;
                    }

                    // Optional comment append
                    if (noteText) {
                        if (!caseData.comments) caseData.comments = [];
                        caseData.comments.push({
                            user: currentUser,
                            text: noteText,
                            created_at: new Date().toISOString()
                        });
                    }

                    const updateRes = await this.app._fetch('/cases/update', {
                        method: 'POST',
                        body: JSON.stringify(caseData)
                    });
                    if (!updateRes.ok) {
                        throw new Error(await updateRes.text() || "Failed to update case");
                    }

                    if (resultBox) {
                        resultBox.innerHTML = `<div class="notification terminal-form-notification is-success">Successfully updated case with ${addedCount} new indicator(s)!</div>`;
                    }
                } else {
                    // Create new case
                    const name = document.getElementById('modalCaseName')?.value?.trim();
                    const priority = document.getElementById('modalCasePriority')?.value || 'Medium';
                    const assignedTo = document.getElementById('modalCaseAssignee')?.value || '';
                    const description = document.getElementById('modalCaseDesc')?.value?.trim() || '';

                    const comments = [];
                    if (noteText) {
                        comments.push({
                            user: currentUser,
                            text: noteText,
                            created_at: new Date().toISOString()
                        });
                    }

                    const newCasePayload = {
                        name: name,
                        description: description,
                        priority: priority,
                        assigned_to: assignedTo,
                        iocs: uniqueIocs,
                        comments: comments,
                        response_id: currentResponseId,
                        is_auto: false
                    };

                    const createRes = await this.app._fetch('/cases/create', {
                        method: 'POST',
                        body: JSON.stringify(newCasePayload)
                    });
                    if (!createRes.ok) {
                        throw new Error(await createRes.text() || "Failed to create case");
                    }

                    if (resultBox) {
                        resultBox.innerHTML = `<div class="notification terminal-form-notification is-success">Successfully created case with ${uniqueIocs.length} indicator(s)!</div>`;
                    }
                }

                setTimeout(() => {
                    this.resetStylesAndShowDetails();
                    this.close();
                }, 1500);
            } catch (err) {
                console.error("Case form submission error:", err);
                if (resultBox) {
                    resultBox.innerHTML = `<div class="notification terminal-form-notification is-danger">${escapeHtml(err.message)}</div>`;
                }
                if (submitBtn) {
                    submitBtn.classList.remove('is-loading');
                    submitBtn.disabled = false;
                }
            }
        };

        const formEl = document.getElementById('addToCaseForm');
        formEl?.addEventListener('submit', handleCaseSubmit);
        document.getElementById('caseSubmitBtn')?.addEventListener('click', (e) => {
            e.preventDefault();
            handleCaseSubmit(e);
        });
    }

    renderMispForm() {
        const currentData = this.app.focus;
        const { eventSource, primaryIoc, type: detectedType } = this.extractEventContext(currentData);

        // Extract Data
        let initialValue = primaryIoc || eventSource?.value || "";
        let initialType = detectedType || eventSource?.type || "";
        
        // Mapping
        if (initialType === 'ip' || initialType === 'ipv4' || initialType === 'ipv6') initialType = 'ip-src';
        else if (initialType === 'email') initialType = 'email-src';
        else if (initialType === 'cve') initialType = 'vulnerability';
        
        let initialInfo = initialValue ? `Investigation of ${initialValue}` : 'ThreatCo Security Investigation';
        if (eventSource?.info) {
            initialInfo = `ThreatCo: ${eventSource.info.substring(0, 150)}${eventSource.info.length > 150 ? '...' : ''}`;
        }

        // Render MISP Form via dedicated form container
        this.showFormView(`
            <div class="modal-subform-container">
                <div class="modal-subform-header">
                    <div class="modal-subform-title">
                        <span class="icon"><i class="material-icons">bug_report</i></span>
                        <span>Create MISP Event</span>
                    </div>
                    <div class="modal-ioc-tag">
                        <span class="modal-ioc-label">TARGET IOC:</span>
                        <code class="modal-ioc-val">${escapeHtml(initialValue || 'Manual Entry')}</code>
                    </div>
                </div>
                
                <form id="mispForm" novalidate>
                    <div class="field mb-3">
                        <label class="label terminal-form-label">Event Description *</label>
                        <div class="control">
                            <input class="input terminal-input" type="text" id="mispEventInfo" value="${escapeHtml(initialInfo)}">
                        </div>
                    </div>

                    <div class="columns is-variable is-2 mb-2">
                        <div class="column">
                            <div class="field mb-3">
                                <label class="label terminal-form-label">Indicator Value *</label>
                                <div class="control">
                                    <input class="input terminal-input font-mono" type="text" id="mispAttrValue" value="${escapeHtml(initialValue)}">
                                </div>
                            </div>
                        </div>
                        <div class="column is-narrow" style="min-width: 170px;">
                            <div class="field mb-3">
                                <label class="label terminal-form-label">Type *</label>
                                <div class="control">
                                    <div class="select is-fullwidth terminal-select">
                                        <select id="mispAttrType">
                                            <option value="ip-src" ${initialType === 'ip-src' ? 'selected' : ''}>ip-src</option>
                                            <option value="ip-dst" ${initialType === 'ip-dst' ? 'selected' : ''}>ip-dst</option>
                                            <option value="domain" ${initialType === 'domain' ? 'selected' : ''}>domain</option>
                                            <option value="url" ${initialType === 'url' ? 'selected' : ''}>url</option>
                                            <option value="sha256" ${initialType === 'sha256' ? 'selected' : ''}>sha256</option>
                                            <option value="md5" ${initialType === 'md5' ? 'selected' : ''}>md5</option>
                                            <option value="email-src" ${initialType === 'email-src' ? 'selected' : ''}>email-src</option>
                                            <option value="vulnerability" ${initialType === 'vulnerability' || initialType === 'cve' ? 'selected' : ''}>vulnerability</option>
                                            <option value="other" ${initialType === 'other' || initialType === '' ? 'selected' : ''}>other</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="field mb-3">
                        <label class="label terminal-form-label">Tag (Optional)</label>
                        <div class="control has-icons-left">
                            <input class="input terminal-input" type="text" id="mispTagName" placeholder="e.g., TLP:AMBER">
                            <span class="icon is-small is-left modal-tag-icon">
                                <i class="material-icons">label</i>
                            </span>
                        </div>
                    </div>

                    <div id="mispFormResult" class="mt-2" style="word-break: break-word;"></div>

                    <div class="buttons is-right mt-3">
                        <button type="button" class="button terminal-action-btn" id="mispCancelBtn">Cancel</button>
                        <button type="submit" class="button terminal-action-btn modal-btn-misp" id="mispSubmitBtn">
                            <span>Create Event</span>
                            <span class="icon is-small"><i class="material-icons">send</i></span>
                        </button>
                    </div>
                </form>
            </div>
        `);

        // Attach MISP Form Listeners
        document.getElementById('mispCancelBtn')?.addEventListener('click', () => {
            this.resetStylesAndShowDetails();
        });

        const handleMispSubmit = async (e) => {
            if (e) {
                e.preventDefault();
                e.stopPropagation();
            }

            const submitBtn = document.getElementById('mispSubmitBtn');
            const resultBox = document.getElementById('mispFormResult');
            if (resultBox) resultBox.innerHTML = '';

            const eventInfo = document.getElementById('mispEventInfo')?.value?.trim();
            const attrVal = document.getElementById('mispAttrValue')?.value?.trim();
            const attrType = document.getElementById('mispAttrType')?.value?.trim();
            const tagName = document.getElementById('mispTagName')?.value?.trim() || '';

            if (!eventInfo || !attrVal || !attrType) {
                if (resultBox) {
                    resultBox.innerHTML = `<div class="notification terminal-form-notification is-danger">Event description, indicator value, and attribute type are required.</div>`;
                }
                return;
            }

            if (submitBtn) {
                submitBtn.classList.add('is-loading');
                submitBtn.disabled = true;
            }

            const payload = {
                event_info: eventInfo,
                attribute_value: attrVal,
                attribute_type: attrType,
                tag_name: tagName
            };

            try {
                await this.app.sendMispEvent(payload);
                if (resultBox) {
                    resultBox.innerHTML = `<div class="notification terminal-form-notification is-success">
                        Event created successfully in MISP!
                    </div>`;
                }
                setTimeout(() => {
                    this.resetStylesAndShowDetails();
                    this.close(); 
                }, 1500);
            } catch (err) {
                console.error("MISP form submission error:", err);
                if (resultBox) {
                    resultBox.innerHTML = `<div class="notification terminal-form-notification is-danger">
                        <strong>Failed:</strong> ${escapeHtml(err.message)}
                    </div>`;
                }
                if (submitBtn) {
                    submitBtn.classList.remove('is-loading');
                    submitBtn.disabled = false;
                }
            }
        };

        const mispForm = document.getElementById('mispForm');
        mispForm?.addEventListener('submit', handleMispSubmit);
        document.getElementById('mispSubmitBtn')?.addEventListener('click', (e) => {
            e.preventDefault();
            handleMispSubmit(e);
        });
    }

    resetStylesAndShowDetails() {
        this.showRawView();
        // Re-show original details using the ID stored on the archive button
        this.show(this.archiveButton?.dataset?.id || '', this.app.focus);
    }
}