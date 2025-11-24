import { escapeHtml } from './utils.js';

export class ModalManager {
    constructor(modalId, app) {
        this.modal = document.getElementById(modalId);
        this.app = app;
        
        // Cache elements
        this.title = document.getElementById('detailsModalTitle');
        this.content = document.getElementById('detailsModalContent');
        this.archiveButton = document.getElementById('archiveButton');
        this.copyButton = document.getElementById('copyButton');
        this.mispButton = document.getElementById('mispButton');
        
        this.attachListeners();
    }

    attachListeners() {
        // Close actions
        this.modal.querySelectorAll('.delete, .modal-background').forEach(el => {
            el.addEventListener('click', () => this.close());
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

        // Copy
        if (this.copyButton) {
            this.copyButton.addEventListener('click', () => {
                navigator.clipboard.writeText(this.content.textContent).then(() => {
                    const originalHTML = this.copyButton.innerHTML;
                    this.copyButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">check</i></span><span>Copied!</span></span>`;
                    setTimeout(() => {
                        this.copyButton.innerHTML = originalHTML;
                    }, 2000);
                }).catch(err => console.error('Failed to copy text: ', err));
            });
        }

        // MISP Button triggers the form render
        if (this.mispButton) {
            this.mispButton.addEventListener('click', () => this.renderMispForm());
        }
    }

    show(result, details) {
        let displayId = result.id || result;
        if (typeof displayId === 'string' && displayId.length > 24) {
            displayId = `${displayId.substring(0, 10)}...${displayId.substring(displayId.length - 10)}`;
        }
        
        this.title.textContent = `Details for ${displayId}`;
        this.title.title = `Full ID: ${result.id || result}`;
        this.archiveButton.dataset.id = result.id || result;

        try {
            this.content.textContent = JSON.stringify(details, null, 2);
        } catch (e) {
            this.content.textContent = "Error: Could not display details.";
        }
        this.modal.classList.add('is-active');
    }

    close() {
        this.modal.classList.remove('is-active');
        this.content.textContent = '';
        this.content.style.whiteSpace = '';
        this.content.style.fontFamily = '';
    }

    renderMispForm() {
        const currentData = this.app.focus;
        let eventSource = null;

        // 1. Validate Data & Find SummarizedEvent
        // We look for an object that matches the SummarizedEvent struct signature (matched, value, from)
        if (Array.isArray(currentData)) {
            eventSource = currentData.find(item => 
                item && 
                typeof item === 'object' && 
                'matched' in item && 
                'value' in item && 
                'from' in item
            );
        }

        if (!eventSource) {
            this.content.style.whiteSpace = 'normal';
            this.content.style.fontFamily = 'inherit';
            
            this.content.innerHTML = `
                <div class="notification is-warning is-light">
                    <strong>Insufficient Data:</strong> Could not find valid event data in the response.
                </div>
                <div class="buttons is-right">
                    <button class="button" id="mispCancelBtn">Go Back</button>
                </div>`;
            
            document.getElementById('mispCancelBtn').addEventListener('click', () => {
                this.resetStylesAndShowDetails();
            });
            return;
        }

        // 2. Extract Data
        let initialValue = eventSource.value || "";
        let initialType = eventSource.type || "";
        
        // Mapping
        if (initialType === 'ip') initialType = 'ip-src';
        if (initialType === 'ipv4') initialType = 'ip-src';
        if (initialType === 'ipv6') initialType = 'ip-src';
        if (initialType === 'email') initialType = 'email-src';
        
        let initialInfo = `Investigation of ${initialValue}`;
        if (eventSource.info) {
            initialInfo = `ThreatCo: ${eventSource.info.substring(0, 150)}${eventSource.info.length > 150 ? '...' : ''}`;
        }

        // 3. Override Styles for Form Layout
        this.content.style.whiteSpace = 'normal';
        this.content.style.fontFamily = 'sans-serif';

        // 4. Render Form
        this.content.innerHTML = `
            <div class="box" style="box-shadow: none; padding: 0.5rem;">
                <h3 class="title is-5 has-text-dark mb-4">
                    <span class="icon-text">
                        <span class="icon has-text-danger"><i class="material-icons">bug_report</i></span>
                        <span>Create MISP Event</span>
                    </span>
                </h3>
                
                <form id="mispForm">
                    <div class="field">
                        <label class="label">Event Description</label>
                        <div class="control">
                            <input class="input" type="text" id="mispEventInfo" value="${escapeHtml(initialInfo)}" required>
                        </div>
                    </div>

                    <div class="columns is-variable is-2 mb-2">
                        <div class="column">
                            <div class="field">
                                <label class="label">Value</label>
                                <div class="control">
                                    <input class="input" type="text" id="mispAttrValue" value="${escapeHtml(initialValue)}" required>
                                </div>
                            </div>
                        </div>
                        <div class="column is-narrow">
                            <div class="field">
                                <label class="label">Type</label>
                                <div class="control">
                                    <div class="select is-fullwidth">
                                        <select id="mispAttrType">
                                            <option value="ip-src" ${initialType === 'ip-src' ? 'selected' : ''}>ip-src</option>
                                            <option value="ip-dst" ${initialType === 'ip-dst' ? 'selected' : ''}>ip-dst</option>
                                            <option value="domain" ${initialType === 'domain' ? 'selected' : ''}>domain</option>
                                            <option value="url" ${initialType === 'url' ? 'selected' : ''}>url</option>
                                            <option value="sha256" ${initialType === 'sha256' ? 'selected' : ''}>sha256</option>
                                            <option value="md5" ${initialType === 'md5' ? 'selected' : ''}>md5</option>
                                            <option value="email-src" ${initialType === 'email-src' ? 'selected' : ''}>email-src</option>
                                            <option value="other" ${initialType === 'other' || initialType === '' ? 'selected' : ''}>other</option>
                                        </select>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="field">
                        <label class="label">Tag (Optional)</label>
                        <div class="control has-icons-left">
                            <input class="input" type="text" id="mispTagName" placeholder="e.g., TLP:AMBER">
                            <span class="icon is-small is-left">
                                <i class="material-icons">label</i>
                            </span>
                        </div>
                    </div>

                    <div id="mispFormResult" class="mt-3" style="word-break: break-word;"></div>

                    <div class="buttons is-right mt-5">
                        <button type="button" class="button" id="mispCancelBtn">Cancel</button>
                        <button type="submit" class="button is-danger" id="mispSubmitBtn">
                            <span>Create Event</span>
                            <span class="icon is-small"><i class="material-icons">send</i></span>
                        </button>
                    </div>
                </form>
            </div>
        `;

        // 5. Attach Listeners
        document.getElementById('mispCancelBtn').addEventListener('click', () => {
            this.resetStylesAndShowDetails();
        });

        document.getElementById('mispForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = document.getElementById('mispSubmitBtn');
            const resultBox = document.getElementById('mispFormResult');
            
            submitBtn.classList.add('is-loading');
            submitBtn.disabled = true;
            resultBox.innerHTML = '';

            const payload = {
                event_info: document.getElementById('mispEventInfo').value,
                attribute_value: document.getElementById('mispAttrValue').value,
                attribute_type: document.getElementById('mispAttrType').value,
                tag_name: document.getElementById('mispTagName').value
            };

            try {
                await this.app.sendMispEvent(payload);
                resultBox.innerHTML = `<div class="notification is-success is-light">
                    <button class="delete"></button>
                    Event created successfully!
                </div>`;
                setTimeout(() => {
                    this.resetStylesAndShowDetails();
                    this.close(); 
                }, 1500);
            } catch (err) {
                resultBox.innerHTML = `<div class="notification is-danger is-light">
                    <button class="delete"></button>
                    <strong>Failed:</strong> ${err.message}
                </div>`;
                submitBtn.classList.remove('is-loading');
                submitBtn.disabled = false;
                
                const delBtn = resultBox.querySelector('.delete');
                if(delBtn) delBtn.addEventListener('click', () => resultBox.innerHTML = '');
            }
        });
    }

    resetStylesAndShowDetails() {
        this.content.style.whiteSpace = '';
        this.content.style.fontFamily = '';
        // Re-show original details using the ID stored on the archive button
        this.show(this.archiveButton.dataset.id, this.app.focus);
    }
}