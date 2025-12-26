import { escapeHtml } from './utils.js';

export class CaseController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.currentCase = null;
    }

    async render() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
            <div class="level">
                <div class="level-left">
                    <h1 class="title has-text-info">Case Management</h1>
                </div>
                <div class="level-right">
                    <button class="button is-success" id="btnNewCase">
                        <span class="icon"><i class="material-icons">add</i></span>
                        <span>New Case</span>
                    </button>
                </div>
            </div>
            <div id="caseListContainer" class="columns is-multiline"></div>
            
            <div class="modal" id="newCaseModal">
                <div class="modal-background"></div>
                <div class="modal-card">
                    <header class="modal-card-head">
                        <p class="modal-card-title">Create New Case</p>
                        <button class="delete" aria-label="close"></button>
                    </header>
                    <section class="modal-card-body">
                        <div class="field">
                            <label class="label">Case Name</label>
                            <div class="control"><input class="input" type="text" id="newCaseName" placeholder="e.g. Phishing Campaign Dec 2025"></div>
                        </div>
                        <div class="field">
                            <label class="label">Description</label>
                            <div class="control"><textarea class="textarea" id="newCaseDesc" placeholder="Brief summary..."></textarea></div>
                        </div>
                    </section>
                    <footer class="modal-card-foot">
                        <button class="button is-success" id="btnSaveCase">Create</button>
                        <button class="button" id="btnCancelCase">Cancel</button>
                    </footer>
                </div>
            </div>
        `;

        this.attachMainListeners();
        await this.loadCases();
    }

    attachMainListeners() {
        const modal = document.getElementById('newCaseModal');
        const closeModal = () => modal.classList.remove('is-active');

        document.getElementById('btnNewCase').onclick = () => modal.classList.add('is-active');
        document.getElementById('btnCancelCase').onclick = closeModal;
        modal.querySelector('.delete').onclick = closeModal;

        document.getElementById('btnSaveCase').onclick = async () => {
            const name = document.getElementById('newCaseName').value;
            const desc = document.getElementById('newCaseDesc').value;
            if (!name) return alert("Name is required");

            try {
                const res = await this.app._fetch('/cases/create', {
                    method: 'POST',
                    body: JSON.stringify({ name, description: desc })
                });
                if (!res.ok) throw new Error(await res.text());
                closeModal();
                await this.loadCases();
            } catch (e) {
                alert("Error creating case: " + e.message);
            }
        };
    }

    async loadCases() {
        const container = document.getElementById('caseListContainer');
        container.innerHTML = '<div class="loader"></div>';
        try {
            const res = await this.app._fetch('/cases/list');
            const cases = await res.json();
            container.innerHTML = '';

            if (cases.length === 0) {
                container.innerHTML = '<div class="column is-full"><p class="has-text-grey">No open cases found.</p></div>';
                return;
            }

            cases.forEach(c => {
                const col = document.createElement('div');
                col.className = 'column is-one-third';
                const card = document.createElement('div');
                card.className = 'card has-background-dark';
                card.style.cursor = 'pointer';
                card.onclick = () => this.openCase(c);

                const statusColor = c.status === 'Open' ? 'is-success' : 'is-danger';

                card.innerHTML = `
                    <div class="card-content">
                        <div class="media">
                            <div class="media-content">
                                <p class="title is-4 has-text-white">${escapeHtml(c.name)}</p>
                                <p class="subtitle is-6 has-text-grey-light">by ${escapeHtml(c.created_by)}</p>
                            </div>
                            <div class="media-right">
                                <span class="tag ${statusColor}">${escapeHtml(c.status)}</span>
                            </div>
                        </div>
                        <div class="content has-text-light">
                            ${escapeHtml(c.description || 'No description')}
                            <br>
                            <small class="has-text-grey">${new Date(c.created_at).toLocaleString()}</small>
                            <br>
                            <span class="tag is-dark mt-2">${c.iocs ? c.iocs.length : 0} IOCs</span>
                        </div>
                    </div>
                `;
                col.appendChild(card);
                container.appendChild(col);
            });
        } catch (e) {
            container.innerHTML = `<p class="has-text-danger">Error loading cases: ${e.message}</p>`;
        }
    }

    openCase(c) {
        this.currentCase = c;
        // Re-render container with details view
        this.container.innerHTML = `
            <div class="mb-4">
                <button class="button is-small is-dark" id="btnBackList"><span class="icon"><i class="material-icons">arrow_back</i></span><span>Back to Cases</span></button>
            </div>
            <div class="box has-background-custom">
                <div class="level">
                    <div class="level-left">
                        <div>
                            <h2 class="title is-3 has-text-white">${escapeHtml(c.name)}</h2>
                            <p class="subtitle is-6 has-text-grey-light">Created by ${escapeHtml(c.created_by)} on ${new Date(c.created_at).toLocaleString()}</p>
                        </div>
                    </div>
                    <div class="level-right">
                         <div class="field has-addons">
                            <div class="control">
                                <button class="button is-danger" id="btnDeleteCase">
                                    <span class="icon"><i class="material-icons">delete</i></span>
                                    <span>Delete Case</span>
                                </button>
                            </div>
                         </div>
                    </div>
                </div>
                <hr class="has-background-grey-dark">
                
                <div class="columns">
                    <div class="column is-two-thirds">
                         <h4 class="title is-5 has-text-info">IOCs</h4>
                         <div class="field has-addons">
                            <div class="control is-expanded">
                                <input class="input is-small" type="text" id="inputAddIOC" placeholder="Add IP, Domain, Hash...">
                            </div>
                            <div class="control">
                                <button class="button is-info is-small" id="btnAddIOC">Add</button>
                            </div>
                         </div>
                         <div class="tags are-medium" id="iocList">
                             ${(c.iocs || []).map(ioc => `<span class="tag is-dark">${escapeHtml(ioc)}<button class="delete is-small delete-ioc" data-val="${escapeHtml(ioc)}"></button></span>`).join('')}
                         </div>

                         <h4 class="title is-5 has-text-info mt-5">Comments</h4>
                         <div id="commentList" class="mb-4" style="max-height: 300px; overflow-y: auto;">
                             ${(c.comments || []).map(cm => `
                                <article class="media">
                                    <div class="media-content">
                                        <div class="content">
                                            <p class="has-text-light">
                                                <strong>${escapeHtml(cm.user)}</strong> <small>${new Date(cm.created_at).toLocaleString()}</small>
                                                <br>
                                                ${escapeHtml(cm.text)}
                                            </p>
                                        </div>
                                    </div>
                                </article>
                             `).join('')}
                         </div>
                         <article class="media">
                            <div class="media-content">
                                <div class="field">
                                    <p class="control">
                                        <textarea class="textarea has-background-dark has-text-white" id="inputComment" placeholder="Add a comment..."></textarea>
                                    </p>
                                </div>
                                <div class="field">
                                    <p class="control">
                                        <button class="button is-info" id="btnPostComment">Post comment</button>
                                    </p>
                                </div>
                            </div>
                         </article>
                    </div>
                    <div class="column">
                         <h4 class="title is-5 has-text-warning">Actions</h4>
                         <p class="has-text-grey-light is-size-7">More analysis tools coming soon...</p>
                    </div>
                </div>
            </div>
        `;

        document.getElementById('btnBackList').onclick = () => this.render();

        document.getElementById('btnDeleteCase').onclick = async () => {
            if (!confirm("Are you sure you want to permanently delete this case? This cannot be undone.")) {
                return;
            }

            try {
                const res = await this.app._fetch('/cases/delete', {
                    method: 'POST',
                    body: JSON.stringify({ id: this.currentCase.id })
                });

                if (!res.ok) throw new Error(await res.text());

                // Go back to the list view after deletion
                this.render();
            } catch (e) {
                alert("Delete failed: " + e.message);
            }
        };

        document.getElementById('btnAddIOC').onclick = () => {
            const val = document.getElementById('inputAddIOC').value.trim();
            if (!val) return;
            if (!this.currentCase.iocs) this.currentCase.iocs = [];
            if (!this.currentCase.iocs.includes(val)) {
                this.currentCase.iocs.push(val);
                this.updateCase();
            }
            document.getElementById('inputAddIOC').value = "";
        };

        // Event delegation for delete IOC buttons
        document.getElementById('iocList').onclick = (e) => {
            if (e.target.classList.contains('delete-ioc')) {
                const val = e.target.dataset.val;
                this.currentCase.iocs = this.currentCase.iocs.filter(i => i !== val);
                this.updateCase();
            }
        };

        document.getElementById('btnPostComment').onclick = async () => {
            const text = document.getElementById('inputComment').value.trim();
            if (!text) return;

            // Optimistic update
            const comment = {
                user: this.app.user.email, // Assume current user
                text: text,
                created_at: new Date().toISOString()
            };

            if (!this.currentCase.comments) this.currentCase.comments = [];
            this.currentCase.comments.push(comment);
            await this.updateCase();
        };
    }

    async updateCase() {
        try {
            const res = await this.app._fetch('/cases/update', {
                method: 'POST',
                body: JSON.stringify(this.currentCase)
            });
            if (!res.ok) throw new Error(await res.text());
            this.openCase(this.currentCase); // Re-render details
        } catch (e) {
            alert("Update failed: " + e.message);
        }
    }
}