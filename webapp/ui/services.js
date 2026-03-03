import { escapeHtml } from './utils.js';

export class ServiceController {
    constructor(viewId, app) {
        this.view = document.getElementById(viewId);
        this.app = app;
    }

    async render() {
        await this.app.getServices();
        this.view.classList.remove('is-hidden');
        
        let html = `
            <div class="block">
                <h1 class="title has-text-info">Services</h1>
            </div>
            <div class="block mb-4">
                <div class="buttons">
                    <button class="button is-info" id="rectifyServicesButton" type="button">
                        <span class="icon-text">
                            <span class="icon"><i class="material-icons">sync</i></span>
                            <span>Rectify</span>
                        </span>
                    </button>
                </div>
            </div>
        `;

        if (this.app.servers.length === 0) {
            html += '<p class="has-text-white">No services available.</p>';
            this.view.innerHTML = html;
            this.initListeners();
            return;
        }

        html += `
            <table class="table is-fullwidth is-striped">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Types</th>
                        <th class="has-text-right">Actions</th>
                    </tr>
                </thead>
                <tbody>
        `;

        this.app.servers.forEach((data, index) => {
            const isChecked = this.app.user.services?.some(s => s.kind === data.kind) || false;
            data.checked = isChecked;
            const types = Array.isArray(data.type) ? data.type.map(escapeHtml).join(', ') : "Invalid Type";
            
            const btnClass = isChecked ? 'is-warning' : 'is-success';
            const btnIcon = isChecked ? 'remove_circle' : 'add_circle';
            const btnText = isChecked ? 'Remove' : 'Add';

            html += `
                <tr>
                    <td class="is-vcentered"><strong>${escapeHtml(data.kind)}</strong></td>
                    <td class="is-vcentered" style="word-break: break-all;">${types}</td>
                    <td class="is-vcentered">
                        <div class="field is-grouped is-grouped-right">
                            <p class="control">
                                <button class="button is-small ${btnClass} is-light toggle-service-btn" data-index="${index}">
                                    <span class="icon-text">
                                        <span class="icon is-small"><i class="material-icons">${btnIcon}</i></span>
                                        <span>${btnText}</span>
                                    </span>
                                </button>
                            </p>
                        </div>
                    </td>
                </tr>
            `;
        });

        html += `
                </tbody>
            </table>
        `;

        this.view.innerHTML = html;
        this.initListeners();
    }

    initListeners() {
        const rectifyBtn = document.getElementById('rectifyServicesButton');
        if (rectifyBtn) {
            rectifyBtn.addEventListener('click', async () => {
                 rectifyBtn.classList.add('is-loading');
                 await this.app.rectifyServices();
                 await this.render();
            });
        }

        const toggleBtns = this.view.querySelectorAll('.toggle-service-btn');
        toggleBtns.forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                const index = btn.getAttribute('data-index');
                const service = this.app.servers[index];
                
                service.checked = !service.checked;
                if (service.checked) {
                    this.app.addService(service);
                } else {
                    this.app.removeService(service);
                }
                
                // Re-render to update the table state immediately
                this.render();
            });
        });
    }
}