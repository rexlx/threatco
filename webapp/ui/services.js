import { escapeHtml } from './utils.js';

export class ServiceController {
    constructor(viewId, app) {
        this.view = document.getElementById(viewId);
        this.listContainer = document.getElementById('cardList');
        this.app = app;
        
        this.initListeners();
    }
    
    initListeners() {
        const backBtn = document.getElementById('backButtonServices');
        if (backBtn) {
            backBtn.addEventListener('click', () => {
                document.dispatchEvent(new Event('req-show-home'));
            });
        }

        const rectifyBtn = document.getElementById('rectifyServicesButton');
        if (rectifyBtn) {
            rectifyBtn.addEventListener('click', async () => {
                 await this.app.rectifyServices();
                 await this.render();
            });
        }
    }

    async render() {
        await this.app.getServices();
        this.view.classList.remove('is-hidden');
        this.listContainer.innerHTML = '';
        
        if (this.app.servers.length === 0) {
            this.listContainer.innerHTML = '<p class="has-text-white">No services available.</p>';
            return;
        }

        this.app.servers.forEach(data => {
            // Determine if this service is already active in the user's profile
            data.checked = this.app.user.services?.some(s => s.kind === data.kind) || false;
            this.listContainer.appendChild(this.createCard(data));
        });
    }

    createCard(service) {
        const column = document.createElement('div');
        column.className = 'column is-one-third-desktop is-half-tablet';
        
        const card = document.createElement('div');
        card.className = 'card has-background-dark is-flex is-flex-direction-column';
        card.style.height = '100%';
        
        // Header
        const header = document.createElement('header');
        header.className = 'card-header';
        const title = document.createElement('p');
        title.className = 'card-header-title has-text-white';
        title.textContent = escapeHtml(service.kind);
        header.appendChild(title);
        
        // Content
        const contentDiv = document.createElement('div');
        contentDiv.className = 'card-content has-background-black';
        contentDiv.style.flexGrow = '1';
        
        const content = document.createElement('div');
        content.className = 'content has-text-link-light';
        content.textContent = Array.isArray(service.type) ? service.type.map(escapeHtml).join(', ') : "Invalid Type";
        contentDiv.appendChild(content);
        
        // Footer
        const footer = document.createElement('footer');
        footer.className = 'card-footer';
        
        const addButton = document.createElement('a');
        addButton.href = '#';
        addButton.className = 'card-footer-item has-text-white';
        addButton.textContent = service.checked ? 'Remove' : 'Add';
        addButton.classList.add(service.checked ? 'has-background-warning' : 'has-background-success');
        
        // Add/Remove Logic
        addButton.addEventListener('click', (e) => {
            e.preventDefault();
            service.checked = !service.checked;
            if (service.checked) {
                this.app.addService(service);
                addButton.textContent = 'Remove';
                addButton.classList.replace('has-background-success', 'has-background-warning');
            } else {
                this.app.removeService(service);
                addButton.textContent = 'Add';
                addButton.classList.replace('has-background-warning', 'has-background-success');
            }
        });
        
        footer.appendChild(addButton);
        card.appendChild(header);
        card.appendChild(contentDiv);
        card.appendChild(footer);
        
        column.appendChild(card);
        return column;
    }
}
