import { escapeHtml } from './utils.js';

export class NotificationManager {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.attachListener();
    }

    attachListener() {
        // Delegate click events for notifications
        this.container.addEventListener('click', async (event) => {
            const link = event.target.closest('a');
            // If it's a link with an ID (view details)
            if (link && link.dataset.id) {
                event.preventDefault();
                // Dispatch a custom event so the Main renderer can handle the Modal opening
                // This keeps modules decoupled
                const customEvent = new CustomEvent('req-open-details', { detail: link.dataset.id });
                document.dispatchEvent(customEvent);
            }
            // If it's a delete button
            if (event.target.classList.contains('delete')) {
                const notifDiv = event.target.closest('.notification');
                if (notifDiv && notifDiv.dataset.id) {
                    this.app.notifications = this.app.notifications.filter(n => n.id !== notifDiv.dataset.id);
                    this.render();
                }
            }
        });
    }

    render() {
        if (!this.container) return;
        this.container.innerHTML = '';
        
        this.app.notifications.forEach(notif => {
            const notifDiv = document.createElement('div');
            const colorClass = notif.Error ? 'is-danger' : 'is-success';
            notifDiv.className = `notification ${colorClass} is-light`;
            notifDiv.dataset.id = notif.id;

            const deleteButton = document.createElement('button');
            deleteButton.className = 'delete';

            const message = document.createElement('p');
            const timestamp = new Date(notif.created).toLocaleTimeString();
            const escapedInfo = escapeHtml(notif.info);

            // Add clickable links for IDs
            const idRegex = /(with ID )([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/i;
            const processedInfo = escapedInfo.replace(idRegex, (match, prefix, uuid) => {
                return `${prefix}<a href="#" class="has-text-weight-bold" data-id="${uuid}">${uuid}</a>`;
            });

            message.innerHTML = `<strong>[${timestamp}]</strong> ${processedInfo}`;

            notifDiv.appendChild(deleteButton);
            notifDiv.appendChild(message);
            
            if (notif.link) {
                const linkAnchor = document.createElement('a');
                linkAnchor.href = notif.link;
                linkAnchor.target = '_blank';
                linkAnchor.className = 'button is-small is-link ml-2';
                linkAnchor.textContent = 'View';
                notifDiv.appendChild(linkAnchor);
            }
            this.container.appendChild(notifDiv);
        });
    }
}
