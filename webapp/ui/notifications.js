import { escapeHtml } from './utils.js';

export class NotificationManager {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.attachListener();

        // RE-ENABLE POP-UPS: Listen for the event from app.js
        document.addEventListener('notification-received', (event) => {
            this.render(); // Update the history list/container
            this.showToast(event.detail); // Create the transient pop-up
        });
    }

    /**
     * Creates a transient "Toast" notification at the top of the screen.
     */
    showToast(notif) {
        // Ensure a container for toasts exists
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.style = "position: fixed; top: 20px; right: 20px; z-index: 9999; width: 320px;";
            document.body.appendChild(toastContainer);
        }

        const toast = document.createElement('div');
        const colorClass = notif.Error ? 'is-danger' : 'is-success';
        toast.className = `notification ${colorClass} is-light fadeIn-animation`;
        toast.style = "margin-bottom: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.1);";
        
        const timestamp = new Date(notif.created).toLocaleTimeString();
        toast.innerHTML = `
            <button class="delete"></button>
            <p><strong>[${timestamp}] New Alert</strong></p>
            <p>${escapeHtml(notif.info)}</p>
        `;

        // Handle manual close of the toast
        toast.querySelector('.delete').onclick = () => toast.remove();

        toastContainer.appendChild(toast);

        // Auto-remove after 6 seconds
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.5s ease';
            setTimeout(() => toast.remove(), 500);
        }, 6000);
    }

    attachListener() {
        this.container.addEventListener('click', async (event) => {
            const target = event.target;

            // 1. Handle Delete Button (Sync with Backend)
            const deleteBtn = target.closest('.delete');
            if (deleteBtn) {
                const notifDiv = deleteBtn.closest('.notification');
                if (notifDiv && notifDiv.dataset.id) {
                    // Call the backend "rogue" SQL handler (as discussed)
                    if (this.app.deleteNotificationFromDB) {
                        this.app.deleteNotificationFromDB(notifDiv.dataset.id);
                    }
                    
                    this.app.notifications = this.app.notifications.filter(n => n.id !== notifDiv.dataset.id);
                    this.render();
                }
                return;
            }

            // 2. Handle Details/ID links
            const idLink = target.closest('a[data-id]');
            if (idLink) {
                event.preventDefault();
                const customEvent = new CustomEvent('req-open-details', { detail: idLink.dataset.id });
                document.dispatchEvent(customEvent);
                return;
            }

            // 3. Handle Full Notification Click (Interactivity)
            const notifDiv = target.closest('.notification.is-clickable');
            if (notifDiv && notifDiv.dataset.link && !target.closest('a')) {
                window.open(notifDiv.dataset.link, '_blank');
            }
        });
    }

    render() {
        if (!this.container) return;
        this.container.innerHTML = '';
        
        this.app.notifications.forEach(notif => {
            const notifDiv = document.createElement('div');
            const colorClass = notif.Error ? 'is-danger' : 'is-success';
            
            notifDiv.className = `notification ${colorClass} is-light fadeIn-animation`;
            notifDiv.dataset.id = notif.id;

            if (notif.link) {
                notifDiv.classList.add('is-clickable');
                notifDiv.dataset.link = notif.link;
                notifDiv.style.cursor = 'pointer';
            }

            const deleteButton = document.createElement('button');
            deleteButton.className = 'delete';

            const message = document.createElement('p');
            const timestamp = new Date(notif.created).toLocaleTimeString();
            const escapedInfo = escapeHtml(notif.info);

            // Linkify UUIDs in the text
            const idRegex = /(with ID\s+)([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi;
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
                linkAnchor.className = 'button is-small is-link is-outlined ml-2';
                linkAnchor.textContent = 'View';
                notifDiv.appendChild(linkAnchor);
            }
            this.container.appendChild(notifDiv);
        });
    }
}