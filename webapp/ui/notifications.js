import { escapeHtml } from './utils.js';

export class NotificationManager {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.activeFilter = 'all'; // 'all', 'error', 'info'
        this.searchQuery = '';
        this.attachListener();

        // Listen for real-time notifications dispatched by app.js
        document.addEventListener('notification-received', (event) => {
            this.render(); // Update the notification history feed
            this.showToast(event.detail); // Show modern dark toast popup
        });
    }

    /**
     * Creates a transient dark "Toast" notification at the top-right of the screen.
     */
    showToast(notif) {
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.style = "position: fixed; top: 20px; right: 20px; z-index: 9999; width: 360px;";
            document.body.appendChild(toastContainer);
        }

        const isErr = Boolean(notif.Error || notif.error);
        const toast = document.createElement('div');
        toast.className = `dark-toast ${isErr ? 'is-error' : 'is-success'} fadeIn-animation`;
        
        const timestamp = new Date(notif.created || Date.now()).toLocaleTimeString();
        const iconName = isErr ? 'error_outline' : 'check_circle_outline';
        
        toast.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.25rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <i class="material-icons" style="font-size: 1.1rem; color: ${isErr ? '#f14668' : '#48c78e'};">${iconName}</i>
                    <strong style="font-size: 0.85rem; color: #f5f5f5;">${isErr ? 'Alert' : 'Notification'}</strong>
                    <span style="font-size: 0.75rem; color: #8c9ba5; font-family: monospace;">[${timestamp}]</span>
                </div>
                <button class="notif-dismiss-btn delete-toast-btn" style="color: #8c9ba5;">
                    <i class="material-icons" style="font-size: 1.1rem;">close</i>
                </button>
            </div>
            <p style="font-size: 0.9rem; margin: 0; color: #d1d5db; line-height: 1.4;">${escapeHtml(notif.info || '')}</p>
        `;

        const deleteBtn = toast.querySelector('.delete-toast-btn');
        if (deleteBtn) {
            deleteBtn.onclick = () => toast.remove();
        }

        toastContainer.appendChild(toast);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.4s ease';
            setTimeout(() => toast.remove(), 400);
        }, 5000);
    }

    attachListener() {
        if (!this.container) return;

        this.container.addEventListener('click', async (event) => {
            const target = event.target;

            // 1. Filter buttons
            const filterBtn = target.closest('[data-notif-filter]');
            if (filterBtn) {
                this.activeFilter = filterBtn.dataset.notifFilter;
                this.render();
                return;
            }

            // 2. Clear All button
            const clearAllBtn = target.closest('#clearAllNotifsBtn');
            if (clearAllBtn) {
                if (confirm('Are you sure you want to clear all notifications?')) {
                    const list = [...(this.app.notifications || [])];
                    for (const notif of list) {
                        if (notif.id && this.app.deleteNotificationFromDB) {
                            this.app.deleteNotificationFromDB(notif.id);
                        }
                    }
                    this.app.notifications = [];
                    this.render();
                }
                return;
            }

            // 3. Single Dismiss button
            const dismissBtn = target.closest('.notif-dismiss-btn');
            if (dismissBtn) {
                const notifCard = dismissBtn.closest('.notif-card');
                if (notifCard && notifCard.dataset.id) {
                    const id = notifCard.dataset.id;
                    if (this.app.deleteNotificationFromDB) {
                        this.app.deleteNotificationFromDB(id);
                    }
                    this.app.notifications = (this.app.notifications || []).filter(n => n.id !== id);
                    this.render();
                }
                return;
            }

            // 4. Details/UUID links
            const idLink = target.closest('a[data-id]');
            if (idLink) {
                event.preventDefault();
                const customEvent = new CustomEvent('req-open-details', { detail: idLink.dataset.id });
                document.dispatchEvent(customEvent);
                return;
            }

            // 5. Full notification card click if link present
            const notifCard = target.closest('.notif-card.is-clickable');
            if (notifCard && notifCard.dataset.link && !target.closest('a') && !target.closest('button')) {
                window.open(notifCard.dataset.link, '_blank');
            }
        });

        // Search input delegation
        this.container.addEventListener('input', (event) => {
            if (event.target && event.target.id === 'notifSearchInput') {
                this.searchQuery = event.target.value.toLowerCase();
                this.renderListOnly();
            }
        });
    }

    render() {
        if (!this.container) return;

        // Structure HTML layout if control panel doesn't exist
        let controlsDiv = this.container.querySelector('#notifHeaderControls');
        let listDiv = this.container.querySelector('#notifListContainer');

        if (!controlsDiv || !listDiv) {
            this.container.innerHTML = `
                <div id="notifHeaderControls" class="notif-controls"></div>
                <div id="notifListContainer" class="notif-container"></div>
            `;
            controlsDiv = this.container.querySelector('#notifHeaderControls');
            listDiv = this.container.querySelector('#notifListContainer');
        }

        const notifications = this.app.notifications || [];
        const totalCount = notifications.length;
        const errorCount = notifications.filter(n => Boolean(n.Error || n.error)).length;
        const infoCount = totalCount - errorCount;

        controlsDiv.innerHTML = `
            <div class="level mb-3">
                <div class="level-left">
                    <div>
                        <h1 class="title is-4 has-text-info mb-1" style="display: flex; align-items: center; gap: 0.5rem;">
                            <span>Notifications</span>
                            <span class="tag is-dark is-rounded">${totalCount}</span>
                        </h1>
                        <p class="subtitle is-7 has-text-grey">Real-time alerts, system activity, and security event logs</p>
                    </div>
                </div>
                <div class="level-right">
                    <button class="button is-danger is-outlined is-small" id="clearAllNotifsBtn" ${totalCount === 0 ? 'disabled' : ''}>
                        <span class="icon-text">
                            <span class="icon"><i class="material-icons">clear_all</i></span>
                            <span>Clear All</span>
                        </span>
                    </button>
                </div>
            </div>

            <div class="columns is-mobile is-vcentered">
                <div class="column">
                    <div class="buttons has-addons">
                        <button class="button is-small ${this.activeFilter === 'all' ? 'is-info' : 'is-dark'}" data-notif-filter="all">
                            All (${totalCount})
                        </button>
                        <button class="button is-small ${this.activeFilter === 'error' ? 'is-danger' : 'is-dark'}" data-notif-filter="error">
                            Errors (${errorCount})
                        </button>
                        <button class="button is-small ${this.activeFilter === 'info' ? 'is-success' : 'is-dark'}" data-notif-filter="info">
                            Info (${infoCount})
                        </button>
                    </div>
                </div>
                <div class="column is-narrow">
                    <div class="control has-icons-left" style="min-width: 200px;">
                        <input class="input is-small has-background-dark has-text-light" type="text" id="notifSearchInput" placeholder="Filter alerts..." value="${escapeHtml(this.searchQuery)}">
                        <span class="icon is-small is-left">
                            <i class="material-icons" style="font-size: 1rem; color: #8c9ba5;">search</i>
                        </span>
                    </div>
                </div>
            </div>
        `;

        this.renderListOnly();
    }

    renderListOnly() {
        const listDiv = this.container.querySelector('#notifListContainer');
        if (!listDiv) return;

        listDiv.innerHTML = '';
        let notifications = this.app.notifications || [];

        // Apply Category Filter
        if (this.activeFilter === 'error') {
            notifications = notifications.filter(n => Boolean(n.Error || n.error));
        } else if (this.activeFilter === 'info') {
            notifications = notifications.filter(n => !Boolean(n.Error || n.error));
        }

        // Apply Text Search Query
        if (this.searchQuery) {
            notifications = notifications.filter(n => {
                const infoText = (n.info || '').toLowerCase();
                const idText = (n.id || '').toLowerCase();
                return infoText.includes(this.searchQuery) || idText.includes(this.searchQuery);
            });
        }

        // Empty state
        if (notifications.length === 0) {
            const emptyDiv = document.createElement('div');
            emptyDiv.className = 'notif-empty-state';
            emptyDiv.innerHTML = `
                <i class="material-icons">notifications_off</i>
                <p class="has-text-weight-bold has-text-light">No notifications to show</p>
                <p class="is-size-7 has-text-grey mt-1">
                    ${this.searchQuery || this.activeFilter !== 'all' ? 'Try adjusting your search or filter settings.' : 'System status is quiet. New activity will appear here in real-time.'}
                </p>
            `;
            listDiv.appendChild(emptyDiv);
            return;
        }

        // Render Cards
        notifications.forEach(notif => {
            const notifCard = document.createElement('div');
            const isErr = Boolean(notif.Error || notif.error);
            const statusClass = isErr ? 'is-error' : 'is-success';

            notifCard.className = `notif-card ${statusClass} fadeIn-animation`;
            notifCard.dataset.id = notif.id;

            if (notif.link) {
                notifCard.classList.add('is-clickable');
                notifCard.dataset.link = notif.link;
                notifCard.style.cursor = 'pointer';
            }

            const infoStr = notif.info || '';
            const iconName = this.getIconForNotification(infoStr, isErr);
            const typeLabel = this.getTypeLabel(infoStr, isErr);
            const timestamp = new Date(notif.created || Date.now()).toLocaleTimeString();
            const escapedInfo = escapeHtml(infoStr);

            // Linkify UUIDs in text
            const idRegex = /(with ID\s+)([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi;
            const processedInfo = escapedInfo.replace(idRegex, (match, prefix, uuid) => {
                return `${prefix}<a href="#" class="has-text-weight-bold" data-id="${uuid}">${uuid}</a>`;
            });

            const countBadge = notif.count && notif.count > 1 
                ? `<span class="tag is-warning is-rounded" title="Occurred ${notif.count} times">${notif.count}x</span>` 
                : '';

            const linkButton = notif.link 
                ? `<div class="mt-2"><a href="${escapeHtml(notif.link)}" target="_blank" class="button is-small is-link is-outlined">
                    <span class="icon-text">
                        <span class="icon"><i class="material-icons">open_in_new</i></span>
                        <span>View</span>
                    </span>
                   </a></div>` 
                : '';

            notifCard.innerHTML = `
                <div class="notif-header">
                    <div class="notif-meta">
                        <i class="material-icons notif-icon">${iconName}</i>
                        ${typeLabel}
                        <span class="notif-time">[${timestamp}]</span>
                        ${countBadge}
                    </div>
                    <button class="notif-dismiss-btn" title="Dismiss notification">
                        <i class="material-icons" style="font-size: 1.1rem;">close</i>
                    </button>
                </div>
                <div class="notif-body">${processedInfo}</div>
                ${linkButton}
            `;

            listDiv.appendChild(notifCard);
        });
    }

    getIconForNotification(info, isErr) {
        if (isErr) return 'error_outline';
        const lower = info.toLowerCase();
        if (lower.includes('dns') || lower.includes('lookup') || lower.includes('domain')) return 'dns';
        if (lower.includes('ssh') || lower.includes('key')) return 'vpn_key';
        if (lower.includes('case')) return 'work_outline';
        if (lower.includes('service')) return 'dns';
        return 'check_circle_outline';
    }

    getTypeLabel(info, isErr) {
        if (isErr) return '<span class="tag is-danger is-light">ERROR</span>';
        const lower = info.toLowerCase();
        if (lower.includes('dns') || lower.includes('lookup')) return '<span class="tag is-info is-light">DNS</span>';
        if (lower.includes('ssh')) return '<span class="tag is-warning is-light">SSH</span>';
        if (lower.includes('reverse')) return '<span class="tag is-info is-light">REVERSE</span>';
        return '<span class="tag is-success is-light">INFO</span>';
    }
}