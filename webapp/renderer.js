import { Application } from "./app.js";
import { Contextualizer } from "./parser.js";
import { NotificationManager } from "./ui/notifications.js";
import { ModalManager } from "./ui/modal.js";
import { SearchController } from "./ui/search.js";
import { ServiceController } from "./ui/services.js";
import { HealthController } from "./ui/health.js";
import { ResponseController } from "./ui/responses.js";
import { ToolsController } from "./ui/tools.js";
import { CaseController } from './ui/cases.js';
import { ProfileController } from './ui/profile.js';
import { FeedController } from './ui/feed.js';
import { escapeHtml } from "./ui/utils.js";

const application = new Application();
const contextualizer = new Contextualizer();

const notifyMgr = new NotificationManager('notificationContainer', application);
const modalMgr = new ModalManager('detailsModal', application);
const searchCtrl = new SearchController('matchBox', application, contextualizer);
const serviceCtrl = new ServiceController('servicesContainer', application);
const healthCtrl = new HealthController('healthStatusContainer', application);
const responseCtrl = new ResponseController('responsesContainer', application);
const toolsCtrl = new ToolsController('toolsContainer', application);
const caseCtrl = new CaseController('casesContainer', application);
const profileCtrl = new ProfileController('profileContainer', application);
const feedCtrl = new FeedController('feedContainer', application);

const errorBox = document.getElementById("errors");
const sidebarLinks = document.querySelectorAll('.menu-list a');

const VIEW_CONTAINERS = [
    'matchBox',
    'responsesContainer',
    'feedContainer',
    'casesContainer',
    'healthStatusContainer',
    'toolsContainer',
    'servicesContainer',
    'profileContainer',
    'notificationContainer'
];

let currentActiveViewId = null;

function transitionToView(targetContainerId, onShowCallback) {
    if (currentActiveViewId === targetContainerId) {
        if (onShowCallback) onShowCallback();
        return;
    }

    VIEW_CONTAINERS.forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        if (id !== targetContainerId) {
            el.classList.add('is-hidden');
            el.classList.remove('fade-enter', 'fade-enter-active');
        }
    });

    const targetEl = document.getElementById(targetContainerId);
    if (targetEl) {
        targetEl.classList.add('fade-enter');
        targetEl.classList.remove('is-hidden');
        // Trigger reflow for CSS transition
        void targetEl.offsetWidth;
        targetEl.classList.add('fade-enter-active');
        setTimeout(() => {
            targetEl.classList.remove('fade-enter', 'fade-enter-active');
        }, 150);
    }

    currentActiveViewId = targetContainerId;
    if (onShowCallback) onShowCallback();
}

async function main() {
    await application.init();
    
    if (application.initialized) {
        showMainView();
        updateStatus();
    } else {
        errorBox.innerHTML = `<p class="has-text-danger">Could not initialize application.</p>`;
    }
}

function showMainView() {
    transitionToView('matchBox', () => {
        searchCtrl.renderForm();
    });
}

function setActiveSidebar(clickedLink) {
    sidebarLinks.forEach(l => l.classList.remove('is-active'));
    if (clickedLink) clickedLink.classList.add('is-active');
}

document.addEventListener('req-open-details', async (e) => {
    const id = e.detail;
    await application.fetchDetails(id);
    modalMgr.show(id, application.focus);
});

document.addEventListener('req-show-home', () => {
    const searchLink = document.getElementById("sidebarSearch");
    setActiveSidebar(searchLink);
    showMainView();
});

document.addEventListener('req-show-responses', () => {
    document.getElementById("sidebarRecentActivity").click();
});

document.addEventListener('req-open-case', async (e) => {
    const caseId = e.detail;
    if (sidebarCases) setActiveSidebar(sidebarCases);
    transitionToView('casesContainer', async () => {
        await caseCtrl.openCase({ id: caseId });
    });
});

document.getElementById("sidebarSearch").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    showMainView();
});

const sidebarFeed = document.getElementById("sidebarFeed");
if (sidebarFeed) {
    sidebarFeed.addEventListener('click', (e) => {
        setActiveSidebar(e.currentTarget);
        transitionToView('feedContainer', () => {
            feedCtrl.render();
        });
    });
}

const sidebarCases = document.getElementById("sidebarCases");
if (sidebarCases) {
    sidebarCases.addEventListener('click', (e) => {
        setActiveSidebar(e.currentTarget);
        transitionToView('casesContainer', () => {
            caseCtrl.render();
        });
    });
}

document.getElementById("sidebarRecentActivity").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    transitionToView('responsesContainer', () => {
        responseCtrl.render();
    });
});

document.getElementById("sidebarServices").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    transitionToView('servicesContainer', () => {
        serviceCtrl.render();
    });
});

document.getElementById("sidebarTools").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    transitionToView('toolsContainer', () => {
        toolsCtrl.render();
    });
});

document.getElementById("sidebarHealth").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    transitionToView('healthStatusContainer', () => {
        healthCtrl.render();
    });
});

document.getElementById("sidebarNotifications").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    transitionToView('notificationContainer', () => {
        notifyMgr.render();
    });
});

document.getElementById("sidebarProfile").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    transitionToView('profileContainer', () => {
        profileCtrl.render();
    });
});

function updateStatus() {
    if (application.errors.length > 0) {
        const uniqueErrors = [...new Set(application.errors)];
        errorBox.innerHTML = uniqueErrors.map(e => `<span class="system-status-pill status-warning"><span class="status-indicator-dot dot-warning"></span>${escapeHtml(e)}</span>`).join(' ');
    } else {
        errorBox.innerHTML = '<span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>system nominal</span>';
    }

    const notifIcon = document.getElementById('sidebarNotificationIcon');
    const notifText = document.getElementById('sidebarNotificationText');
    if (notifIcon && notifText) {
        if (application.notifications.length > 0) {
            notifIcon.classList.remove('has-text-grey');
            notifIcon.classList.add('has-text-warning');
            notifText.innerHTML = `Notifications (${application.notifications.length})`;
        } else {
            notifIcon.classList.remove('has-text-warning');
            notifIcon.classList.add('has-text-grey');
            notifText.innerHTML = `Notifications`;
        }
    }
}

document.addEventListener('notification-received', () => {
    updateStatus();
    if (currentActiveViewId === 'notificationContainer') {
        notifyMgr.render();
    }
});

// Periodic lightweight error check without layout thrashing
setInterval(updateStatus, 3000);

main();