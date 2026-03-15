// webapp/renderer.js
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

const application = new Application();
const contextualizer = new Contextualizer();

const notifyMgr = new NotificationManager('notificationContainer', application);
const modalMgr = new ModalManager('detailsModal', application);
const searchCtrl = new SearchController('matchBox', application, contextualizer);
const serviceCtrl = new ServiceController('servicesContainer', application);
const healthCtrl = new HealthController('healthStatusContainer', application);
const responseCtrl = new ResponseController('matchBox', application);
const toolsCtrl = new ToolsController('toolsContainer', application);
const caseCtrl = new CaseController('casesContainer', application);
const profileCtrl = new ProfileController('profileContainer', application);

const errorBox = document.getElementById("errors");
const sidebarLinks = document.querySelectorAll('.menu-list a');

async function main() {
    await application.init();
    
    if (application.initialized) {
        showMainView();
        requestAnimationFrame(updateUI);
    } else {
        errorBox.innerHTML = `<p class="has-text-danger">Could not initialize application.</p>`;
    }
}

function hideAll() {
    document.getElementById('healthStatusContainer').classList.add('is-hidden');
    document.getElementById('matchBox').classList.add('is-hidden');
    document.getElementById('toolsContainer').classList.add('is-hidden');
    document.getElementById('casesContainer').classList.add('is-hidden');
    document.getElementById('servicesContainer').classList.add('is-hidden');
    document.getElementById('profileContainer').classList.add('is-hidden');
    document.getElementById('notificationContainer').classList.add('is-hidden');
}

function showMainView() {
    hideAll();
    document.getElementById('matchBox').classList.remove('is-hidden');
    searchCtrl.renderForm();
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
    showMainView();
});

document.addEventListener('req-show-responses', () => {
    document.getElementById("sidebarRecentActivity").click();
});

document.getElementById("sidebarSearch").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    showMainView();
});

const sidebarCases = document.getElementById("sidebarCases");
if (sidebarCases) {
    sidebarCases.addEventListener('click', (e) => {
        setActiveSidebar(e.currentTarget);
        hideAll();
        caseCtrl.render();
    });
}

document.getElementById("sidebarRecentActivity").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    document.getElementById('matchBox').classList.remove('is-hidden');
    responseCtrl.render();
});

document.getElementById("sidebarServices").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    serviceCtrl.render();
});

document.getElementById("sidebarTools").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    toolsCtrl.render();
});

document.getElementById("sidebarHealth").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    healthCtrl.render();
});

document.getElementById("sidebarNotifications").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    document.getElementById('notificationContainer').classList.remove('is-hidden');
    notifyMgr.render();
});

document.getElementById("sidebarProfile").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    profileCtrl.render();
});

let previousResults = [];
let previousNotifications = [];

function updateUI() {
    if (application.errors.length > 0) {
        const uniqueErrors = [...new Set(application.errors)];
        errorBox.innerHTML = uniqueErrors.map(e => `<p class="has-text-warning">${e}</p>`).join('');
    } else {
        errorBox.innerHTML = '<p class="has-text-success">system nominal</p>';
    }

    if (JSON.stringify(application.results) !== JSON.stringify(previousResults)) {
        previousResults = [...application.results];
        searchCtrl.renderResultCards(application.results, false);
    }

    if (JSON.stringify(application.notifications) !== JSON.stringify(previousNotifications)) {
        previousNotifications = [...application.notifications];
        notifyMgr.render();
        
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

    requestAnimationFrame(updateUI);
}

main();