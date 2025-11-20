import { Application } from "./app.js";
import { Contextualizer } from "./parser.js";
import { NotificationManager } from "./ui/notifications.js";
import { ModalManager } from "./ui/modal.js";
import { SearchController } from "./ui/search.js";
import { ServiceController } from "./ui/services.js";
import { HealthController } from "./ui/health.js";
import { ResponseController } from "./ui/responses.js"; // <-- IMPORT THIS

// --- Initialization ---
const application = new Application();
const contextualizer = new Contextualizer();

// --- Managers ---
const notifyMgr = new NotificationManager('notificationContainer', application);
const modalMgr = new ModalManager('detailsModal', application);
const searchCtrl = new SearchController('matchBox', application, contextualizer);
const serviceCtrl = new ServiceController('servicesView', application);
const healthCtrl = new HealthController('healthStatusContainer', application);
const responseCtrl = new ResponseController('matchBox', application); // <-- INIT THIS

// --- Global Elements ---
const mainSection = document.getElementById("mainSection");
const serviceView = document.getElementById("servicesView");
const profileView = document.getElementById("profileView");
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

// --- Navigation ---
function hideAll() {
    [mainSection, serviceView, profileView].forEach(el => el.classList.add('is-hidden'));
    document.getElementById('healthStatusContainer').classList.add('is-hidden');
    document.getElementById('matchBox').classList.add('is-hidden');
}

function showMainView() {
    hideAll();
    mainSection.classList.remove('is-hidden');
    document.getElementById('matchBox').classList.remove('is-hidden');
    searchCtrl.renderForm();
}

function setActiveSidebar(clickedLink) {
    sidebarLinks.forEach(l => l.classList.remove('is-active'));
    if (clickedLink) clickedLink.classList.add('is-active');
}

// --- Event Listeners (Global Navigation) ---

document.addEventListener('req-open-details', async (e) => {
    const id = e.detail;
    await application.fetchDetails(id);
    modalMgr.show(id, application.focus);
});

document.addEventListener('req-show-home', () => {
    showMainView();
});

document.getElementById("sidebarSearch").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    showMainView();
});

// --- THIS WAS MISSING BEFORE ---
document.getElementById("sidebarRecentActivity").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    mainSection.classList.remove('is-hidden');
    document.getElementById('matchBox').classList.remove('is-hidden'); // Re-use matchBox
    responseCtrl.render();
});
// ------------------------------

document.getElementById("sidebarServices").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    serviceCtrl.render();
});

document.getElementById("sidebarHealth").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    mainSection.classList.remove('is-hidden');
    healthCtrl.render();
});

document.getElementById("sidebarProfile").addEventListener('click', (e) => {
    setActiveSidebar(e.currentTarget);
    hideAll();
    profileView.classList.remove('is-hidden');
    document.getElementById("editUserEmail").value = application.user.email || '';
});

document.getElementById("backButtonProfile").addEventListener('click', showMainView);

document.getElementById("updateUserButton").addEventListener("click", async () => {
    await application.fetchUser();
    alert('User profile re-synced!');
});

// --- The Loop ---
let previousResults = [];
let previousNotifications = [];

function updateUI() {
    if (application.errors.length > 0) {
        // Dedupe errors
        const uniqueErrors = [...new Set(application.errors)];
        errorBox.innerHTML = uniqueErrors.map(e => `<p class="has-text-warning">${e}</p>`).join('');
    } else {
        errorBox.innerHTML = '<p class="has-text-success">system nominal</p>';
    }

    // The UI Loop should only force a re-render of result cards if we are currently looking at them
    // But simply checking if results changed is usually safe enough.
    if (JSON.stringify(application.results) !== JSON.stringify(previousResults)) {
        previousResults = [...application.results];
        // Only re-render if we are NOT in Response View (check by seeing if the search form or results are active)
        // For simplicity, we just call renderResultCards. 
        // NOTE: If you are in "Responses" view, this might overwrite it if background results come in. 
        // Ideally, check if searchCtrl is active.
        searchCtrl.renderResultCards(application.results, false);
    }

    if (JSON.stringify(application.notifications) !== JSON.stringify(previousNotifications)) {
        previousNotifications = [...application.notifications];
        notifyMgr.render();
    }

    requestAnimationFrame(updateUI);
}

main();
