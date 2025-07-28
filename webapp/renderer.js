import { Application } from "./app.js";
import { Contextualizer } from "./parser.js";

// --- Global State & App Initialization ---
let application = new Application();
let contextualizer = new Contextualizer();

// --- DOM Element Selectors ---
const allViews = document.querySelectorAll('body > .section');
const matchBox = document.getElementById("matchBox");
const mainSection = document.getElementById("mainSection");
const profileView = document.getElementById("profileView");
const updateUserButton = document.getElementById("updateUserButton");
const serviceView = document.getElementById("servicesView");
const errorBox = document.getElementById("errors");
const editUserEmail = document.getElementById("editUserEmail");
const backButtonServices = document.getElementById("backButtonServices");
const backButtonProfile = document.getElementById("backButtonProfile");
const rectifyServicesButton = document.getElementById("rectifyServicesButton");
const notificationContainer = document.getElementById("notificationContainer");
const healthStatusContainer = document.getElementById("healthStatusContainer");

const sidebarSearch = document.getElementById("sidebarSearch");
const sidebarRecentActivity = document.getElementById("sidebarRecentActivity");
const sidebarServices = document.getElementById("sidebarServices");
const sidebarProfile = document.getElementById("sidebarProfile");
const sidebarHealth = document.getElementById("sidebarHealth");
const sidebarLinks = [sidebarSearch, sidebarRecentActivity, sidebarServices, sidebarProfile, sidebarHealth];

// --- Modal Elements ---
const detailsModal = document.getElementById('detailsModal');
const detailsModalTitle = document.getElementById('detailsModalTitle');
const detailsModalContent = document.getElementById('detailsModalContent');

/**
 * Main function to start the application.
 */
async function main() {
    await application.init();
    if (application.initialized) {
        renderSearchForm();
        attachEventListeners();
        requestAnimationFrame(updateUI);
    } else {
        errorBox.innerHTML = `<p class="has-text-danger">Could not initialize application. Your session may have expired. Please try refreshing the page.</p>`;
    }
}

// --- View Management ---

function showView(viewToShow) {
    allViews.forEach(view => {
        if (view.id !== 'errata') view.style.display = 'none';
    });
    if (viewToShow) {
        viewToShow.style.display = 'block';
    }
}

function setActiveSidebar(activeLink) {
    sidebarLinks.forEach(link => link && link.classList.remove('is-active'));
    if (activeLink) {
        activeLink.closest('a').classList.add('is-active');
    }
}

function showDetailsModal(title, details) {
    detailsModalTitle.textContent = title;
    detailsModalContent.textContent = JSON.stringify(details, null, 2);
    detailsModal.classList.add('is-active');
}

// --- Event Listeners ---

function attachEventListeners() {
    // Modal close listeners
    detailsModal.querySelector('.modal-background').addEventListener('click', () => detailsModal.classList.remove('is-active'));
    detailsModal.querySelector('.delete').addEventListener('click', () => detailsModal.classList.remove('is-active'));

    // Profile view
    updateUserButton.addEventListener("click", async () => {
        // This function can be expanded if you allow users to update their profile.
        // For now, it just re-fetches the user data.
        await application.fetchUser();
        alert('User profile re-synced!');
    });

    // Main search box actions
    matchBox.addEventListener('click', async (event) => {
        const button = event.target.closest('button');
        if (!button) return;
        event.preventDefault();
        const targetId = button.id;

        if (targetId === 'searchButton') {
            application.results = [];
            application.errors = [];
            const userSearch = document.getElementById('userSearch');
            if (!userSearch) return;
            const searchText = userSearch.value;
            notificationContainer.innerHTML = '';
            matchBox.innerHTML = "<p>Parsing text... searching...</p><progress class='progress is-primary'></progress>";

            const allMatches = Object.keys(contextualizer.expressions).map(key => ({ type: key, matches: [...new Set(contextualizer.getMatches(searchText, contextualizer.expressions[key]))] }));
            for (let svr of application.user.services) {
                for (let matchPair of allMatches) {
                    if (svr.type.includes(matchPair.type)) {
                        const route = getRouteByType(svr.route_map, matchPair.type);
                        handleMatches(svr.kind, matchPair, route);
                    }
                }
            }
        } else if (targetId === 'historyButton') {
            renderResultCards(application.resultHistory, true);
        } else if (targetId === 'goToButton') {
            matchBox.innerHTML = `<div class="field"><label class="label has-text-info">Enter ID</label><div class="control"><input class="input" type="text" placeholder="ID" id="goToValue"></div><div class="control"><button class="button is-primary mt-2" id="goButton">Go</button></div></div>`;
        } else if (targetId === 'goButton') {
            const id = document.getElementById("goToValue").value;
            await application.fetchDetails(id);
            showDetailsModal(`Details for ${id}`, application.focus);
        } else if (targetId === 'uploadButton') {
            const fileInput = document.createElement("input");
            fileInput.type = "file";
            fileInput.addEventListener("change", async () => {
                if (!fileInput.files[0]) return;
                const file = new File([fileInput.files[0]], makeUnique(fileInput.files[0].name), { type: fileInput.files[0].type });
                await application.uploadFile(file);
            });
            fileInput.click();
        } else if (targetId === 'applyResponseFilters') {
            const vendor = document.getElementById('filterVendor').value;
            const start = document.getElementById('filterStart').value;
            const limit = document.getElementById('filterLimit').value;
            const options = {};
            if (vendor) options.vendor = vendor;
            if (start) options.start = parseInt(start, 10);
            if (limit) options.limit = parseInt(limit, 10);
            handleResponseFetch(options);
        }
    });

    // Back buttons
    backButtonServices.addEventListener('click', () => { showView(mainSection); renderSearchForm(); });
    backButtonProfile.addEventListener('click', () => { showView(mainSection); renderSearchForm(); });

    // Rectify services
    rectifyServicesButton.addEventListener('click', async () => {
        await application.rectifyServices();
        await navigateToServices();
    });

    // Sidebar navigation
    sidebarSearch.addEventListener('click', (e) => { setActiveSidebar(e.target); showView(mainSection); renderSearchForm(); });
    sidebarRecentActivity.addEventListener('click', (e) => {
        setActiveSidebar(e.target);
        showView(mainSection);
        if (healthStatusContainer) healthStatusContainer.style.display = 'none';
        if (notificationContainer) notificationContainer.innerHTML = '';
        if (matchBox) {
            matchBox.style.display = 'block';
            matchBox.innerHTML = renderResponseFilters();
        }
        handleResponseFetch();
    });
    sidebarServices.addEventListener('click', (e) => { setActiveSidebar(e.target); navigateToServices(); });
    sidebarProfile.addEventListener('click', (e) => { setActiveSidebar(e.target); navigateToProfile(); });
    sidebarHealth.addEventListener('click', async (e) => {
        setActiveSidebar(e.target);
        showView(mainSection);
        if (matchBox) matchBox.style.display = 'none';
        notificationContainer.innerHTML = '';
        healthStatusContainer.innerHTML = '<p class="has-text-info">Checking health...</p><progress class="progress is-small is-primary" max="100"></progress>';
        healthStatusContainer.style.display = 'block';
        const stats = await application.getServerStats();
        if (stats) renderHealthStatus(stats);
        else healthStatusContainer.innerHTML = '<p class="has-text-danger">Could not retrieve health stats.</p>';
    });
}

// --- Navigation & View Rendering ---

const navigateToServices = async () => {
    await application.getServices();
    showView(serviceView);
    const cardList = document.getElementById('cardList');
    cardList.innerHTML = '';
    application.servers.forEach(data => {
        data.checked = application.user.services?.some(s => s.kind === data.kind) || false;
        cardList.appendChild(createServiceCard(data));
    });
};

const navigateToProfile = () => {
    editUserEmail.value = application.user.email || 'Could not load email.';
    showView(profileView);
};

function renderSearchForm() {
    healthStatusContainer.style.display = 'none';
    if (notificationContainer) {
        notificationContainer.innerHTML = '';
        notificationContainer.classList.remove('is-sticky-top');
    }
    if (matchBox) {
        matchBox.style.display = 'block';
        matchBox.innerHTML = `
            <h1 class="title has-text-info">Search</h1>
            <form>
                <div class="field"><div class="control"><textarea class="textarea" placeholder="feed me..." id="userSearch"></textarea></div></div>
                <div class="field"><div class="control"><button class="button is-info is-outlined" id="searchButton" type="submit"><span class="icon-text"><span class="icon"><i class="material-icons">search</i></span><span>Search</span></span></button></div></div>
                <div class="field"><div class="control"><div class="buttons are-small">
                    <button type="button" class="button is-black has-text-info-light" id="historyButton"><span class="icon-text"><span class="icon"><i class="material-icons">history</i></span><span>history</span></span></button>
                    <button type="button" class="button is-black has-text-info-light" id="goToButton"><span class="icon-text"><span class="icon"><i class="material-icons">double_arrow</i></span><span>go to</span></span></button>
                    <button type="button" class="button is-black has-text-info-light" id="uploadButton"><span class="icon-text"><span class="icon"><i class="material-icons">upload_file</i></span><span>upload</span></span></button>
                </div></div></div>
            </form>`;
    }
}

async function handleResponseFetch(options = {}) {
    const container = document.getElementById('responseTableContainer');
    if (!container) return;
    container.innerHTML = '<p class="has-text-info">Fetching...</p><progress class="progress is-small is-info" max="100"></progress>';
    const cacheHtml = await application.fetchResponseCache(options);
    container.innerHTML = cacheHtml;

    container.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', async (event) => {
            event.preventDefault();
            const id = new URL(link.href).pathname.split('/').pop();
            if (id) {
                await application.fetchDetails(id);
                showDetailsModal(`Details for ${id}`, application.focus);
            }
        });
    });
}

// --- UI Component Rendering ---
// (These functions are copied from your original renderer and adapted for the web)

function renderResultCards(resultsArray, isHistoryView = false) {
    if (healthStatusContainer) healthStatusContainer.style.display = 'none';
    matchBox.style.display = 'block';
    matchBox.innerHTML = "";
    if (resultsArray.length === 0) {
        matchBox.innerHTML = `<p class="has-text-info">${isHistoryView ? 'History is empty.' : 'No results found.'}</p>`;
        return;
    }

    resultsArray.sort((a, b) => (b.matched || 0) - (a.matched || 0));

    for (const result of resultsArray) {
        const article = document.createElement('article');
        article.className = 'message is-dark';
        const header = document.createElement('div');
        header.className = 'message-header';
        if (typeof result.background === 'string') header.classList.add(escapeHtml(result.background));
        header.innerHTML = `<p>${escapeHtml(result.from)}</p>`;
        
        const body = document.createElement('div');
        body.className = 'message-body has-background-dark-ter';
        body.innerHTML = `
            <p class="has-text-white">Match: <span class="has-text-white">${escapeHtml(String(result.value))}</span></p>
            <p class="has-text-white">ID: <span class="has-text-white">${escapeHtml(String(result.id))}</span></p>
            <p class="has-text-white">Server ID: <span class="has-text-white">${escapeHtml(String(result.link))}</span></p>
            <p class="has-text-white">Info: <span class="has-text-white">${escapeHtml(String(result.info))}</span></p>
        `;

        const footer = document.createElement('footer');
        footer.className = 'card-footer';
        const historyButton = document.createElement('a');
        historyButton.href = '#';
        historyButton.className = 'card-footer-item has-background-black has-text-info';
        historyButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">history</i></span><span>Past Searches</span></span>`;
        historyButton.addEventListener('click', async (e) => {
            e.preventDefault();
            const pastSearches = await application.fetchPastSearches(result.value);
            displayPastSearchesNotification(pastSearches, result.value);
        });

        const viewButton = document.createElement('a');
        viewButton.href = '#';
        viewButton.className = 'card-footer-item has-background-black has-text-info';
        viewButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">visibility</i></span><span>View Details</span></span>`;
        if (!result.link || result.link === "none") viewButton.classList.add('is-disabled');
        
        viewButton.addEventListener('click', async (e) => {
            e.preventDefault();
            if (!result.link || result.link === "none") return;
            await application.fetchDetails(result.link);
            showDetailsModal(`Details for ${result.link}`, application.focus);
        });

        footer.appendChild(historyButton);
        footer.appendChild(viewButton);
        article.appendChild(header);
        article.appendChild(body);
        article.appendChild(footer);
        matchBox.appendChild(article);
    }

    const footerContainer = document.createElement('footer');
    footerContainer.className = 'card-footer mt-4';
    const downloadButton = document.createElement('a');
    downloadButton.href = '#';
    downloadButton.className = 'card-footer-item has-background-primary has-text-black';
    downloadButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">download</i></span><span>Download CSV</span></span>`;
    downloadButton.addEventListener("click", (e) => { e.preventDefault(); application.saveResultsToCSV(isHistoryView); });
    
    const clearButton = document.createElement('a');
    clearButton.href = '#';
    clearButton.className = 'card-footer-item has-background-danger has-text-white';
    clearButton.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">delete_sweep</i></span><span>${isHistoryView ? 'Clear History' : 'Clear Results'}</span></span>`;
    clearButton.addEventListener('click', (e) => {
        e.preventDefault();
        if (isHistoryView) {
            application.resultHistory = [];
            application.setHistory();
        }
        application.results = [];
        renderSearchForm();
    });

    footerContainer.appendChild(downloadButton);
    footerContainer.appendChild(clearButton);
    matchBox.appendChild(footerContainer);
}

let previousResults = [];
function updateUI() {
    errorBox.innerHTML = '';
    if (application.errors.length > 0) {
        [...new Set(application.errors)].forEach(error => {
            errorBox.innerHTML += `<p class="has-text-warning">${error}</p>`;
        });
    }
    if (application.resultWorkers.length > 0) {
        errorBox.innerHTML += `<p class="has-text-info">Jobs remaining: ${application.resultWorkers.length}</p>`;
    }
    if (errorBox.innerHTML === '') {
        errorBox.innerHTML = '<p class="has-text-success">System nominal</p>';
    }

    if (JSON.stringify(application.results) !== JSON.stringify(previousResults)) {
        previousResults = [...application.results];
        renderResultCards(application.results, false);
    }
    requestAnimationFrame(updateUI);
}

// --- Helper Functions ---
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function makeUnique(filename) {
    const parts = filename.split(".");
    if (parts.length === 1) return `${parts[0]}_${Date.now()}`;
    const ext = parts.pop();
    const name = parts.join(".");
    return `${name}_${Date.now()}.${ext}`;
}

function getRouteByType(routeMap, type) {
    if (!routeMap) return "";
    const route = routeMap.find(r => r.type === type);
    return route ? route.route : "";
}

async function handleMatches(kind, matchPair, route) {
    application.resultWorkers.push(1);
    for (let match of matchPair.matches) {
        if (isPrivateIP(match)) continue;
        try {
            let result = await application.fetchMatch(kind, match, matchPair.type, route);
            application.results.push(result);
        } catch (error) {
            application.errors.push(error.toString());
        }
    }
    await application.setHistory();
    application.resultWorkers.pop();
}

function isPrivateIP(ip) {
    if (typeof ip !== 'string') return false;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return false;
    const [p1, p2] = parts;
    if (p1 === 10) return true;
    if (p1 === 172 && (p2 >= 16 && p2 <= 31)) return true;
    if (p1 === 192 && p2 === 168) return true;
    if (p1 === 127) return true;
    if (p1 === 169 && p2 === 254) return true;
    return false;
}

function createServiceCard(service) {
    const column = document.createElement('div');
    column.className = 'column is-one-third-desktop is-half-tablet';
    const card = document.createElement('div');
    card.className = 'card has-background-dark is-flex is-flex-direction-column';
    card.style.height = '100%';
    const header = document.createElement('header');
    header.className = 'card-header';
    const title = document.createElement('p');
    title.className = 'card-header-title has-text-white';
    title.textContent = escapeHtml(service.kind);
    header.appendChild(title);
    const contentDiv = document.createElement('div');
    contentDiv.className = 'card-content has-background-black';
    contentDiv.style.flexGrow = '1';
    const content = document.createElement('div');
    content.className = 'content has-text-link-light';
    content.textContent = Array.isArray(service.type) ? service.type.map(escapeHtml).join(', ') : "Invalid Type";
    contentDiv.appendChild(content);
    const footer = document.createElement('footer');
    footer.className = 'card-footer';
    const addButton = document.createElement('a');
    addButton.href = '#';
    addButton.className = 'card-footer-item has-text-white';
    addButton.textContent = service.checked ? 'Remove' : 'Add';
    addButton.classList.add(service.checked ? 'has-background-warning' : 'has-background-success');
    footer.appendChild(addButton);
    card.appendChild(header);
    card.appendChild(contentDiv);
    card.appendChild(footer);
    addButton.addEventListener('click', (e) => {
        e.preventDefault();
        service.checked = !service.checked;
        if (service.checked) {
            application.addService(service);
            addButton.textContent = 'Remove';
            addButton.classList.replace('has-background-success', 'has-background-warning');
        } else {
            application.removeService(service);
            addButton.textContent = 'Add';
            addButton.classList.replace('has-background-warning', 'has-background-success');
        }
    });
    column.appendChild(card);
    return column;
}

function renderHealthStatus(stats) {
    if (!healthStatusContainer) return;
    healthStatusContainer.innerHTML = '';
    let hasHealthChecks = false;
    const title = document.createElement('h1');
    title.className = 'title has-text-info';
    title.textContent = 'Health Check';
    healthStatusContainer.appendChild(title);
    const table = document.createElement('table');
    table.className = 'table is-fullwidth is-striped has-background-dark';
    table.innerHTML = `<thead class="has-background-black"><tr><th class="has-text-info">Service</th><th class="has-text-info">Status</th></tr></thead>`;
    const tbody = document.createElement('tbody');
    for (const key in stats) {
        if (key.startsWith('health-check-')) {
            hasHealthChecks = true;
            const serviceName = key.replace('health-check-', '');
            const status = stats[key];
            const tr = document.createElement('tr');
            tr.innerHTML = `<td class="has-text-white">${serviceName}</td><td><span class="tag ${status === 1 || status === '1' ? 'is-success' : 'is-danger'}">${status === 1 || status === '1' ? 'UP' : 'DOWN'}</span></td>`;
            tbody.appendChild(tr);
        }
    }
    table.appendChild(tbody);
    if (hasHealthChecks) {
        healthStatusContainer.appendChild(table);
    } else {
        healthStatusContainer.innerHTML += '<p class="has-text-info">No health check information available.</p>';
    }
    healthStatusContainer.style.display = 'block';
}

function renderResponseFilters() {
    return `<h1 class="title has-text-info">Responses</h1>
        <div class="field is-grouped">
            <p class="control is-expanded"><input class="input" type="text" id="filterVendor" placeholder="Vendor"></p>
            <p class="control"><input class="input" type="number" id="filterStart" placeholder="Start (e.g., 0)"></p>
            <p class="control"><input class="input" type="number" id="filterLimit" placeholder="Limit (e.g., 100)"></p>
            <p class="control"><button class="button is-info" id="applyResponseFilters" type="button"><span class="icon-text"><span class="icon"><i class="material-icons">filter_list</i></span><span>Apply</span></span></button></p>
        </div><hr class="has-background-grey-dark"><div id="responseTableContainer"><p class="has-text-info">Fetching initial responses...</p></div>`;
}

function displayPastSearchesNotification(pastSearches, value) {
    if(!notificationContainer) return;
    notificationContainer.innerHTML = '';
    notificationContainer.classList.add('is-sticky-top');
    const sixtySecondsAgo = new Date(Date.now() - 60000);
    const relevantPastSearches = pastSearches.filter(s => new Date(s.timestamp) < sixtySecondsAgo);
    const notification = document.createElement('div');
    notification.innerHTML = `<button class="delete"></button>`;
    notification.querySelector('.delete').onclick = () => { notificationContainer.innerHTML = ''; notificationContainer.classList.remove('is-sticky-top'); };
    const message = document.createElement('p');
    if (relevantPastSearches.length === 0) {
        notification.className = 'notification is-success is-light';
        message.innerHTML = `No relevant past searches found for "<strong>${escapeHtml(value)}</strong>".`;
    } else {
        const uniqueUsers = [...new Set(relevantPastSearches.map(s => s.from).filter(Boolean))];
        notification.className = 'notification is-info is-light';
        message.innerHTML = uniqueUsers.length > 0 ? `${escapeHtml(uniqueUsers.join(', '))}; past searches for "<strong>${escapeHtml(value)}</strong>".` : `Past searches for "<strong>${escapeHtml(value)}</strong>" were found, but with no user information.`;
    }
    notification.appendChild(message);
    notificationContainer.appendChild(notification);
}

// --- Start the App ---
main();
