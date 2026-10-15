const addUserForm = document.getElementById('addUserForm');
const routeMapButton = document.getElementById('routeMapButton');
const logarea = document.getElementById('logarea');
const scrollbar = document.querySelector('.scrollbar');
const thumb = document.querySelector('.thumb');


function deleteUser(email) {
    if (!confirm('Are you sure you want to delete this user?')) {
        return;
    }

    fetch('/deleteuser', {
        method: 'POST', // Change to POST to match the handler
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded' // Use form-urlencoded to match FormValue
        },
        body: 'email=' + encodeURIComponent(email) // Encode the email in the body
    })
        .then(response => {
            if (response.ok) {
                return response.text(); // Expecting plain text response
            }
            throw new Error('Network response was not ok.');
        })
        .then(data => {
            document.getElementById('userResults').innerHTML = '<div class="notification is-success">User deleted successfully</div>';
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation', error);
            document.getElementById('userResults').innerHTML = '<div class="notification is-danger is-dark">There was a problem deleting the user</div>';
        });
}

function deleteResponse(id) {
    if (!confirm('Are you sure you want to delete this response?')) {
        return;
    }

    fetch('/deleteresponse', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ archived: archived, id: id })
    }).then(response => {
        if (response.ok) {
            return response.text();
        }
        throw new Error('Network response was not ok.');
    })
        .then(data => {
            alert('Response deleted successfully. Please refresh the page to see the changes.');
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation', error);
            alert('There was a problem deleting the response.');
        });
}

/**
 * Generates a new API key for a user and displays it in a custom modal.
 * @param {string} email - The email of the user to generate a key for.
 */
function generateNewKey(email) {
    const endpoint = '/generatekey';
    const resultsDiv = document.getElementById('userResults');

    if (resultsDiv) {
        resultsDiv.innerHTML = '';
    }

    fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: email })
    })
        .then(response => {
            if (response.ok) {
                return response.json();
            }
            return response.text().then(text => {
                throw new Error(`Server error: ${text}`);
            });
        })
        .then(user => {
            // Successfully got the user object
            if (user && user.key) {

                if (resultsDiv) {
                    resultsDiv.innerHTML = `
                    <div class="notification is-success">
                        <strong style="display: block; margin-bottom: 8px;">New API Key Generated</strong>
                        <p style="margin-bottom: 12px;">Click the key below to select it, then press Ctrl+C or Cmd+C to copy. You will not be able to see this key again.</p>
                        <input type="text" class="input" 
                               value="${user.key}" 
                               readonly 
                               onclick="this.select();" 
                               style="width: 100%; cursor: pointer;">
                    </div>
                `;
                } else {
                    console.error("Could not find 'userResults' div to display API key.");
                    prompt("New API Key. Press Ctrl+C to copy:", user.key);
                }


            } else {
                throw new Error('Invalid user data received from server.');
            }
        })
        .catch(error => {
            console.error('There was a problem with the generate key operation:', error);
            if (resultsDiv) {
                resultsDiv.innerHTML = `<div class="notification is-danger is-dark">Error generating key: ${error.message}</div>`;
            }
        });
}

function thislogout() {
    fetch('/logout', {
        method: 'GET'
    })
        .then(response => {
            if (response.ok) {
                window.location.href = '/splash';
            }
            throw new Error('Network response was not ok.');
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation', error);
        });
}
function killServer() {
    fetch('/assisteddeath', {
        method: 'GET'
    })
        .then(response => {
            if (response.ok) {
                window.location.href = '/splash';
            }
            throw new Error('Network response was not ok.');
        })
        .catch(error => {

            console.error('There was a problem with the fetch operation', error);
        });
}

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatLogTimestamp(timeVal) {
    if (!timeVal) return '';
    try {
        const d = new Date(timeVal);
        if (isNaN(d.getTime())) return timeVal;
        const pad = (n, len = 2) => String(n).padStart(len, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
    } catch {
        return timeVal;
    }
}

function logToArticle(log) {
    if (!log || !log.data) {
        return '';
    }
    const level = log.error ? 'ERROR' : 'INFO';
    const levelClass = log.error ? 'log-badge-error' : 'log-badge-info';
    const rowClass = log.error ? 'log-row-error' : 'log-row-info';
    const timeFormatted = formatLogTimestamp(log.time);
    const dataEscaped = escapeHtml(log.data);

    return `<div class="log-row ${rowClass}" data-level="${level}"><span class="log-col-time">${timeFormatted}</span><span class="log-col-level"><span class="log-badge ${levelClass}">${level}</span></span><span class="log-col-data">${dataEscaped}</span></div>`;
}

let isFetchingLogs = false;
let autoScrollEnabled = true;

// Fetch additional logs on infinite scroll
function getLogs(start, end) {
    if (isFetchingLogs) return;
    isFetchingLogs = true;

    fetch('/logs?start=' + start + '&end=' + end, {
        method: 'GET'
    })
        .then(response => {
            if (response.ok) {
                return response.text();
            }
            throw new Error('Network response was not ok.');
        })
        .then(data => {
            let logs = JSON.parse(data);
            if (!logs || logs.length === 0) {
                return;
            }
            const logContainer = document.getElementById('logarea');
            if (logContainer) {
                let htmlChunk = '';
                for (let i = 0; i < logs.length; i++) {
                    htmlChunk += logToArticle(logs[i]);
                }
                logContainer.insertAdjacentHTML('beforeend', htmlChunk);
                applyLogFilters();
                updateLogCount();
                if (autoScrollEnabled) {
                    logContainer.scrollTop = logContainer.scrollHeight;
                }
            }
            startIndex += itemsPerPage;
        })
        .catch(error => {
            console.error('There was a problem fetching logs:', error);
        })
        .finally(() => {
            isFetchingLogs = false;
        });
}

function updateLogCount() {
    const logContainer = document.getElementById('logarea');
    const display = document.getElementById('logCountDisplay');
    if (!logContainer || !display) return;
    const total = logContainer.querySelectorAll('.log-row').length;
    const visible = logContainer.querySelectorAll('.log-row:not([style*="display: none"])').length;
    if (total === visible) {
        display.textContent = `${total} lines`;
    } else {
        display.textContent = `${visible} of ${total} lines shown`;
    }
}

function applyLogFilters() {
    const logContainer = document.getElementById('logarea');
    if (!logContainer) return;

    const searchInput = document.getElementById('logSearchInput');
    const errorsOnly = document.getElementById('filterErrorsBtn')?.classList.contains('is-selected');
    const query = (searchInput?.value || '').trim().toLowerCase();

    const rows = logContainer.querySelectorAll('.log-row');
    rows.forEach(row => {
        const level = row.getAttribute('data-level') || 'INFO';
        const matchesLevel = !errorsOnly || level === 'ERROR';
        const text = row.textContent.toLowerCase();
        const matchesText = !query || text.includes(query);

        if (matchesLevel && matchesText) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });

    updateLogCount();
}

function setupLogViewerControls() {
    const logContainer = document.getElementById('logarea');
    if (!logContainer) return;

    const searchInput = document.getElementById('logSearchInput');
    const filterAllBtn = document.getElementById('filterAllBtn');
    const filterErrorsBtn = document.getElementById('filterErrorsBtn');
    const copyBtn = document.getElementById('copyLogsBtn');
    const autoScrollBtn = document.getElementById('autoScrollToggle');

    if (searchInput) {
        searchInput.addEventListener('input', applyLogFilters);
    }

    if (filterAllBtn && filterErrorsBtn) {
        filterAllBtn.addEventListener('click', () => {
            filterAllBtn.className = 'button is-small is-primary is-selected';
            filterErrorsBtn.className = 'button is-small is-dark';
            applyLogFilters();
        });

        filterErrorsBtn.addEventListener('click', () => {
            filterErrorsBtn.className = 'button is-small is-danger is-selected';
            filterAllBtn.className = 'button is-small is-dark';
            applyLogFilters();
        });
    }

    if (autoScrollBtn) {
        autoScrollBtn.addEventListener('click', () => {
            autoScrollEnabled = !autoScrollEnabled;
            if (autoScrollEnabled) {
                autoScrollBtn.classList.add('is-active');
                autoScrollBtn.textContent = 'Auto-Scroll: ON';
                logContainer.scrollTop = logContainer.scrollHeight;
            } else {
                autoScrollBtn.classList.remove('is-active');
                autoScrollBtn.textContent = 'Auto-Scroll: OFF';
            }
        });
    }

    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const rows = logContainer.querySelectorAll('.log-row:not([style*="display: none"])');
            const lines = Array.from(rows).map(r => r.textContent.trim()).join('\n');
            navigator.clipboard.writeText(lines).then(() => {
                const prev = copyBtn.textContent;
                copyBtn.textContent = 'Copied!';
                setTimeout(() => { copyBtn.textContent = prev; }, 1500);
            }).catch(err => {
                console.error('Clipboard copy failed:', err);
            });
        });
    }

    // Handle initial HTMX load or reload
    logContainer.addEventListener('htmx:afterSwap', () => {
        applyLogFilters();
        updateLogCount();
        if (autoScrollEnabled) {
            logContainer.scrollTop = logContainer.scrollHeight;
        }
    });

    // Infinite scroll
    logContainer.addEventListener('scroll', () => {
        const { scrollTop, scrollHeight, clientHeight } = logContainer;
        if (scrollTop + clientHeight >= scrollHeight - 80) {
            getLogs(startIndex, startIndex + itemsPerPage);
        }
    });

    // Run count update if items already present
    updateLogCount();
}
// Function to open the modal
function openModal(modalID) {
    const modal = document.getElementById(modalID);
    modal.classList.add('is-active'); // Add active class to show modal
}

// Function to close the modal
function closeModal(modalID) {
    const modal = document.getElementById(modalID);
    modal.classList.remove('is-active'); // Remove active class to hide modal
}

// Function to initialize event listeners for modals
function initModals() {
    // Get all buttons that open modals
    const openModalButtons = document.querySelectorAll('.open-modal');

    openModalButtons.forEach(button => {
        button.addEventListener('click', function () {
            const modalID = this.getAttribute('data-modal-id');
            openModal(modalID);
        });
    });

    // Get all close buttons inside modals
    const closeModalButtons = document.querySelectorAll('.close-modal');
    closeModalButtons.forEach(button => {
        button.addEventListener('click', function () {
            const modal = this.closest('.modal');
            closeModal(modal.id);
        });
    });

    // Add event listener for background click to close modal
    const modalBackgrounds = document.querySelectorAll('.modal-background');
    modalBackgrounds.forEach(background => {
        background.addEventListener('click', function () {
            const modal = this.closest('.modal');
            closeModal(modal.id);
        });
    });
}

// Initialize modals on window load
window.onload = () => {
    initModals();
    setupLogViewerControls();

    if (addUserForm) {
        addUserForm.addEventListener('submit', function (event) {
            event.preventDefault();
            const userResults = document.getElementById('userResults');
            const email = document.getElementById('email').value
            const key = document.getElementById('password').value
            const admin = document.getElementById('admin').checked ? "true" : "false";
            const userData = {
                "email": email,
                "password": key,
                "admin": admin
            };
            fetch('/adduser', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(userData),
            })
                .then(response => {
                    if (response.ok) {
                        let x = response.json();
                        return x;
                    }
                    throw new Error('Network response was not ok.');
                })
                .then(data => {
                    // console.log('User added: ', data);
                    if (data.key) {
                        if (!isValid32ByteBase64Key(data.key)) {
                            userResults.innerHTML = '<div class="notification is-danger">User added successfully but key is invalid</div>';
                            return;
                        }
                        userResults.innerHTML = '<div class="notification is-success">User added successfully. Key: ' + data.key + '</div>';
                    }
                    alert('User added! A key will be displayed on the screen, please save it for future reference');
                })
                .catch(error => {
                    console.error('There was a problem with the fetch operation', error);
                });
        });
    }

    if (routeMapButton) {
        routeMapButton.addEventListener('click', function () {
            const typesInput = document.getElementById('typesInput').value;
            const typesArray = typesInput.split(',').map(type => type.trim());
            const routeMap = typesArray.map((type, index) => ({ key: "route" + (index + 1), type: type }));

            const routeMapOutput = document.getElementById('routeMapOutput');
            //   routeMapOutput.innerHTML = '<pre>' + JSON.stringify(routeMap, null, 2) + '</pre>';
            for (let i = 0; i < routeMap.length; i++) {
                let field = '<div class="field">' +
                    '<label class="label has-text-white">' + routeMap[i].type + '</label>' +
                    '<div class="control">' +
                    '<input class="input is-outlined" type="text" name="' + routeMap[i].route + '" placeholder="Enter service kind">' +
                    '</div>' +
                    '</div>';
                routeMapOutput.innerHTML += field;
            }
        });
    }
    const carousel = document.getElementById('navbar-carousel');
    const scrollLeftButton = document.getElementById('scroll-left');
    const scrollRightButton = document.getElementById('scroll-right');

    if (carousel) {
        scrollLeftButton.addEventListener('click', () => {
            carousel.scrollBy({
                left: -200, // Adjust scroll amount as needed
                behavior: 'smooth'
            });
        });

        scrollRightButton.addEventListener('click', () => {
            carousel.scrollBy({
                left: 200, // Adjust scroll amount as needed
                behavior: 'smooth'
            });
        });
    }

};
const dropDownMenu = document.getElementById('dropDownMenu');
const dropDownMenuLink = document.getElementById('dropDownMenuLink');
const itemsPerPage = 50; // Reduce items per page for smoother loading
let startIndex = 50; // server sends 0-50 on load, we want 50-100 next

if (dropDownMenuLink && dropDownMenu) {
    dropDownMenuLink.addEventListener('click', () => {
        dropDownMenu.classList.toggle('is-active');
    });
}

function isValid32ByteBase64Key(key) {
    // Accept 43 (no padding) or 44 (with '=') characters
    if (key.length !== 43 && key.length !== 44) return false;

    // Check valid Base64 characters (standard or URL-safe) and optional padding
    const regex = /^[A-Za-z0-9+/=-]{43,44}$/;
    if (!regex.test(key)) return false;

    // Decode and verify it’s exactly 32 bytes
    try {
        const decoded = atob(key.replace(/-/g, '+').replace(/_/g, '/')); // Handle URL-safe Base64
        return decoded.length === 32;
    } catch (e) {
        return false; // Invalid Base64 string
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.body.addEventListener('click', (e) => {
        // Handle Delete User Button
        const deleteBtn = e.target.closest('.delete-user-btn');
        if (deleteBtn) {
            const email = deleteBtn.getAttribute('data-email');
            deleteUser(email);
            return;
        }

        // Handle Generate New Key Button
        const keyBtn = e.target.closest('.generate-key-btn');
        if (keyBtn) {
            const email = keyBtn.getAttribute('data-email');
            generateNewKey(email);
            return;
        }

        // Handle Logout Button
        if (e.target.closest('.logout-btn') || e.target.closest('#logoutButton')) {
            console.log("Logout button clicked");
            fetch('/logout', { method: 'POST' })
                .then(() => {
                    window.location.href = '/';
                })
                .catch(err => {
                    console.error("Logout failed", err);
                    window.location.href = '/';
                });
        }
    });
});
