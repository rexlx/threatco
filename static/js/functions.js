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
            document.getElementById('userResults').innerHTML = '<div class="notification is-danger">There was a problem deleting the user</div>';
        });
}
function logout() {
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

function logToArticle2(log) {
    if (!log.data || log.data === '') {
        return;
    }
    const newArticle = document.createElement('article');
    const messageHeader = document.createElement('div');
    const messageBody = document.createElement('div');
    if (log.error) {
        newArticle.className = 'message is-danger';
    }
    messageHeader.className = 'message-header';
    messageBody.className = 'message-body';
    messageHeader.innerHTML = log.time;
    newArticle.className = 'message is-info';
    messageBody.innerHTML = log.data;
    newArticle.appendChild(messageHeader);
    return newArticle;
}

function logToArticle(log) {
    if (!log.data || log.data === '') {
        return;
    }
    if (log.error) {
        return `<article class="message is-danger">
                <div class="message-header">
                    <p>${log.time}</p>
                </div>
                <div class="message-body">
                    ${log.data}
                </div>
              </article>`;
    } else {
        return `<article class="message is-info">
                <div class="message-header">
                    <p>${log.time}</p>
                </div>
                <div class="message-body">
                    ${log.data}
                </div>
              </article>`;
    }
}

// TODO Rework this so that it detects empty responses and stops fetching
function getLogs(start, end) {
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
            if (logs.length === 0) {
                return;
            }
            for (let i = 0; i < logs.length; i++) {
                let atc = logToArticle(logs[i]);
                if (atc) {
                    document.getElementById('logarea').innerHTML += atc;
                }
            }
            updateScrollbar();
            startIndex += itemsPerPage;
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation', error);
            // document.getElementById('logarea').innerHTML = '<div class="notification is-danger">There was a problem getting the logs</div>';
        });
}

function updateScrollbar() {
    const scrollTop = logarea.scrollTop;
    const scrollHeight = logarea.scrollHeight - logarea.clientHeight;
    const scrollPercent = scrollTop / scrollHeight;

    const thumbHeight = Math.max(20, logarea.clientHeight * (logarea.clientHeight / logarea.scrollHeight));
    const thumbTop = scrollPercent * (logarea.clientHeight - thumbHeight);
    thumb.style.height = thumbHeight + "px";
    thumb.style.top = thumbTop + "px";
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
    if (logarea) {
        logarea.addEventListener('scroll', () => {
            const { scrollTop, scrollHeight, clientHeight } = logarea;
            const scrollPercent = scrollTop / (scrollHeight - clientHeight);
            const thumbPosition = scrollPercent * (clientHeight - thumb.clientHeight);
            thumb.style.top = thumbPosition + 'px';
            if (scrollPercent > 0.9) {
                getLogs(startIndex, startIndex + itemsPerPage);
            }

        });
    }

    if (addUserForm) {
        addUserForm.addEventListener('submit', function (event) {
            event.preventDefault();
            const userResults = document.getElementById('userResults');
            const email = document.getElementById('email').value
            const key = document.getElementById('password').value
            const admin = document.getElementById('admin').value
            const userData = {
                "email": email,
                "password": key,
                "is_admin": admin
            };
            fetch('/adduser', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': ''
                },
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
                    console.log('User added: ', data);
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
};
const dropDownMenu = document.getElementById('dropDownMenu');
const dropDownMenuLink = document.getElementById('dropDownMenuLink');
const itemsPerPage = 50; // Reduce items per page for smoother loading
let startIndex = 50; // server sends 0-50 on load, we want 50-100 next

dropDownMenuLink.addEventListener('click', () => {
    dropDownMenu.classList.toggle('is-active')
})

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