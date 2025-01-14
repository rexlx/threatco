const addUserForm = document.getElementById('addUserForm');
const routeMapButton = document.getElementById('routeMapButton');
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
            console.log('User deleted: ', data);
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

function logToArticle(log) {
    console.log(log);
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

function getLogs(start, end) {
    // let mylogs = [];
    fetch('/logs', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'start=' + start + '&end=' + end
    })
        .then(response => {
            if (response.ok) {
                return response.text();
            }
            throw new Error('Network response was not ok.');
        })
        .then(data => {
            let logs = JSON.parse(data);
            for (let i = 0; i < logs.length; i++) {
                console.log(logs[i]);
                document.getElementById('logarea').appendChild(logToArticle(logs[i]));
            }
        })
        .catch(error => {
            console.error('There was a problem with the fetch operation', error);
            document.getElementById('logarea').innerHTML = '<div class="notification is-danger">There was a problem getting the logs</div>';
        });
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
};
const dropDownMenu = document.getElementById('dropDownMenu');
const dropDownMenuLink = document.getElementById('dropDownMenuLink');

dropDownMenuLink.addEventListener('click', () => {
    console.log('hello')
    dropDownMenu.classList.toggle('is-active')
})

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
                    console.log(x);
                    return x;
                }
                throw new Error('Network response was not ok.');
            })
            .then(data => {
                console.log('User added: ', data);
                if (data.key) {
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