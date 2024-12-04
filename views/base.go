package views

var BaseView string = `
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="./static/bulma.min.css">
</head>

<body>
    <nav class="navbar has-background-black-ter" role="navigation" aria-label="dropdown navigation">
        <div class="navbar-menu">
            <div class="navbar-start">

                <div class="navbar-item has-dropdown" id="dropDownMenu">
                    <a class="navbar-link has-text-primary" id="dropDownMenuLink">
                        ThreatPunch
                    </a>

                    <div class="navbar-dropdown has-background-black-ter">
                        <a class="navbar-item has-background-black-ter has-text-primary" href="/services">
                            Services
                        </a>

                        <a class="navbar-item has-background-black-ter has-text-primary">
                            Elements
                        </a>

                        <a class="navbar-item has-background-black-ter has-text-primary">
                            Components
                        </a>

                    </div>
                </div>
            </div>
        </div>
    </nav>
    %v
</body>
<script>
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
</script>
<style>
    .section {
        height: 100vh;
    }
</style>

</html>
`
