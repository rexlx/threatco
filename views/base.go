package views

var BaseView string = `<!DOCTYPE html>
<html lang="en" data-theme="dark">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>threatco</title>
    <link rel="stylesheet" href="/static/bulma.min.css">
    <link rel="stylesheet" href="/static/s.css">
    <script src="/static/htmx.min.js"></script>
    <script src="/static/echarts.min.js"></script>
    <script src="/static/js/functions.js"></script>
</head>

<body>
    <div class="site-wrapper">
        <nav class="navbar has-background-custom" role="navigation" aria-label="main navigation">
            <div class="navbar-brand">
                <a class="navbar-item has-text-primary" href="#">
                    <strong>threatco</strong>
                </a>
            </div>
            <div class="navbar-menu is-active">
                <div class="navbar-start">
                    <div class="carousel-container">
                        <button class="scroll-button left" id="scroll-left">‹</button>
                        <div class="navbar-carousel" id="navbar-carousel">
                            <a class="navbar-item has-background-custom has-text-primary" href="/app">app</a>
                            <a class="navbar-item has-background-custom has-text-primary" href="/kb">documentation</a>
                            <a class="navbar-item has-background-custom has-text-primary" href="/services">services</a>
                            <a class="navbar-item has-background-custom has-text-primary" href="/create-user">add user</a>
                            <a class="navbar-item has-background-custom has-text-primary" href="/users">users</a>
                            <a class="navbar-item has-background-custom has-text-primary" href="/view-logs">logs</a>
                            <a class="navbar-item has-background-custom has-text-primary" href="/charts">stats</a>
                        </div>
                        <button class="scroll-button right" id="scroll-right">›</button>
                    </div>
                </div>
                <div class="navbar-end">
                    <div class="navbar-item">
                        <button class="button is-warning is-outlined logout-btn">
                            log out
                        </button>
                    </div>
                </div>
            </div>
        </nav>

        <main class="main-content">
            %v
        </main>

        <footer class="footer has-background-custom has-text-primary">
            <div class="content has-text-centered">
                <p>
                    <strong>threatco</strong> for <a href="#" class="has-text-info">nullferatu</a>.
                </p>
                <p>
                    &copy; 2025 nullferatu. All Rights Reserved.
                </p>
            </div>
        </footer>
    </div>

    <script src="/static/js/functions.js"></script>
</body>

</html>
`
