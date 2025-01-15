package views

var BaseView string = `<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="/static/bulma.min.css">
    <link rel="stylesheet" href="/static/s.css">
    <script src="/static/htmx.min.js"></script>
</head>

<body>
    <nav class="navbar has-background-black-ter" role="navigation" aria-label="dropdown navigation">
        <div class="navbar-menu">
            <div class="navbar-start">

                <div class="navbar-item has-dropdown" id="dropDownMenu">
                    <a class="navbar-link has-text-primary" id="dropDownMenuLink">
                        threatco
                    </a>

                    <div class="navbar-dropdown has-background-black-ter">
                        <a class="navbar-item has-background-black-ter has-text-primary" href="/services">
                            services
                        </a>

                        <a class="navbar-item has-background-black-ter has-text-primary" href="/create-user">
                            add user
                        </a>

                        <a class="navbar-item has-background-black-ter has-text-primary" href="/users">
                            users
                        </a>
                        <a class="navbar-item has-background-black-ter has-text-primary" href="/view-logs">
                            logs
                        </a>
                        <a class="navbar-item has-background-black-ter has-text-primary" href="/charts">
                            stats
                        </a>

                    </div>
                </div>
            </div>
            <div class="navbar-end">
                <div class="navbar-item">
                    <button class="button is-warning is-outlined" onclick="logout()">logout</button>
                    <button class="button is-warning is-outlined" onclick="killServer()">kill server</button>
                </div>
            </div>
        </div>
    </nav>
    %v
</body>
<script src="/static/js/functions.js"></script>

</html>
`
