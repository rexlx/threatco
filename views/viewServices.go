package views

var ViewServicesView string = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="./static/bulma.min.css">
</head>
<body>
    <section class="section has-background-black" id="serviceViewer">
		%v
    </section>
</body>
</html>`