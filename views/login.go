package views

var LoginView string = `<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>login</title>
  <link rel="stylesheet" href="/static/bulma.min.css">
  <style>
    body {
      background-color: #0b141c;
    }

    .animate-spin {
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      from {
        transform: rotate(0deg);
      }

      to {
        transform: rotate(360deg);

      }
    }
  </style>
</head>

<body>
 <section class="section has-background-black-ter" style="height: 100vh;">
  <div class="container">
    <div class="columns is-centered">
      <div class="column">
        <div class="box has-background-black-ter">
          <h2 class="title is-2 has-text-primary">login</h2>
          <form action="/login" method="post" class="has-background-black-ter">

            <div class="field">
              <label class="label has-text-white">username</label>
              <div class="control">
                <input class="input is-outlined" type="text" name="username" placeholder="Enter your usernamess">
              </div>
            </div>
          
            <div class="field">
              <label class="label has-text-white">password</label>
              <div class="control">
                <input class="input is-outlined" type="password" name="password" placeholder="Enter your passwords">
              </div>
            </div>
            <div>
              <button class="button is-primary is-outlined" type="submit">login</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
  </section>
</body>

</html>`
