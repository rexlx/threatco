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

  <div class="container">
    <div class="columns is-centered">
      <div class="column is-half">
        <div class="box has-background-black">
          <h2 class="title is-2 has-text-primary">login</h2>
          <form action="/login" method="post" class="has-background-black">

            <div class="field">
              <label class="label has-text-white">username</label>
              <div class="control">
                <input class="input is-outlined" type="text" name="username" placeholder="Enter your username">
              </div>
            </div>
          
            <div class="field">
              <label class="label has-text-white">password</label>
              <div class="control">
                <input class="input is-outlined" type="password" name="password" placeholder="Enter your password">
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

</body>

</html>`