package views

var AddUserView string = `<!DOCTYPE html>
    <html lang="en"> 
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="stylesheet" href="./static/bulma.min.css">
            <link rel="stylesheet" href="./static/custom.css">
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
                    <a href="./index.html" class="navbar-item has-background-black-ter has-text-primary">
                        Add User
                      </a>
                      
                      <a href="./table.html" class="navbar-item has-background-black-ter has-text-primary">
                        Chat
                      </a>
                       <!-- Services Page-->
                      <a class="navbar-item has-background-black-ter has-text-primary">
                        Components
                      </a>
                    
                  </div>
                </div>
              </div>
              <!-- <div class="navbar-end">
                <image src="./assets/greenfist2.jpg"></image>
              </div> -->
            </div>
          </nav>
         
            <section class="section has-background-black-ter" style="height: 100vh;">
                <div class="container">
                    <h1 class="title has-text-primary">Add User</h1>
                    <form class="box has-background-black-ter" id="addUserForm">
                        <div class="field">
                            <label class="label  has-text-primary" for="email">email:</label>
                            <div class="control">
                                <input class = "input" type="email" id="email" name="email" required/>
                            </div>
                        </div>
            
                        <div class="field">
                            <label class="label  has-text-primary" for="key">password:</label>
                            <div class="control">
                                <input class="input" type="password" id="password" name="password" required/>
                            </div>
                        </div>
            
                        <div class="field">
                            <label class="label  has-text-primary" for="admin">admin:</label>
                            <div class="control">
                                <input type="checkbox" id="admin" name="admin" />
                            </div>
                        </div>
            
                        <div class="field">
                            <div class="control">
                                <button class="button is-primary" type="sumbit">add</button>
                            </div>
                        </div>
                    </form>
                </div>
            </section>
        </body>
        <script type="module" src="./static/js/functions.js"></script>
    </html>


<script>
const dropDownMenu = document.getElementById('dropDownMenu');
const dropDownMenuLink = document.getElementById('dropDownMenuLink');

dropDownMenuLink.addEventListener('click',()=>{
    console.log('hello')
    dropDownMenu.classList.toggle('is-active')
})

</script>
`
