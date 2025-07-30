package views

import "fmt"

var LoginView string = fmt.Sprintf(BaseView, LoginSection)

var LoginSection string = `
 <section class="section has-background-black" style="height: 100vh;">
  <div class="container">
    <div class="columns is-centered">
      <div class="column">
        <div class="box has-background-custom">
          <h2 class="title is-2 has-text-primary">login</h2>
          <form action="/login" method="post" class="has-background-custom">

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
  </section>`
