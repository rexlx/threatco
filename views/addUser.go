package views

import "fmt"

var AddUserView string = fmt.Sprintf(BaseView, AddUserSection)

var AddUserSection string = `
<section class="section has-background-custom" style="height: 100vh;">
    <div class="container mb-3">
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
    <div class="container" id="userResults"></div>
</section>
`
