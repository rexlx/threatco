// webapp/ui/profile.js
export class ProfileController {
    constructor(viewId, app) {
        this.view = document.getElementById(viewId);
        this.app = app;
    }

    render() {
        this.view.classList.remove('is-hidden');
        
        const email = this.app.user.email || '';

        const html = `
            <div class="block">
                <h1 class="title has-text-info">Profile & Settings</h1>
            </div>
            <div class="box has-background-custom" id="profileBox">
                <form>
                    <div class="field">
                        <label class="label">Email</label>
                        <div class="control">
                            <input class="input" type="text" id="editUserEmail" value="${email}" readonly>
                        </div>
                    </div>
                    <div class="field mt-5">
                        <div class="control profileButtons">
                            <button class="button is-info is-outlined" id="updateUserButton" type="button">
                                <span class="icon-text">
                                    <span class="icon"><i class="material-icons">save</i></span>
                                    <span>Update</span>
                                </span>
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        `;

        this.view.innerHTML = html;
        this.initListeners();
    }

    initListeners() {
        const updateBtn = document.getElementById("updateUserButton");
        if (updateBtn) {
            updateBtn.addEventListener("click", async () => {
                await this.app.fetchUser();
                alert('User profile re-synced!');
            });
        }
    }
}