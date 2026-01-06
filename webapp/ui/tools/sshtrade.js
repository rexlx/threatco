// webapp/ui/tools/sshtrade.js
export class SshTradeTool {
    constructor(app) {
        this.app = app;
        this.hosts = [];
    }

    render() {
        return `
        <div id="tool-sshtrade" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">SSH Key Trader</h4>
            <p class="has-text-grey-light mb-4">Batch deploy public keys to remote servers using password or key-based authentication.</p>
            
            <div class="field has-addons">
                <div class="control is-expanded">
                    <input class="input" type="text" id="sshHostInput" placeholder="user@host:port (e.g. root@192.168.1.10)">
                </div>
                <div class="control">
                    <button class="button is-info" id="btnAddSshHost">
                        <span class="icon"><i class="material-icons">add</i></span>
                    </button>
                </div>
            </div>

            <div id="sshHostList" class="tags mb-4"></div>

            <div class="columns">
                <div class="column">
                    <div class="field">
                        <label class="label has-text-grey-light">Auth Method</label>
                        <div class="control">
                            <div class="select is-fullwidth">
                                <select id="sshAuthMethod">
                                    <option value="password">Password</option>
                                    <option value="key">Identity File (Private Key)</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="column">
                    <div class="field" id="sshPasswordContainer">
                        <label class="label has-text-grey-light">Login Password</label>
                        <div class="control">
                            <input class="input" type="password" id="sshLoginPassword" placeholder="Remote password">
                        </div>
                    </div>
                </div>
            </div>

            <div class="field is-hidden" id="sshPrivKeyContainer">
                <label class="label has-text-grey-light">Login Private Key</label>
                <div class="control">
                    <textarea class="textarea is-small has-background-black has-text-warning" id="sshLoginPrivKey" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                </div>
            </div>

            <div class="field">
                <label class="label has-text-info">Public Key to Deploy</label>
                <div class="control">
                    <textarea class="textarea is-small has-background-black has-text-success" id="sshDeployPubKey" placeholder="ssh-rsa AAAA... (The key to be added to authorized_keys)"></textarea>
                </div>
            </div>

            <button class="button is-info is-fullwidth is-outlined" id="btnDeploySSH">
                <span class="icon"><i class="material-icons">send</i></span>
                <span>Start Deployment</span>
            </button>
        </div>`;
    }

    attachListeners() {
        const addBtn = document.getElementById('btnAddSshHost');
        const hostInput = document.getElementById('sshHostInput');
        const hostList = document.getElementById('sshHostList');
        const authSelect = document.getElementById('sshAuthMethod');
        const deployBtn = document.getElementById('btnDeploySSH');

        // Host management
        addBtn.onclick = () => {
            const val = hostInput.value.trim();
            if (val && !this.hosts.includes(val)) {
                this.hosts.push(val);
                this.updateHostList();
                hostInput.value = '';
            }
        };

        // Toggle Auth View
        authSelect.onchange = (e) => {
            const isKey = e.target.value === 'key';
            document.getElementById('sshPrivKeyContainer').classList.toggle('is-hidden', !isKey);
            document.getElementById('sshPasswordContainer').classList.toggle('is-hidden', isKey);
        };

        // Deployment
        deployBtn.onclick = async () => {
            if (this.hosts.length === 0) return alert("Add at least one host.");
            
            deployBtn.classList.add('is-loading');
            const payload = {
                hosts: this.hosts,
                method: authSelect.value,
                password: document.getElementById('sshLoginPassword').value,
                private_key: document.getElementById('sshLoginPrivKey').value,
                public_key: document.getElementById('sshDeployPubKey').value
            };

            try {
                const res = await this.app._fetch('/tools/ssh-deploy', {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
                if (!res.ok) throw new Error(await res.text());
                alert("Deployment process started. Check notifications for results.");
            } catch (e) {
                alert("Deployment Error: " + e.message);
            } finally {
                deployBtn.classList.remove('is-loading');
            }
        };
    }

    updateHostList() {
        const hostList = document.getElementById('sshHostList');
        hostList.innerHTML = this.hosts.map(h => `
            <span class="tag is-dark is-medium">
                ${h}
                <button class="delete is-small" onclick="window._removeSshHost('${h}')"></button>
            </span>
        `).join('');

        window._removeSshHost = (host) => {
            this.hosts = this.hosts.filter(h => h !== host);
            this.updateHostList();
        };
    }
}