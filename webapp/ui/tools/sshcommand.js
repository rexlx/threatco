// webapp/ui/tools/sshcommand.js
export class SshCommandTool {
    constructor(app) {
        this.app = app;
        this.commands = [];
    }

    render() {
        return `
        <div id="tool-sshcommand" class="block">
            <h4 class="title is-4 has-text-white">Remote Command Execution</h4>
            <p class="has-text-grey-light mb-4">Execute a sequence of commands across remote targets.</p>
            
            <div class="columns">
                <div class="column is-7">
                    <div class="field">
                        <label class="label has-text-grey-light">Target Host</label>
                        <div class="control">
                            <input class="input" type="text" id="sshExecHost" placeholder="user@address:port (e.g. root@10.0.0.5)">
                            <p class="help has-text-grey">Defaults to root and port 22 if omitted.</p>
                        </div>
                    </div>
                </div>
                <div class="column">
                    <div class="field">
                        <label class="label has-text-grey-light">Auth Method</label>
                        <div class="control">
                            <div class="select is-fullwidth">
                                <select id="sshExecAuthMethod">
                                    <option value="password">Password</option>
                                    <option value="key">Identity File</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="field" id="sshExecPassField">
                <label class="label has-text-grey-light">Password</label>
                <div class="control">
                    <input class="input" type="password" id="sshExecPassword" placeholder="Remote password">
                </div>
            </div>

            <div class="field is-hidden" id="sshExecKeyField">
                <label class="label has-text-grey-light">Private Key (PEM)</label>
                <div class="control">
                    <textarea class="textarea is-small has-background-black has-text-warning" id="sshExecPrivKey" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                </div>
            </div>

            <div class="field mt-5">
                <label class="label has-text-info">Command Queue</label>
                <div class="field has-addons">
                    <div class="control is-expanded">
                        <input class="input" type="text" id="sshExecCmdInput" placeholder="Enter command (e.g. systemctl restart nginx)">
                    </div>
                    <div class="control">
                        <button class="button is-info" id="btnAddExecCmd">
                            <span class="icon"><i class="material-icons">add</i></span>
                        </button>
                    </div>
                </div>
            </div>

            <div id="sshExecCmdList" class="tags mb-4"></div>

            <button class="button is-warning is-fullwidth is-outlined" id="btnRunSshExec">
                <span class="icon"><i class="material-icons">terminal</i></span>
                <span>Run Commands</span>
            </button>

            <div id="sshExecOutputContainer" class="mt-5 is-hidden">
                <label class="label is-small has-text-success">Console Output</label>
                <pre id="sshExecOutput" class="has-background-black has-text-light" style="max-height: 500px; overflow-y: auto; font-family: 'IBMPlexMono-Regular', monospace; font-size: 0.85rem; padding: 15px; border: 1px solid #444; white-space: pre-wrap;"></pre>
            </div>
        </div>`;
    }

    attachListeners() {
        const authMethod = document.getElementById('sshExecAuthMethod');
        const passField = document.getElementById('sshExecPassField');
        const keyField = document.getElementById('sshExecKeyField');
        const addCmdBtn = document.getElementById('btnAddExecCmd');
        const cmdInput = document.getElementById('sshExecCmdInput');
        const runBtn = document.getElementById('btnRunSshExec');

        authMethod.onchange = (e) => {
            const isKey = e.target.value === 'key';
            passField.classList.toggle('is-hidden', isKey);
            keyField.classList.toggle('is-hidden', !isKey);
        };

        addCmdBtn.onclick = () => {
            const cmd = cmdInput.value.trim();
            if (cmd) {
                this.commands.push(cmd);
                this.updateCmdList();
                cmdInput.value = '';
            }
        };

        runBtn.onclick = async () => {
            if (!document.getElementById('sshExecHost').value) return alert("Host is required.");
            if (this.commands.length === 0) return alert("Queue at least one command.");

            runBtn.classList.add('is-loading');
            const outputArea = document.getElementById('sshExecOutput');
            const container = document.getElementById('sshExecOutputContainer');
            
            outputArea.textContent = "Connecting to remote host...\n";
            container.classList.remove('is-hidden');

            const payload = {
                host: document.getElementById('sshExecHost').value,
                method: authMethod.value,
                password: document.getElementById('sshExecPassword').value,
                private_key: document.getElementById('sshExecPrivKey').value,
                commands: this.commands // Sent as array for backend to join
            };

            try {
                const res = await this.app._fetch('/tools/ssh-exec', {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
                
                const data = await res.json();
                outputArea.textContent = data.output || "No output received.";
                if (data.error) outputArea.classList.add('has-text-danger');
                else outputArea.classList.remove('has-text-danger');
                
            } catch (e) {
                outputArea.textContent += `Execution Error: ${e.message}`;
            } finally {
                runBtn.classList.remove('is-loading');
            }
        };
    }

    updateCmdList() {
        const list = document.getElementById('sshExecCmdList');
        list.innerHTML = this.commands.map((c, i) => `
            <span class="tag is-dark">
                <code>${c}</code>
                <button class="delete is-small" onclick="window._removeExecCmd(${i})"></button>
            </span>
        `).join('');

        window._removeExecCmd = (idx) => {
            this.commands.splice(idx, 1);
            this.updateCmdList();
        };
    }
}