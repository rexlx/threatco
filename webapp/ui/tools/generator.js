export class GeneratorTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-generator" class="block">
            <h4 class="title is-4 has-text-white">Generators</h4>
            <p class="has-text-grey-light mb-4">Create secure identifiers and credentials.</p>

            <div class="box has-background-dark-ter mb-5">
                <div class="level is-mobile mb-2">
                    <div class="level-left">
                        <h5 class="title is-5 has-text-info mb-0">UUID v4</h5>
                    </div>
                    <div class="level-right">
                        <span class="tag is-black" id="uuid-status">Ready</span>
                    </div>
                </div>
                
                <div class="field has-addons">
                    <div class="control is-expanded">
                        <input class="input has-text-centered has-background-black has-text-success" 
                               style="font-family: monospace; font-size: 1.1em;" 
                               type="text" id="uuidOutput" readonly placeholder="Generating...">
                    </div>
                    <div class="control">
                        <button class="button is-dark" id="btnCopyUUID" title="Copy to clipboard">
                            <span class="icon"><i class="material-icons">content_copy</i></span>
                        </button>
                    </div>
                </div>
                <button class="button is-info is-outlined is-fullwidth" id="btnRunUUID">
                    <span class="icon"><i class="material-icons">refresh</i></span>
                    <span>Generate New UUID</span>
                </button>
            </div>

            <div class="box has-background-dark-ter">
                <h5 class="title is-5 has-text-info">Strong Password</h5>
                
                <div class="field">
                    <label class="label has-text-grey-light">Length: <span id="pwdLengthDisplay" class="has-text-info">32</span></label>
                    <input class="slider is-fullwidth is-circle is-info" id="pwdLength" step="1" min="8" max="64" value="32" type="range">
                </div>

                <div class="field is-grouped is-grouped-multiline mb-4">
                    <div class="control">
                        <label class="checkbox has-text-grey-light">
                            <input type="checkbox" id="pwdUpper" checked> A-Z
                        </label>
                    </div>
                    <div class="control">
                        <label class="checkbox has-text-grey-light">
                            <input type="checkbox" id="pwdLower" checked> a-z
                        </label>
                    </div>
                    <div class="control">
                        <label class="checkbox has-text-grey-light">
                            <input type="checkbox" id="pwdNum" checked> 0-9
                        </label>
                    </div>
                    <div class="control">
                        <label class="checkbox has-text-grey-light">
                            <input type="checkbox" id="pwdSym" checked> !@#$
                        </label>
                    </div>
                </div>

                <div class="field has-addons">
                    <div class="control is-expanded">
                        <input class="input has-background-black has-text-warning" 
                               style="font-family: monospace;" 
                               type="text" id="pwdOutput" readonly placeholder="Password result">
                    </div>
                     <div class="control">
                        <button class="button is-dark" id="btnCopyPwd" title="Copy to clipboard">
                            <span class="icon"><i class="material-icons">content_copy</i></span>
                        </button>
                    </div>
                </div>
                <button class="button is-info is-outlined is-fullwidth" id="btnRunPwd">
                    <span class="icon"><i class="material-icons">vpn_key</i></span>
                    <span>Generate Password</span>
                </button>
            </div>
        </div>`;
    }

    attachListeners() {
        // UUID Listeners
        document.getElementById('btnRunUUID').addEventListener('click', () => this.generateUUID());
        document.getElementById('btnCopyUUID').addEventListener('click', () => this.copyToClipboard('uuidOutput', 'uuid-status'));

        // Password Listeners
        document.getElementById('btnRunPwd').addEventListener('click', () => this.generatePassword());
        document.getElementById('btnCopyPwd').addEventListener('click', () => this.copyToClipboard('pwdOutput', 'pwdLengthDisplay'));
        
        // Slider Listener
        const slider = document.getElementById('pwdLength');
        const display = document.getElementById('pwdLengthDisplay');
        slider.addEventListener('input', () => {
            display.textContent = slider.value;
        });

        // Run once on load
        this.generateUUID();
    }

    async generateUUID() {
        const out = document.getElementById('uuidOutput');
        const btn = document.getElementById('btnRunUUID');
        
        btn.classList.add('is-loading');
        try {
            const res = await this.app._fetch('/tools/uuid', { method: 'GET' });
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            out.value = data.uuid;
        } catch (e) {
            console.error("UUID Gen Error:", e);
            out.value = "Error generating UUID";
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    async generatePassword() {
        const length = parseInt(document.getElementById('pwdLength').value);
        const useUpper = document.getElementById('pwdUpper').checked;
        const useLower = document.getElementById('pwdLower').checked;
        const useNum = document.getElementById('pwdNum').checked;
        const useSym = document.getElementById('pwdSym').checked;

        if (!useUpper && !useLower && !useNum && !useSym) {
            alert("Please select at least one character type.");
            return;
        }

        const btn = document.getElementById('btnRunPwd');
        const out = document.getElementById('pwdOutput');
        
        btn.classList.add('is-loading');
        try {
            const payload = {
                length: length,
                upper: useUpper,
                lower: useLower,
                num: useNum,
                sym: useSym
            };

            const res = await this.app._fetch('/tools/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            out.value = data.password;
        } catch (e) {
            console.error("Password Gen Error:", e);
            out.value = "Error generating password";
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    copyToClipboard(elementId, statusElementId) {
        const copyText = document.getElementById(elementId);
        copyText.select();
        copyText.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(copyText.value).then(() => {
            const statusEl = document.getElementById(statusElementId);
            const originalText = statusEl.textContent;
            
            if(statusElementId === 'uuid-status') {
                statusEl.textContent = "Copied!";
                statusEl.classList.remove('is-black');
                statusEl.classList.add('is-success');
                setTimeout(() => {
                    statusEl.textContent = originalText;
                    statusEl.classList.remove('is-success');
                    statusEl.classList.add('is-black');
                }, 1500);
            } else {
                statusEl.textContent = "Copied!";
                setTimeout(() => {
                    statusEl.textContent = document.getElementById('pwdLength').value;
                }, 1500);
            }
        });
    }
}