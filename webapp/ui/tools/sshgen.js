export class SshGenTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-sshgen" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">SSH Key Generator</h4>
            <p class="has-text-grey-light mb-4">Generate RSA or ECDSA key pairs and download them locally.</p>
            
            <div class="field">
                <label class="label has-text-grey-light">Key Algorithm</label>
                <div class="control">
                    <div class="select is-fullwidth">
                        <select id="sshKeyType">
                            <option value="rsa">RSA (4096-bit)</option>
                            <option value="ecdsa">ECDSA (P-521)</option>
                        </select>
                    </div>
                </div>
            </div>

            <button class="button is-info is-fullwidth is-outlined" id="btnGenSSH">
                <span class="icon"><i class="material-icons">vpn_key</i></span>
                <span>Generate Key Pair</span>
            </button>

            <div id="sshResultContainer" class="message is-info mt-4 is-hidden">
                <div class="message-header">
                    <p>Generated Keys</p>
                    <button class="delete" id="btnCloseSshResult"></button>
                </div>
                <div class="message-body has-background-black-ter">
                    <div class="field">
                        <label class="label is-small has-text-info">Private Key (Keep Secret)</label>
                        <div class="control">
                            <textarea class="textarea is-small has-background-black has-text-warning" id="outputSshPriv" readonly rows="8"></textarea>
                        </div>
                    </div>
                    
                    <div class="field mt-3">
                        <label class="label is-small has-text-info">Public Key (OpenSSH Format)</label>
                        <div class="control">
                            <textarea class="textarea is-small has-background-black has-text-success" id="outputSshPub" readonly rows="3"></textarea>
                        </div>
                    </div>

                    <div class="buttons mt-4">
                        <button class="button is-small is-info is-outlined" id="btnDownloadSshPriv">
                            <span class="icon"><i class="material-icons">download</i></span>
                            <span>Download Private Key</span>
                        </button>
                        <button class="button is-small is-success is-outlined" id="btnDownloadSshPub">
                            <span class="icon"><i class="material-icons">download</i></span>
                            <span>Download Public Key</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>`;
    }

    attachListeners() {
        const genBtn = document.getElementById('btnGenSSH');
        const closeBtn = document.getElementById('btnCloseSshResult');

        genBtn.onclick = async () => {
            const type = document.getElementById('sshKeyType').value;
            genBtn.classList.add('is-loading');

            try {
                // Interacts with the Go endpoint we discussed
                const res = await this.app._fetch(`/tools/ssh-gen?type=${type}`);
                if (!res.ok) throw new Error(await res.text());
                
                const data = await res.json();
                this.displayResults(data, type);
            } catch (e) {
                alert("Generation Error: " + e.message);
            } finally {
                genBtn.classList.remove('is-loading');
            }
        };

        closeBtn.onclick = () => {
            document.getElementById('sshResultContainer').classList.add('is-hidden');
        };
    }

    displayResults(data, type) {
        const container = document.getElementById('sshResultContainer');
        const privArea = document.getElementById('outputSshPriv');
        const pubArea = document.getElementById('outputSshPub');
        const dlPriv = document.getElementById('btnDownloadSshPriv');
        const dlPub = document.getElementById('btnDownloadSshPub');

        privArea.value = data.private;
        pubArea.value = data.public;
        container.classList.remove('is-hidden');

        // Logic to "Save to Disk" using Blobs
        dlPriv.onclick = () => this.downloadFile(data.private, `id_${type}`);
        dlPub.onclick = () => this.downloadFile(data.public, `id_${type}.pub`);
    }

    downloadFile(content, filename) {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }
}