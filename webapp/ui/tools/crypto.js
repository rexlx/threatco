export class CryptoTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-aes" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">AES256 Encryptor</h4>
            <p class="has-text-grey-light mb-4">Securely encrypt or decrypt data via the server.</p>
            
            <div class="tabs is-toggle is-fullwidth is-small mb-4">
                <ul>
                    <li class="is-active" id="tabModeEncrypt"><a><span class="icon is-small"><i class="material-icons">lock</i></span><span>Encrypt</span></a></li>
                    <li id="tabModeDecrypt"><a><span class="icon is-small"><i class="material-icons">lock_open</i></span><span>Decrypt</span></a></li>
                </ul>
            </div>
            <div class="tabs is-boxed is-small mb-3">
                <ul>
                    <li class="is-active" id="tabTypeString"><a><span class="icon is-small"><i class="material-icons">text_fields</i></span><span>String</span></a></li>
                    <li id="tabTypeFile"><a><span class="icon is-small"><i class="material-icons">insert_drive_file</i></span><span>File</span></a></li>
                </ul>
            </div>

            <div id="sectionTypeString" class="field"><div class="control"><textarea class="textarea has-background-dark has-text-white" id="inputCryptoString" rows="3" placeholder="Enter text to encrypt..."></textarea></div></div>
            <div id="sectionTypeFile" class="field is-hidden">
                <div class="file has-name is-fullwidth is-info">
                    <label class="file-label">
                        <input class="file-input" type="file" id="inputCryptoFile">
                        <span class="file-cta"><span class="file-icon"><i class="material-icons">upload_file</i></span><span class="file-label">Choose file…</span></span>
                        <span class="file-name" id="displayCryptoFileName">No file selected</span>
                    </label>
                </div>
            </div>

            <div class="field mt-4">
                <label class="label has-text-grey-light">Password</label>
                <div class="control has-icons-left">
                    <input class="input has-background-dark has-text-white" type="password" id="inputCryptoPassword" placeholder="Enter a strong password">
                    <span class="icon is-small is-left"><i class="material-icons">vpn_key</i></span>
                </div>
            </div>

            <button class="button is-info is-fullwidth is-outlined" id="btnRunCrypto"><span class="icon"><i class="material-icons">play_arrow</i></span><span id="btnRunCryptoLabel">Encrypt Data</span></button>

            <div id="cryptoResultContainer" class="message is-info mt-4 is-hidden">
                <div class="message-header"><p>Result</p><button class="delete" id="btnCloseCryptoResult"></button></div>
                <div class="message-body has-background-black-ter">
                    <textarea class="textarea is-small has-background-black has-text-info mb-2" readonly id="outputCryptoResult" rows="3"></textarea>
                    <button class="button is-small is-info is-outlined" id="btnDownloadCryptoFile"><span class="icon"><i class="material-icons">download</i></span><span>Download File</span></button>
                </div>
            </div>
        </div>
        <hr class="has-background-grey-darker my-6">
        <div id="tool-checksum" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">File Checksum Generator</h4>
            <div class="file has-name is-fullwidth is-info mb-4">
                <label class="file-label">
                    <input class="file-input" type="file" id="inputChecksumFile">
                    <span class="file-cta"><span class="file-icon"><i class="material-icons">insert_drive_file</i></span><span class="file-label">Choose a file…</span></span>
                    <span class="file-name" id="displayChecksumFileName">No file selected</span>
                </label>
            </div>
            <button class="button is-info is-outlined is-fullwidth" id="btnRunChecksum">Calculate SHA-256</button>
            <div id="checksumResultContainer" class="message is-success mt-4 is-hidden">
                <div class="message-header"><p>Result</p><button class="delete" id="btnCloseChecksumResult"></button></div>
                <div class="message-body has-background-black-ter"><textarea class="textarea is-small has-background-black has-text-danger" readonly id="outputChecksumResult" rows="2"></textarea></div>
            </div>
        </div>`;
    }

    attachListeners() {
        this.attachCryptoListeners();
        this.attachChecksumListeners();
    }

    attachCryptoListeners() {
        const encryptTab = document.getElementById('tabModeEncrypt');
        const decryptTab = document.getElementById('tabModeDecrypt');
        const label = document.getElementById('btnRunCryptoLabel');
        const inputStr = document.getElementById('inputCryptoString');

        encryptTab.onclick = () => {
            encryptTab.classList.add('is-active'); decryptTab.classList.remove('is-active');
            label.textContent = "Encrypt Data"; inputStr.placeholder = "Enter text to encrypt...";
            this.clearCrypto();
        };
        decryptTab.onclick = () => {
            decryptTab.classList.add('is-active'); encryptTab.classList.remove('is-active');
            label.textContent = "Decrypt Data"; inputStr.placeholder = "Paste ciphertext (Base64)...";
            this.clearCrypto();
        };

        const strTab = document.getElementById('tabTypeString');
        const fileTab = document.getElementById('tabTypeFile');
        strTab.onclick = () => {
            strTab.classList.add('is-active'); fileTab.classList.remove('is-active');
            document.getElementById('sectionTypeString').classList.remove('is-hidden');
            document.getElementById('sectionTypeFile').classList.add('is-hidden');
        };
        fileTab.onclick = () => {
            fileTab.classList.add('is-active'); strTab.classList.remove('is-active');
            document.getElementById('sectionTypeFile').classList.remove('is-hidden');
            document.getElementById('sectionTypeString').classList.add('is-hidden');
        };

        const fileInput = document.getElementById('inputCryptoFile');
        fileInput.onchange = () => { if (fileInput.files.length) document.getElementById('displayCryptoFileName').textContent = fileInput.files[0].name; };

        document.getElementById('btnRunCrypto').onclick = () => this.runCrypto();
        document.getElementById('btnCloseCryptoResult').onclick = () => document.getElementById('cryptoResultContainer').classList.add('is-hidden');
    }

    attachChecksumListeners() {
        const fileInput = document.getElementById('inputChecksumFile');
        fileInput.onchange = () => {
            if (fileInput.files.length) {
                document.getElementById('displayChecksumFileName').textContent = fileInput.files[0].name;
                document.getElementById('checksumResultContainer').classList.add('is-hidden');
            }
        };
        document.getElementById('btnRunChecksum').onclick = () => this.runChecksum();
        document.getElementById('btnCloseChecksumResult').onclick = () => document.getElementById('checksumResultContainer').classList.add('is-hidden');
    }

    clearCrypto() {
        document.getElementById('inputCryptoString').value = "";
        document.getElementById('inputCryptoFile').value = "";
        document.getElementById('cryptoResultContainer').classList.add('is-hidden');
    }

    async runCrypto() {
        const pwd = document.getElementById('inputCryptoPassword').value;
        if (!pwd) return alert("Password required.");
        
        const isEncrypt = document.getElementById('tabModeEncrypt').classList.contains('is-active');
        const isFile = document.getElementById('tabTypeFile').classList.contains('is-active');
        const btn = document.getElementById('btnRunCrypto');
        
        btn.classList.add('is-loading');
        try {
            const formData = new FormData();
            formData.append('password', pwd);
            let endpoint = isEncrypt ? '/tools/encrypt' : '/tools/decrypt';
            let filename = "result";

            if (isFile) {
                const f = document.getElementById('inputCryptoFile').files[0];
                if (!f) throw new Error("Select a file.");
                formData.append('file', f);
                filename = f.name;
            } else {
                const txt = document.getElementById('inputCryptoString').value;
                if (!txt) throw new Error("Enter text.");
                if (isEncrypt) {
                    formData.append('text', txt);
                    filename = "encrypted.txt";
                } else {
                    const bytes = Uint8Array.from(atob(txt), c => c.charCodeAt(0));
                    formData.append('file', new Blob([bytes]), "pasted.bin");
                    filename = "decrypted.txt";
                }
            }

            const res = await this.app._fetch(endpoint, { method: 'POST', body: formData });
            if (!res.ok) throw new Error(await res.text());

            const blob = await res.blob();
            const buf = await blob.arrayBuffer();
            if (res.headers.get('X-Filename')) filename = res.headers.get('X-Filename');

            this.showCryptoResult(buf, filename, isEncrypt);
        } catch (e) {
            alert("Error: " + e.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }

    showCryptoResult(buf, filename, wasEncrypting) {
        const container = document.getElementById('cryptoResultContainer');
        const out = document.getElementById('outputCryptoResult');
        const dlBtn = document.getElementById('btnDownloadCryptoFile');
        container.classList.remove('is-hidden');

        if (wasEncrypting) {
            out.value = btoa(String.fromCharCode(...new Uint8Array(buf)));
        } else {
            try {
                const txt = new TextDecoder("utf-8", {fatal: true}).decode(buf);
                out.value = txt;
            } catch {
                out.value = "[Binary Data]";
            }
        }
        
        // Clone to clear listeners
        const newBtn = dlBtn.cloneNode(true);
        dlBtn.parentNode.replaceChild(newBtn, dlBtn);
        newBtn.onclick = () => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([buf]));
            a.download = filename;
            a.click();
        };
    }

    async runChecksum() {
        const f = document.getElementById('inputChecksumFile').files[0];
        if (!f) return alert("Select file.");
        const btn = document.getElementById('btnRunChecksum');
        btn.classList.add('is-loading');

        try {
            const formData = new FormData();
            formData.append('file', f);
            const res = await this.app._fetch('/tools/checksum', { method: 'POST', body: formData });
            if (!res.ok) throw new Error(await res.text());
            document.getElementById('outputChecksumResult').value = await res.text();
            document.getElementById('checksumResultContainer').classList.remove('is-hidden');
        } catch (e) {
            alert("Checksum error: " + e.message);
        } finally {
            btn.classList.remove('is-loading');
        }
    }
}