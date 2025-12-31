export class SignatureTool {
    constructor(app) {
        this.app = app;
        // Common file signatures (Magic Numbers)
        this.signatures = [
            { hex: '89504E47', type: 'image/png', ext: ['png'] },
            { hex: 'FFD8FF', type: 'image/jpeg', ext: ['jpg', 'jpeg'] },
            { hex: '47494638', type: 'image/gif', ext: ['gif'] },
            { hex: '25504446', type: 'application/pdf', ext: ['pdf'] },
            { hex: '504B0304', type: 'application/zip', ext: ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odt'] },
            { hex: '52617221', type: 'application/x-rar', ext: ['rar'] },
            { hex: '4D5A', type: 'application/x-dosexec', ext: ['exe', 'dll'] },
            { hex: '7F454C46', type: 'application/x-elf', ext: ['bin', 'elf', 'o'] },
            { hex: '1F8B', type: 'application/gzip', ext: ['gz', 'tgz'] },
            { hex: '424D', type: 'image/bmp', ext: ['bmp'] },
            { hex: '494433', type: 'audio/mp3', ext: ['mp3'] },
            { hex: '000001BA', type: 'video/mpeg', ext: ['mpg', 'mpeg'] },
            { hex: '00000020', type: 'video/mp4', ext: ['mp4'] }
        ];
    }

    render() {
        return `
        <div id="tool-signature" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">File Identity Verifier</h4>
            <p class="has-text-grey-light mb-4">Verify if a file's extension matches its true binary signature (Magic Bytes).</p>

            <div class="columns">
                <div class="column is-half">
                    <div class="field">
                        <label class="label has-text-grey-light">Select File</label>
                        <div class="file has-name is-fullwidth is-info">
                            <label class="file-label">
                                <input class="file-input" type="file" id="fileUploadSig">
                                <span class="file-cta">
                                    <span class="file-icon">
                                        <i class="material-icons">fingerprint</i>
                                    </span>
                                    <span class="file-label">
                                        Inspect File...
                                    </span>
                                </span>
                                <span class="file-name" id="fileNameSig">
                                    No file selected
                                </span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>

            <div class="box has-background-dark is-hidden" id="sigResultBox">
                <h5 class="title is-5" id="sigResultTitle">Analysis</h5>
                <div class="content">
                    <table class="table is-fullwidth has-background-dark has-text-white">
                        <tbody>
                            <tr>
                                <td class="has-text-grey-light">Declared Extension:</td>
                                <td class="has-text-weight-bold has-text-info" id="sigExtDeclared">--</td>
                            </tr>
                            <tr>
                                <td class="has-text-grey-light">Detected Signature:</td>
                                <td class="has-text-family-code has-text-warning" id="sigHexFound">--</td>
                            </tr>
                            <tr>
                                <td class="has-text-grey-light">Likely Type:</td>
                                <td id="sigTypeLikely">--</td>
                            </tr>
                        </tbody>
                    </table>
                    <div class="notification is-light" id="sigVerdict"></div>
                </div>
            </div>
        </div>`;
    }

    attachListeners() {
        const fileInput = document.getElementById('fileUploadSig');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFile(e));
        }
    }

    handleFile(event) {
        const file = event.target.files[0];
        if (!file) return;

        document.getElementById('fileNameSig').textContent = file.name;
        
        const reader = new FileReader();
        reader.onloadend = (e) => {
            if (e.target.readyState === FileReader.DONE) {
                const uint8 = new Uint8Array(e.target.result);
                this.analyze(file.name, uint8);
            }
        };
        // We only need the first 32 bytes to identify most headers
        reader.readAsArrayBuffer(file.slice(0, 32));
    }

    analyze(filename, bytes) {
        const box = document.getElementById('sigResultBox');
        const elDeclared = document.getElementById('sigExtDeclared');
        const elHex = document.getElementById('sigHexFound');
        const elLikely = document.getElementById('sigTypeLikely');
        const elVerdict = document.getElementById('sigVerdict');

        box.classList.remove('is-hidden');

        // 1. Get Extension
        const parts = filename.split('.');
        const ext = parts.length > 1 ? parts.pop().toLowerCase() : 'none';
        elDeclared.textContent = '.' + ext;

        // 2. Get Hex
        let hexStr = "";
        for (let i = 0; i < bytes.length; i++) {
            hexStr += bytes[i].toString(16).padStart(2, '0').toUpperCase();
        }
        // Show first 8 bytes for readability
        elHex.textContent = hexStr.substring(0, 16) + (hexStr.length > 16 ? "..." : "");

        // 3. Match Signature
        let match = null;
        for (let sig of this.signatures) {
            if (hexStr.startsWith(sig.hex)) {
                match = sig;
                break; // Found a match
            }
        }

        // 4. Verdict
        if (match) {
            elLikely.textContent = `${match.type} (${match.ext.join(', ')})`;
            
            if (match.ext.includes(ext)) {
                // Exact match (e.g., .png is PNG)
                elVerdict.className = 'notification is-success is-light';
                elVerdict.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">check_circle</i></span><span><strong>Match Confirmed:</strong> The file signature matches the extension.</span></span>`;
            } else {
                // Mismatch (e.g., .jpg is actually PNG)
                elVerdict.className = 'notification is-danger is-light';
                elVerdict.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">warning</i></span><span><strong>Mismatch Detected:</strong> File has extension <code>.${ext}</code> but contains <code>${match.type}</code> data.</span></span>`;
            }
        } else {
            // Unknown signature
            elLikely.textContent = "Unknown / Binary";
            elVerdict.className = 'notification is-warning is-light';
            elVerdict.innerHTML = `<span class="icon-text"><span class="icon"><i class="material-icons">help</i></span><span><strong>Unknown Signature:</strong> We could not match this file's magic bytes to our database. It might be a text file or an uncommon format.</span></span>`;
        }
    }
}