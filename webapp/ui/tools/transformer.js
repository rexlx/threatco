export class TransformerTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-decoder" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">Text Transformer</h4>
            <p class="has-text-grey-light mb-4">Decode, encode, defang, and process lists.</p>

            <div class="field">
                <label class="label has-text-grey-light">Input</label>
                <div class="control">
                    <textarea class="textarea has-background-dark has-text-white" id="inputDecoder" rows="5" placeholder="Paste text here..."></textarea>
                </div>
            </div>

            <div class="field py-2">
                 <div class="buttons is-centered">
                    <button class="button is-small is-info is-light" data-op="b64_decode">Base64 Decode</button>
                    <button class="button is-small is-info is-light" data-op="b64_encode">Base64 Encode</button>
                    <button class="button is-small is-warning is-light" data-op="url_decode">URL Decode</button>
                    <button class="button is-small is-warning is-light" data-op="url_encode">URL Encode</button>
                    <button class="button is-small is-danger is-light" data-op="defang">Defang</button>
                    <button class="button is-small is-success is-light" data-op="refang">Refang</button>
                    <button class="button is-small is-primary is-light" data-op="sort_uniq_nl">Sort | Uniq | Nl</button>
                </div>
            </div>

            <div class="field">
                <label class="label has-text-grey-light">Output</label>
                <div class="control">
                    <textarea class="textarea has-background-black has-text-info" id="outputDecoder" rows="5" readonly placeholder="Result..."></textarea>
                </div>
            </div>
            
            <button class="button is-small is-dark is-fullwidth mt-2" id="btnCopyDecoder">
                <span class="icon is-small"><i class="material-icons">content_copy</i></span>
                <span>Copy Output</span>
            </button>
        </div>`;
    }

    attachListeners() {
        const buttons = document.querySelectorAll('#tool-decoder button[data-op]');
        buttons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                // Ensure we get the data-op from the button even if icon/span is clicked
                const op = e.target.closest('button').dataset.op;
                this.runOp(op);
            });
        });

        const copyBtn = document.getElementById('btnCopyDecoder');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                const output = document.getElementById('outputDecoder');
                output.select();
                document.execCommand('copy');
                const orig = copyBtn.innerHTML;
                copyBtn.innerHTML = `<span class="icon is-small"><i class="material-icons">check</i></span><span>Copied!</span>`;
                setTimeout(() => copyBtn.innerHTML = orig, 2000);
            });
        }
    }

    runOp(op) {
        const input = document.getElementById('inputDecoder').value;
        const output = document.getElementById('outputDecoder');
        if (!input) return;

        try {
            let res = "";
            switch (op) {
                case 'b64_decode': res = atob(input); break;
                case 'b64_encode': res = btoa(input); break;
                case 'url_decode': res = decodeURIComponent(input); break;
                case 'url_encode': res = encodeURIComponent(input); break;
                case 'defang': res = input.replace(/\./g, '[.]').replace(/http/gi, 'hxxp'); break;
                case 'refang': res = input.replace(/\[\.\]/g, '.').replace(/hxxp/gi, 'http'); break;
                case 'sort_uniq_nl': 
                    // 1. Split by newlines and remove empty trailing lines
                    const lines = input.split(/\r?\n/).filter(line => line.length > 0);
                    // 2. Sort and Uniq (Set automatically deduplicates)
                    const sortedUnique = [...new Set(lines)].sort();
                    // 3. Number lines (pad start for alignment)
                    const padding = String(sortedUnique.length).length;
                    res = sortedUnique.map((line, idx) => {
                        const num = String(idx + 1).padStart(padding, ' ');
                        return `${num}  ${line}`;
                    }).join('\n');
                    break;
            }
            output.value = res;
        } catch (e) {
            output.value = "Error: " + e.message;
        }
    }
}