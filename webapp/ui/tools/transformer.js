export class TransformerTool {
    constructor(app) {
        this.app = app;
    }

    render() {
        return `
        <div id="tool-decoder" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">Text Transformer</h4>
            <p class="has-text-grey-light mb-4">Decode, encode, and defang text artifacts.</p>

            <div class="columns">
                <div class="column">
                    <label class="label has-text-grey-light">Input</label>
                    <textarea class="textarea has-background-dark has-text-white" id="inputDecoder" rows="6" placeholder="Paste text here..."></textarea>
                </div>
                <div class="column is-narrow is-flex is-flex-direction-column is-justify-content-center">
                     <div class="buttons is-centered">
                        <button class="button is-small is-info is-light is-fullwidth mb-1" data-op="b64_decode">Base64 Decode &rarr;</button>
                        <button class="button is-small is-info is-light is-fullwidth mb-1" data-op="b64_encode">Base64 Encode &rarr;</button>
                        <button class="button is-small is-warning is-light is-fullwidth mb-1" data-op="url_decode">URL Decode &rarr;</button>
                        <button class="button is-small is-warning is-light is-fullwidth mb-1" data-op="url_encode">URL Encode &rarr;</button>
                        <button class="button is-small is-danger is-light is-fullwidth mb-1" data-op="defang">Defang &rarr;</button>
                        <button class="button is-small is-success is-light is-fullwidth mb-0" data-op="refang">Refang &rarr;</button>
                    </div>
                </div>
                <div class="column">
                    <label class="label has-text-grey-light">Output</label>
                    <textarea class="textarea has-background-black has-text-info" id="outputDecoder" rows="6" readonly placeholder="Result..."></textarea>
                    <button class="button is-small is-dark is-fullwidth mt-2" id="btnCopyDecoder">
                        <span class="icon is-small"><i class="material-icons">content_copy</i></span>
                        <span>Copy Output</span>
                    </button>
                </div>
            </div>
        </div>`;
    }

    attachListeners() {
        const buttons = document.querySelectorAll('#tool-decoder button[data-op]');
        buttons.forEach(btn => {
            btn.addEventListener('click', (e) => {
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
            }
            output.value = res;
        } catch (e) {
            output.value = "Error: " + e.message;
        }
    }
}