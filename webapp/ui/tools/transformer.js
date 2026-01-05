export class TransformerTool {
    constructor(app) {
        this.app = app;
    }

    showColumnManipulator(input) {
        const container = document.getElementById('column-grid-container');
        container.classList.remove('is-hidden');
        const sep = document.getElementById('col-sep').value || ',';

        // Store the raw lines
        this.lines = input.split(/\r?\n/).filter(l => l.trim());

        // Determine max columns found in the data to build our "active" map
        const maxCols = Math.max(...this.lines.map(line => line.split(sep).length));
        this.activeColumns = new Array(maxCols).fill(true);

        this.renderGrid();
    }

    renderGrid() {
        const sep = document.getElementById('col-sep').value || ',';
        const gridDiv = document.getElementById('col-grid-output');

        let html = `<table class="table is-narrow has-background-black has-text-white"><thead><tr>`;

        // Create header with "Remove" buttons for each column
        this.activeColumns.forEach((isActive, idx) => {
            if (!isActive) return;
            html += `
            <th class="has-text-centered">
                <button class="button is-danger is-small btn-del-col" data-idx="${idx}">
                    <i class="material-icons" style="font-size: 14px;">remove_circle</i>
                </button>
            </th>`;
        });
        html += `</tr></thead><tbody>`;

        // Render rows (showing only active columns)
        this.lines.forEach(line => {
            const parts = line.split(sep);
            html += `<tr>`;
            this.activeColumns.forEach((isActive, idx) => {
                if (!isActive) return;
                const content = parts[idx] || "";
                html += `<td class="is-size-7"><span class="tag is-dark">${content}</span></td>`;
            });
            html += `</tr>`;
        });

        gridDiv.innerHTML = html + `</tbody></table>`;

        // Attach column deletion listeners
        gridDiv.querySelectorAll('.btn-del-col').forEach(btn => {
            btn.addEventListener('click', () => {
                const i = parseInt(btn.dataset.idx);
                this.activeColumns[i] = false;
                this.renderGrid();
            });
        });
    }

    attachGridListeners() {
        document.getElementById('btn-apply-sep').addEventListener('click', () => {
            // Re-run showColumnManipulator to reset the grid with the new separator
            const input = document.getElementById('inputDecoder').value;
            this.showColumnManipulator(input);
        });

        document.getElementById('btn-save-grid').addEventListener('click', () => {
            const sep = document.getElementById('col-sep').value || ',';

            const finalOutput = this.lines.map(line => {
                const parts = line.split(sep);
                // Only keep parts where the column index is still active
                return parts.filter((_, idx) => this.activeColumns[idx]).join(sep);
            }).join('\n');

            document.getElementById('outputDecoder').value = finalOutput;
            document.getElementById('column-grid-container').classList.add('is-hidden');
        });
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
                    <button class="button is-small is-link is-light" data-op="col_manip">Column Manipulator</button>
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

            <div id="column-grid-container" class="is-hidden mt-4 p-4 has-background-dark-ter" style="border-radius: 6px;">
                <div class="field has-addons mb-4">
                    <div class="control"><input id="col-sep" class="input is-small" type="text" placeholder="Separator (e.g. , or |)" value=","></div>
                    <div class="control"><button id="btn-apply-sep" class="button is-small is-info">Apply</button></div>
                </div>
                <div id="col-grid-output" style="max-height: 400px; overflow-y: auto; overflow-x: auto;"></div>
                <button class="button is-small is-success is-fullwidth mt-3" id="btn-save-grid">Commit Changes to Output</button>
            </div>
        </div>`;
    }

    attachListeners() {
        // [1] Existing logic for the main op buttons
        const buttons = document.querySelectorAll('#tool-decoder button[data-op]');
        buttons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const op = e.target.closest('button').dataset.op;
                this.runOp(op);
            });
        });

        // [2] Existing logic for copy button
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

        // [3] Wire up the column manipulator UI events
        this.attachGridListeners();
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
                case 'col_manip':
                    this.showColumnManipulator(input);
                    return; // Don't overwrite output yet; the Grid UI handles it
                case 'sort_uniq_nl':
                    const lines = input.split(/\r?\n/).filter(line => line.length > 0);
                    const sortedUnique = [...new Set(lines)].sort();
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