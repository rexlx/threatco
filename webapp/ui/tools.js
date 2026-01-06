import { IocTool } from './tools/ioc.js';
import { TransformerTool } from './tools/transformer.js';
import { CryptoTool } from './tools/crypto.js';
import { DnsTool } from './tools/dns.js';
import { ArchiveTool } from './tools/archive.js';
import { DescribeTool } from './tools/describe.js';
import { SignatureTool } from './tools/signature.js';
import { SshTool } from './tools/ssh.js'; // Consolidated SSH tool container

export class ToolsController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        
        this.iocTool = new IocTool(app);
        this.transformerTool = new TransformerTool(app);
        this.cryptoTool = new CryptoTool(app);
        this.dnsTool = new DnsTool(app);
        this.archiveTool = new ArchiveTool(app);
        this.describeTool = new DescribeTool(app);
        this.signatureTool = new SignatureTool(app);
        this.sshTool = new SshTool(app); // Initializing the stacked SSH tool
    }

    render() {
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = `
            <div class="box has-background-custom">
                <div class="tabs is-toggle is-fullwidth is-small mb-5" style="position: sticky; top: 0; z-index: 20; background-color: inherit; padding-top: 10px; border-bottom: 2px solid #2c2c2c;"> 
                    <ul id="tool-main-nav">
                        <li class="is-active" data-tab="tool-ioc"><a><span class="icon"><i class="material-icons">search</i></span><span>IOC Extractor</span></a></li>
                        <li data-tab="tool-decoder"><a><span class="icon"><i class="material-icons">transform</i></span><span>Transformer</span></a></li>
                        <li data-tab="tool-aes"><a><span class="icon"><i class="material-icons">lock</i></span><span>Crypto</span></a></li>
                        <li data-tab="tool-dns"><a><span class="icon"><i class="material-icons">dns</i></span><span>DNS</span></a></li>
                        <li data-tab="tool-archive"><a><span class="icon"><i class="material-icons">folder_zip</i></span><span>Archive</span></a></li>
                        <li data-tab="tool-describe"><a><span class="icon"><i class="material-icons">bar_chart</i></span><span>Stats</span></a></li>
                        <li data-tab="tool-signature"><a><span class="icon"><i class="material-icons">fingerprint</i></span><span>File ID</span></a></li>
                        <li data-tab="tool-ssh"><a><span class="icon"><i class="material-icons">vpn_key</i></span><span>SSH Tools</span></a></li>
                    </ul>
                </div>
                
                <h2 class="title is-2 has-text-info">Tools</h2>

                <div class="tool-content" id="view-tool-ioc">${this.iocTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-decoder">${this.transformerTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-aes">${this.cryptoTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-dns">${this.dnsTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-archive">${this.archiveTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-describe">${this.describeTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-signature">${this.signatureTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-ssh">${this.sshTool.render()}</div>
            </div>`;

        this.attachListeners();
        
        this.iocTool.attachListeners(() => this.render());
        this.transformerTool.attachListeners();
        this.cryptoTool.attachListeners();
        this.dnsTool.attachListeners();
        this.archiveTool.attachListeners();
        this.describeTool.attachListeners();
        this.signatureTool.attachListeners();
        this.sshTool.attachListeners(); // Attaching consolidated listeners
    }

    attachListeners() {
        const navContainer = document.getElementById('tool-main-nav');
        if (!navContainer) return;
        
        const tabs = navContainer.querySelectorAll('li');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('is-active'));
                tab.classList.add('is-active');
                const targetId = tab.dataset.tab;
                this.container.querySelectorAll('.tool-content').forEach(el => el.classList.add('is-hidden'));
                const viewEl = document.getElementById(`view-${targetId}`);
                if (viewEl) viewEl.classList.remove('is-hidden');
            });
        });
    }
}