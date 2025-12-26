import { IocTool } from './tools/ioc.js';
import { TransformerTool } from './tools/transformer.js';
import { CryptoTool } from './tools/crypto.js';
import { DnsTool } from './tools/dns.js';

export class ToolsController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        
        // Initialize sub-controllers
        this.iocTool = new IocTool(app);
        this.transformerTool = new TransformerTool(app);
        this.cryptoTool = new CryptoTool(app);
        this.dnsTool = new DnsTool(app);
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
                    </ul>
                </div>
                
                <h2 class="title is-2 has-text-info">Tools</h2>

                <div class="tool-content" id="view-tool-ioc">${this.iocTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-decoder">${this.transformerTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-aes">${this.cryptoTool.render()}</div>
                <div class="tool-content is-hidden" id="view-tool-dns">${this.dnsTool.render()}</div>
            </div>`;

        this.attachListeners();
        
        // Delegate listener attachment to sub-tools
        this.iocTool.attachListeners(() => this.render());
        this.transformerTool.attachListeners();
        this.cryptoTool.attachListeners();
        this.dnsTool.attachListeners();
    }

    attachListeners() {
        // FIX: Only select 'li' elements that are direct children of our main nav ID
        const navContainer = document.getElementById('tool-main-nav');
        if (!navContainer) return;
        
        const tabs = navContainer.querySelectorAll('li');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // UI Toggle
                tabs.forEach(t => t.classList.remove('is-active'));
                tab.classList.add('is-active');

                // View Toggle
                const targetId = tab.dataset.tab;
                
                // Hide all tool views
                this.container.querySelectorAll('.tool-content').forEach(el => el.classList.add('is-hidden'));
                
                // Show the specific view
                const viewId = `view-${targetId}`;
                const viewEl = document.getElementById(viewId);
                if (viewEl) {
                    viewEl.classList.remove('is-hidden');
                }
            });
        });
    }
}