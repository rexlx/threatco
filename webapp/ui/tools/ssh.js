// webapp/ui/tools/ssh.js
import { SshGenTool } from './sshgen.js';
import { SshTradeTool } from './sshtrade.js';

export class SshTool {
    constructor(app) {
        this.genTool = new SshGenTool(app);
        this.tradeTool = new SshTradeTool(app);
    }

    render() {
        return `
        <div id="tool-ssh-container">
            <h2 class="title is-2 has-text-info mb-6">SSH Management</h2>
            
            <div class="box has-background-black-bis mb-6">
                ${this.genTool.render()}
            </div>

            <hr class="has-background-grey-dark">

            <div class="box has-background-black-bis">
                ${this.tradeTool.render()}
            </div>
        </div>`;
    }

    attachListeners() {
        this.genTool.attachListeners();
        this.tradeTool.attachListeners();
    }
}