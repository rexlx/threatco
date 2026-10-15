package views

import "fmt"

var LogView = fmt.Sprintf(BaseView, LoggingSection)

var LoggingSection = `<section class="section has-background-black" style="padding-top: 1.5rem;">
	<div class="container is-fluid">
		<div class="terminal-window">
			<div class="terminal-titlebar">
				<div class="terminal-dots">
					<span class="terminal-dot dot-close"></span>
					<span class="terminal-dot dot-min"></span>
					<span class="terminal-dot dot-expand"></span>
				</div>
				<div class="terminal-title">
					<span class="terminal-status-dot"></span>
					<span>threatco-daemon.log</span>
				</div>
				<div class="terminal-actions">
					<input id="logSearchInput" type="text" class="input is-small terminal-search" placeholder="Filter logs (regex/text)..." />
					<div class="buttons has-addons mb-0">
						<button id="filterAllBtn" class="button is-small is-primary is-selected">All</button>
						<button id="filterErrorsBtn" class="button is-small is-dark">Errors</button>
					</div>
					<button id="copyLogsBtn" class="button is-small is-dark" title="Copy visible logs">
						<span>Copy</span>
					</button>
					<button id="autoScrollToggle" class="button is-small is-dark is-active" title="Toggle Auto-Scroll">
						<span>Auto-Scroll: ON</span>
					</button>
				</div>
			</div>
			<div class="logarea terminal-body" id="logarea" hx-get="/getlogs" hx-trigger="load" hx-target="#logarea" hx-swap="innerHTML">
				<div class="terminal-placeholder">
					<span class="animate-spin" style="display: inline-block; margin-right: 8px;">⏳</span> Loading logs stream...
				</div>
			</div>
			<div class="terminal-statusbar">
				<span id="logCountDisplay">Loading lines...</span>
				<span class="is-pulled-right">threatco runtime • live</span>
			</div>
		</div>
	</div>
</section>`
