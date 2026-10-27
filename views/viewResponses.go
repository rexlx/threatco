package views

import "fmt"

var ResponsesListView = fmt.Sprintf(BaseView, ResponsesListSection)

var ResponsesListSection = `<section class="section has-background-black responses-section" style="padding-top: 1rem; padding-bottom: 3rem;">
	<div class="container is-fluid">
		<!-- Sticky Responses Header / Navigation Bar -->
		<div class="users-nav-bar responses-nav-bar mb-4" id="responses-top">
			<div class="users-nav-left">
				<div class="users-nav-title-group">
					<span class="users-nav-title">Responses</span>
					<span class="tag is-info is-dark is-rounded charts-count-badge" id="responseCountBadge">Telemetry Cache</span>
				</div>
			</div>
			<div class="users-nav-right">
				<button type="button" class="button is-small is-dark is-outlined" onclick="window.location.reload()" title="Refresh responses">↻ Refresh</button>
			</div>
		</div>

		<!-- Responses Terminal Window -->
		<div class="users-window responses-window" id="responsesViewer">
			<div class="terminal-titlebar">
				<div class="terminal-dots">
					<span class="terminal-dot dot-close"></span>
					<span class="terminal-dot dot-min"></span>
					<span class="terminal-dot dot-expand"></span>
				</div>
				<div class="terminal-title">
					<span class="terminal-status-dot"></span>
					<span>responses.telemetry.threatco</span>
				</div>
				<div class="terminal-actions">
					<span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>CACHE ONLINE</span>
				</div>
			</div>

			<div class="responsesarea" id="responsesarea" hx-get="/getresponses" hx-trigger="load" hx-target="#responsesarea">
			</div>

			<div class="terminal-statusbar">
				<span>Telemetry Cache Records</span>
				<span class="is-pulled-right">threatco telemetry • cache</span>
			</div>
		</div>
	</div>
</section>`

var ResponseTable = `<div class="terminal-table-container">
	<table class="terminal-table users-table responses-table">
		<thead>
			<tr>
				<th class="resp-th-time">TIME</th>
				<th class="resp-th-vendor">VENDOR</th>
				<th class="resp-th-value">RESPONSE ID</th>
				<th class="resp-th-actions">ACTIONS</th>
			</tr>
		</thead>
		<tbody>
			%v
		</tbody>
	</table>
</div>`

var ResponseRow = `<tr class="terminal-table-row">
	<td class="resp-cell-time">%v</td>
	<td class="resp-cell-vendor"><span class="service-meta-pill">%v</span></td>
	<td class="resp-cell-value">%v</td>
	<td class="resp-cell-actions">
		<div class="user-action-group">
			<button class="button is-small terminal-action-btn terminal-btn-danger delete-btn delete-response-btn" data-id="%s" title="Delete response">
				<span class="icon is-small"><i class="material-icons">delete</i></span>
			</button>
		</div>
	</td>
</tr>`
