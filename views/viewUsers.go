package views

var ViewUsersSection string = `<section class="section has-background-black users-section" style="padding-top: 1rem; padding-bottom: 3rem;">
	<div class="container is-fluid">
		<!-- Sticky Users Header / Navigation Bar -->
		<div class="users-nav-bar" id="users-top">
			<div class="users-nav-left">
				<div class="users-nav-title-group">
					<span class="users-nav-title">User Accounts</span>
					<span class="tag is-info is-dark is-rounded charts-count-badge" id="userCountBadge">%s</span>
				</div>
			</div>

			<div class="users-nav-right">
				<form action="/users" method="GET" class="users-search-form">
					<div class="field has-addons mb-0">
						<div class="control">
							<input id="userSearchInput" name="q" type="text" class="input is-small terminal-search" placeholder="Search by email..." value="%s" autocomplete="off" />
						</div>
						<div class="control">
							<button type="submit" class="button is-small is-dark" title="Search users">Search</button>
						</div>
						%s
					</div>
				</form>
				<a href="/create-user" class="button is-small is-primary is-outlined" title="Add a new user">+ Add User</a>
				<button type="button" class="button is-small is-dark is-outlined" onclick="window.location.reload()" title="Refresh users">↻ Refresh</button>
			</div>
		</div>

		<!-- Users Terminal Window -->
		<div class="users-window" id="usersViewer">
			<div class="terminal-titlebar">
				<div class="terminal-dots">
					<span class="terminal-dot dot-close"></span>
					<span class="terminal-dot dot-min"></span>
					<span class="terminal-dot dot-expand"></span>
				</div>
				<div class="terminal-title">
					<span class="terminal-status-dot"></span>
					<span>users.registry.threatco</span>
				</div>
				<div class="terminal-actions">
					<span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>DATABASE ONLINE</span>
				</div>
			</div>

			<div id="userResults" class="user-results-container"></div>

			<div class="terminal-table-container">
				<table class="terminal-table users-table">
					<thead>
						<tr>
							<th class="user-th-email">USER / EMAIL</th>
							<th class="user-th-role">ROLE</th>
							<th class="user-th-services">SERVICES</th>
							<th class="user-th-date">CREATED</th>
							<th class="user-th-date">UPDATED</th>
							<th class="user-th-actions">ACTIONS</th>
						</tr>
					</thead>
					<tbody>
						%s
					</tbody>
				</table>
			</div>

			<div class="terminal-statusbar">
				<span>%s</span>
				<span class="is-pulled-right">threatco auth • rbac</span>
			</div>
		</div>

		<!-- Pagination Navigation -->
		%s
	</div>
</section>
`

// PaginationControls wraps the previous, list, and next components.
var PaginationControls string = `
	<nav class="pagination is-centered terminal-pagination" role="navigation" aria-label="pagination">
		%v
		<ul class="pagination-list">
			%v
		</ul>
		%v
	</nav>
`

var PaginationItem string = `<li><a class="pagination-link %v" href="?page=%d%s">%d</a></li>`
var PaginationEllipsis string = `<li><span class="pagination-ellipsis">&hellip;</span></li>`
var PaginationPrevious string = `<a class="pagination-previous %v" href="?page=%d%s">« Previous</a>`
var PaginationNext string = `<a class="pagination-next %v" href="?page=%d%s">Next »</a>`

// UserTableBody defines the row structure for individual user data.
var UserTableBody string = `
<tr class="terminal-table-row">
	<td class="user-cell-email">%v</td>
	<td class="user-cell-role">%v</td>
	<td class="user-cell-services">%v</td>
	<td class="user-cell-date">%v</td>
	<td class="user-cell-date">%v</td>
	<td class="user-cell-actions">
		<div class="user-action-group">
			%v
			%v
		</div>
	</td>
</tr>
`

