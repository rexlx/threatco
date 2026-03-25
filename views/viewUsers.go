package views

var ViewUsersSection string = `
<section class="section has-background-black">
	<div class="container">
		<h1 class="title has-text-primary">Users</h1>

		<form action="/users" method="GET" style="margin-bottom: 2rem;">
			<div class="field has-addons">
				<div class="control is-expanded">
					<input class="input is-dark" type="text" name="q" placeholder="Search by email..." value="%s">
				</div>
				<div class="control">
					<button type="submit" class="button is-primary">Search</button>
				</div>
			</div>
		</form>

		<div id="userResults" style="margin-bottom: 1rem;"></div>
		<table class="table is-fullwidth is-striped">
			<thead>
				<tr>
					<th>Email</th>
					<th>Admin</th>
					<th>Services</th>
					<th>Created</th>
					<th>Updated</th>
					<th>Delete</th>
					<th>New API Key</th>
				</tr>
			</thead>
			<tbody>
				%v
			</tbody>
		</table>
		<nav class="pagination is-centered" role="navigation" aria-label="pagination">
			%v
		</nav>
	</div>
</section>
`

// PaginationControls wraps the previous, list, and next components.
var PaginationControls string = `
	%v
	<ul class="pagination-list">
		%v
	</ul>
	%v
`

var PaginationItem string = `<li><a class="pagination-link %v" href="?page=%d%s">%d</a></li>`
var PaginationEllipsis string = `<li><span class="pagination-ellipsis">&hellip;</span></li>`
var PaginationPrevious string = `<a class="pagination-previous %v" href="?page=%d%s">« Previous</a>`
var PaginationNext string = `<a class="pagination-next %v" href="?page=%d%s">Next »</a>`

// UserTableBody defines the row structure for individual user data.
var UserTableBody string = `
<tr>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
</tr>
`
