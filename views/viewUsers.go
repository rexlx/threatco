package views

var ViewUsersSection string = `
<section class="section has-background-black">
	<div class="container">
		<h1 class="title has-text-primary">Users</h1>
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

var PaginationControls string = `
	%v
	<ul class="pagination-list">
		%v
	</ul>
	%v
`

var PaginationItem string = `<li><a class="pagination-link %v" href="?page=%d">%d</a></li>`
var PaginationEllipsis string = `<li><span class="pagination-ellipsis">&hellip;</span></li>`
var PaginationPrevious string = `<a class="pagination-previous %v" href="?page=%d">« Previous</a>`
var PaginationNext string = `<a class="pagination-next %v" href="?page=%d">Next »</a>`

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
