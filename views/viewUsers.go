package views

var ViewUsersSection string = `
<section class="section has-background-custom">
	<div class="container">
		<h1 class="title has-text-primary">Users</h1>
		<table class="table is-fullwidth is-striped">
			<thead>
				<tr>
					<th>Email</th>
					<th>Admin</th>
					<th>Services</th>
					<th>Created</th>
					<th>Updated</th>
					<th>Delete</th>
				</tr>
			</thead>
			<tbody>
				%v
			</tbody>
		</table>
	</div>
</section>
`

var UserTableBody string = `
<tr>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
</tr>
`
