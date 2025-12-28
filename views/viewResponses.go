package views

import "fmt"

var ResponsesListView = fmt.Sprintf(BaseView, ResponsesListSection)

var ResponsesListSection = `<section class="section has-background-black">
	<h1 class="title has-text-primary">Responses</h1>
	<div class="container is-fluid" hx-get="/getresponses" hx-trigger="load" hx-target="#responsesarea">
		<div class="responsesarea" id="responsesarea">
		</div>
	</div>
</section>`

var ResponseTable = `<table class="table is-fullwidth is-hoverable">
	<thead>
		<tr>
			<th>Time</th>
			<th>Service</th>
			<th>Response ID</th>
			<th>Delete</th>
		</tr>
	</thead>
	<tbody>
		%v
	</tbody>
</table>`

var ResponseRow = `<tr>
	<td>%v</td>
	<td>%v</td>
	<td>%v</td>
	<td><button class="button is-danger delete-response-btn" data-id="%s">delete</button></td>
</tr>`
