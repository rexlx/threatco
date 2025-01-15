package views

import "fmt"

var LogView = fmt.Sprintf(BaseView, LoggingSection)

var LoggingSection = `<section class="section has-background-custom">
	<div class="container is-fluid" hx-get="/getlogs" hx-trigger="load" hx-target="#logarea">
		<h1 class="title">Logs</h1>
		<div class="logarea" id="logarea">
		<div class="scrollbar">
            <div class="thumb"></div>
        </div>
		</div>
	</div>
</section>`
