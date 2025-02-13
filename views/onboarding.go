package views

import "fmt"

var OnboardingView string = fmt.Sprintf(BaseView, OnboardingSection)

var OnboardingSection string = `
<section class="section has-background-custom"">
  <div class="container">
    <div class="content">
	  <h1 class="title is-1 has-text-primary">onboarding users</h1>
	  <h2 class="subtitle is-3 has-text-white">add users to the system</h2>
	  <p class"has-text-info-light">follow the instructions below add users to the system</p>
	  <ol class="has-text-white">
	    <li>click on the "add user" link in the navigation bar</li>
		<li>fill in the form with the user's details</li>
		<li>click on the "add user" button. a prompt will appear informing you of a one time key appearing on screen</li>
		<li>click ok and copy the one time key and give it to the user</li>
	  </ol>

	  <p class"has-text-info-light">you can now view the user in the users section</p>

	  <h2 class="subtitle is-3 has-text-white">add users to the extensions</h2>
	  <p class"has-text-info-light">follow the instructions below to add users to the extensions</p>
	  <ol class="has-text-white">
	    <li>click on the "profile" link in the navigation bar (three lines in top right)</li>
		<li>enter the server url, email, and key generated earlier</li>
		<li>click on the "update" button</li>
	  </ol>

	  <p class"has-text-info-light">you can test by clicking the "services" link in the navigation bar. if no services appear you have not connected</p>
	</div>
	</div>
</section>
`
