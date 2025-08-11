package views

import "fmt"

var AddServiceView string = fmt.Sprintf(BaseView, AddServiceSection)

var AddServiceSection string = `
    <section class="section has-background-black">
        <div class="columns is-centered">
            <div class="column is-half">
                <div class="box has-background-custom">
                    <h2 class="title is-2 has-text-primary">Add New Service</h2>
                    <form id="addServiceForm" action="/addservice" method="post" class="has-background-black">
                        <div class="field">
                            <label class="label has-text-white">Service Kind</label>
                            <div class="control">
                                <input class="input is-outlined" type="text" name="kind"
                                    placeholder="Enter service kind">
                            </div>
                        </div>
                        <div class="field">
                            <label class="label has-text-white">Service Types</label>
                            <div class="control">
                                <input id="typesInput" class="input is-outlined" type="text" name="types"
                                    placeholder="Enter service types (comma-separated)">
                            </div>
                        </div>
                        <div>
                            <button class="button is-primary is-outlined" type="submit">Add Service</button>
                            <button id="routeMapButton" class="button is-secondary is-outlined" type="button">Create
                                Route Map</button>
                        </div>
                        <div id="routeMapOutput" class="has-text-white"></div>
                    </form>
                </div>
            </div>
        </div>
    </section>`
