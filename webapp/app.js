/**
 * app.js
 * The complete application logic, refactored for a web environment
 * with server-side session authentication.
 */
export class Application {
    constructor() {
        this.user = {};
        this.resultWorkers = [];
        this.results = [];
        this.errors = [];
        this.notifications = []; // <-- Add notifications array
        this.socket = null; // <-- Add WebSocket instance property
        // API URL is relative because the app is served from the same domain as the API.
        this.apiUrl = "";
        this.servers = [];
        this.resultHistory = [];
        this.focus = { "message": "this data wasn't ready or something truly unexpected happened" };
        this.initialized = false;
    }

    /**
     * Initializes the application.
     * Replaces Electron store with web standards.
     */
    async init() {
        // Fetch user data. This succeeds only if the user has a valid session.
        await this.fetchUser();
        
        // Only proceed if we successfully got user data
        if (this.user && this.user.email) {
            await this.fetchHistory();
            await this.getServices();
            this.initWebSocket(); // <-- Initialize WebSocket connection
            this.initialized = true;
        }
    }

    /**
     * NEW: Initializes the WebSocket connection.
     */
    initWebSocket() {
        // Determine the WebSocket protocol based on the window's protocol.
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        // Construct the WebSocket URL. Assumes the WebSocket endpoint is at '/ws'.
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        console.log(`Connecting to WebSocket at ${wsUrl}`);
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
            console.log('WebSocket connection established.');
            this.errors.push('Real-time connection active.');
        };

        this.socket.onmessage = (event) => {
            try {
                const notification = JSON.parse(event.data);
                console.log('Received notification:', notification);
                // Add a unique ID for the frontend to manage it
                notification.id = `notif-${Date.now()}`;
                this.notifications.push(notification);
            } catch (e) {
                console.error('Error parsing notification message:', e);
            }
        };

        this.socket.onclose = () => {
            console.log('WebSocket connection closed. Attempting to reconnect...');
            this.errors.push('Real-time connection lost. Reconnecting...');
            // Simple reconnect logic
            setTimeout(() => this.initWebSocket(), 5000);
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.errors.push('A real-time connection error occurred.');
        };
    }

    /**
     * Generic fetch wrapper to include credentials (session cookies) by default.
     * @param {string} url - The URL to fetch.
     * @param {object} options - The options for the fetch call.
     * @returns {Promise<Response>}
     */
    async _fetch(url, options = {}) {
        // Start with default options and robustly merge incoming options.
        const finalOptions = {
            credentials: 'include', // This is crucial for sending session cookies.
            ...options,
            headers: {
                // Spread incoming headers safely.
                ...options.headers,
            },
        };
        // console.log(finalOptions)
        // Determine if this is a file upload, which shouldn't have a Content-Type set by us.
        const isFileUpload = finalOptions.body instanceof FormData || finalOptions.body instanceof Blob || finalOptions.body instanceof File;
    
        // Set default Content-Type to JSON if it's not a file upload and no Content-Type is already set.
        if (!isFileUpload && !finalOptions.headers['Content-Type']) {
            finalOptions.headers['Content-Type'] = 'application/json';
        }
    
        return fetch(this.apiUrl + url, finalOptions);
    }

    /**
     * This function is no longer needed for setting credentials,
     * but can be kept for updating user profile information if necessary.
     */
    async updateUser(user) {
        let thisURL = `/updateuser`; // Relative path
        let response = await this._fetch(thisURL, {
            method: 'POST',
            body: JSON.stringify(user)
        });
        let data = await response.json();
        this.user = data;
    }

    async fetchResponseCache(options = {}) {
        const params = new URLSearchParams();
        if (options.vendor) params.append('vendor', options.vendor);
        if (options.start !== undefined) params.append('start', options.start);
        if (options.limit !== undefined) params.append('limit', options.limit);
        const finalURL = `/getresponses?${params.toString()}`;

        try {
            const response = await this._fetch(finalURL, { method: 'GET' });
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            return await response.text();
        } catch (error) {
            this.errors.push(`Error fetching response cache: ${error.message}`);
            return `<p class="has-text-danger">Error fetching response cache: ${error.message}</p>`;
        }
    }

    async fetchPastSearches(value) {
        const thisURL = `/previous-results`;
        try {
            const response = await this._fetch(thisURL, {
                method: 'POST',
                body: JSON.stringify({ "value": value || "" })
            });
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            return await response.json();
        } catch (error) {
            this.errors.push(`Error fetching past searches: ${error.message}`);
            return [];
        }
    }

    addService(service) {
        if (!this.user.services) this.user.services = [];
        this.user.services.push(service);
        this.updateUser(this.user);
    }

    removeService(service) {
        if (this.user.services) {
            this.user.services = this.user.services.filter(s => s.kind !== service.kind);
            this.updateUser(this.user);
        }
    }

    /**
     * REPLACED: Uses web standards to trigger a file download.
     */
    saveResultsToCSV(includeHistory) {
        const rightFreakinNow = new Date();
        const filename = `results-${rightFreakinNow.getFullYear()}-${rightFreakinNow.getMonth() + 1}-${rightFreakinNow.getDate()}.csv`;
        let csvContent = "server-id,local-id,value,from,matched,info\n";
        let data = this.results;
        if (includeHistory) data = [...data, ...this.resultHistory];

        data.forEach((result) => {
            const info = result.info ? String(result.info).replaceAll(",", " - ") : '';
            let row = `${result.link || ''},${result.id || ''},${result.value || ''},${result.from || ''},${result.matched || ''},${info}\n`;
            csvContent += row;
        });

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement("a");
        const url = URL.createObjectURL(blob);
        link.setAttribute("href", url);
        link.setAttribute("download", filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        this.errors.push(`File '${filename}' download initiated.`);
    }

    /**
     * REPLACED: Uses localStorage instead of Electron store.
     */
    async fetchHistory() {
        try {
            const history = JSON.parse(localStorage.getItem("threatpunch_history"));
            if (history && Array.isArray(history)) this.resultHistory = history;
        } catch (err) {
            this.errors.push("Error fetching history: " + err);
        }
    }

    /**
     * REPLACED: Uses localStorage instead of Electron store.
     */
    async setHistory() {
        if (this.resultHistory.length > 50) {
            this.resultHistory.splice(0, this.resultHistory.length - 50);
        }
        localStorage.setItem("threatpunch_history", JSON.stringify(this.resultHistory));
    }

    async sendLog(message) {
        if (!this.user || !this.user.email || message === "") return;
        const thisURL = `/logger`;
        try {
            await this._fetch(thisURL, {
                method: 'POST',
                body: JSON.stringify({ username: this.user.email, message: message })
            });
        } catch (error) {
            this.errors.push(`Error sending log: ${error.message}`);
        }
    }

    async uploadFile(file) {
        const thisURL = `/upload`;
        const chunkSize = 1024 * 1024;
        let currentChunk = 0;

        const uploadChunk = async () => {
            const start = currentChunk * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const chunk = file.slice(start, end);
            this.errors = [`<progress class="progress" value="${Math.ceil((end / file.size) * 100)}" max="100"></progress>`];
            
            try {
                const uploadHeaders = {
                        'Content-Range': `bytes ${start}-${end - 1}/${file.size}`,
                        'X-filename': file.name,
                        'X-last-chunk': currentChunk === Math.ceil(file.size / chunkSize) - 1,
                    }
                const response = await this._fetch(thisURL, {
                    method: 'POST',
                    headers: uploadHeaders,
                    body: chunk
                });

                if (!response.ok) throw new Error(`Error uploading chunk: ${response.status}`);
                
                currentChunk++;
                if (currentChunk < Math.ceil(file.size / chunkSize)) {
                    uploadChunk();
                } else {
                    this.errors = [`<p class="has-text-info">Uploaded ${file.name}</p>`];
                    const data = await response.json();
                    if (data && data.id) this.results.push({ "background": "has-background-success", "from": "uploader service", "id": data.id, "value": file.name, "link": "none", "info": `${data.status} uploaded!` });
                }
            } catch (error) {
                this.sendLog(`Error uploading chunk: ${error.message}`);
            }
        };
        uploadChunk();
    }

    async fetchUser() {
        let thisURL = `/user`; // Must be a protected endpoint
        try {
            let response = await this._fetch(thisURL, { method: 'GET' });
            if (!response.ok) throw new Error(`Failed to fetch user: ${response.status}`);
            this.user = await response.json();
        } catch (e) {
            console.error("Failed to fetch user", e);
            this.user = {};
        }
    }

    async fetchDetails(id) {
        if (!id) return this.errors.push("No ID provided.");
        let thisURL = `/events/${id}`;
        let response = await this._fetch(thisURL, { method: 'GET' });
        if (!response.ok) return this.errors.push(`Error fetching details for ID ${id}: ${response.statusText}`);
        this.focus = await response.json();
    }

    async fetchMatch(to, match, type, route) {
        let thisURL = `/pipe`;
        const proxyRequest = { "username": this.user.email, "to": to, "value": match, "type": type, "route": route };
        let response = await this._fetch(thisURL, {
            method: 'POST',
            body: JSON.stringify(proxyRequest)
        });
        let data = await response.json();
        if (this.resultHistory.length > 50) this.resultHistory.splice(0, this.resultHistory.length - 50);
        this.resultHistory.push(data);
        return data;
    }

    async fetchMatchDontParse(blob) {
        let thisURL = `/parse`;
        const proxyRequest = { "username": this.user.email, "blob": blob };
        console.log("fetchMatchDontParse", blob)
        let response = await this._fetch(thisURL, {
            method: 'POST',
            body: JSON.stringify(proxyRequest)
        });
        let data = await response.json();
        if (this.resultHistory.length > 100) this.resultHistory.splice(0, this.resultHistory.length - 100);
        this.resultHistory.push(data);
        return data;
    }

    async rectifyServices() {
        const thisURL = `/rectify`;
        try {
            const response = await this._fetch(thisURL, { method: 'GET' });
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status} - ${await response.text()}`);
            const data = await response.json();
            this.errors = [data.message || "Services rectified successfully."];
            await this.getServices();
        } catch (error) {
            this.errors.push(`Error rectifying services: ${error.message}`);
        }
    }

    async getServices() {
        let thisURL = `/getservices`;
        try {
            let response = await this._fetch(thisURL, { method: 'GET' });
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            let data = await response.json();
            if (!Array.isArray(data)) throw new Error("Error fetching services: " + JSON.stringify(data));
            this.servers = data.map(sanitizeService);
        } catch (err) {
            this.errors.push("Error fetching services: " + err);
        }
    }

    async getServerStats() {
        let thisURL = `/stats`;
        try {
            let response = await this._fetch(thisURL, { method: 'GET' });
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            let data = await response.json();
            if (typeof data !== 'object' || data === null || Array.isArray(data)) throw new Error("Unexpected data format for stats");
            return data;
        } catch (err) {
            this.errors.push("Error fetching server stats: " + err.message);
            return null;
        }
    }
    
    /**
     * Archives a result by its ID.
     * @param {string} id - The ID of the result to archive.
     */
    async archiveResult(id) {
        const thisURL = `/archive`;
        try {
            const response = await this._fetch(thisURL, {
                method: 'POST',
                body: JSON.stringify({ id: id })
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP error! Status: ${response.status} - ${errorText}`);
            }
            const data = await response.json();
            this.notifications.push({
                id: `notif-${Date.now()}`,
                info: data.message || `Successfully archived item ${id}.`,
                created: new Date().toISOString()
            });
            return data;
        } catch (error) {
            this.errors.push(`Error archiving result: ${error.message}`);
            return null;
        }
    }
}

// This function remains the same as it's for data sanitization.
function sanitizeService(service) {
    if (!service || typeof service !== 'object') {
        return { name: "Invalid Service", type: [] };
    }
    return {
        upload_service: Boolean(service.upload_service),
        expires: Number.isInteger(service.expires) ? service.expires : 0,
        secret: String(service.secret || ''),
        selected: Boolean(service.selected),
        insecure: Boolean(service.insecure),
        name: String(service.name || '').replace(/[<>&"'`;]/g, ''),
        url: String(service.url || '').startsWith('http') ? service.url : '',
        rate_limited: Boolean(service.rate_limited),
        max_requests: Number.isInteger(service.max_requests) ? service.max_requests : 0,
        refill_rate: Number.isInteger(service.refill_rate) ? service.refill_rate : 0,
        auth_type: String(service.auth_type || ''),
        key: String(service.key || ''),
        kind: String(service.kind || ''),
        type: Array.isArray(service.type) ? service.type.map(String) : [],
        route_map: service.route_map,
        description: String(service.description || '').replace(/[<>&"'`;]/g, '')
    };
}
