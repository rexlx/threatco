import { escapeHtml } from './utils.js';

export class HealthController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
    }

    async render() {
        // 1. Show Loading State
        this.container.classList.remove('is-hidden');
        this.container.innerHTML = '<p class="has-text-info">Checking health...</p><progress class="progress is-small is-primary" max="100"></progress>';
        
        // 2. Fetch Data
        const stats = await this.app.getServerStats();
        
        // 3. Handle Empty/Error State
        if (!stats) {
            this.container.innerHTML = '<p class="has-text-danger">Could not retrieve health stats.</p>';
            return;
        }

        // 4. Render Container & Title
        this.container.innerHTML = '';
        const title = document.createElement('h1');
        title.className = 'title has-text-info';
        title.textContent = 'Health Check';
        this.container.appendChild(title);

        // 5. Configuration
        const DEGRADED_THRESHOLD = 0.2; // 20% failure rate
        let hasHealthChecks = false;

        // 6. Build Table Structure
        const table = document.createElement('table');
        table.className = 'table is-fullwidth is-striped has-background-dark';
        table.innerHTML = `
            <thead class="has-background-black">
                <tr>
                    <th class="has-text-info">Service</th>
                    <th class="has-text-info">Status</th>
                    <th class="has-text-info">Uptime (Recent)</th>
                </tr>
            </thead>`;
        
        const tbody = document.createElement('tbody');

        // 7. Loop through Stats
        for (const key in stats) {
            if (key.startsWith('health-check-')) {
                hasHealthChecks = true;
                const serviceName = key.replace('health-check-', '');
                const verboseHistory = stats[key] || [];
                
                // Extract values from history object
                const history = [];
                if (Array.isArray(verboseHistory)) {
                    verboseHistory.forEach(entry => {
                        // Handle cases where entry is an object {value: 1} or just a number
                        if (typeof entry === 'object' && entry !== null && entry.value !== undefined) {
                            history.push(entry.value);
                        } else {
                            history.push(entry);
                        }
                    });
                }

                let statusText = 'NO DATA';
                let statusClass = 'is-light';
                let uptimePercentage = 'N/A';

                if (history.length > 0) {
                    const lastStatus = history[history.length - 1];
                    const totalChecks = history.length;
                    const failures = history.filter(s => s === 0).length;
                    const successRate = (totalChecks - failures) / totalChecks;
                    uptimePercentage = `${(successRate * 100).toFixed(1)}%`;

                    // Determine Status Color
                    if (lastStatus === 0) {
                        statusText = 'DOWN';
                        statusClass = 'is-danger';
                    } else {
                        const failureRate = failures / totalChecks;
                        if (failureRate > DEGRADED_THRESHOLD) {
                            statusText = 'DEGRADED';
                            statusClass = 'is-warning';
                        } else {
                            statusText = 'UP';
                            statusClass = 'is-success';
                        }
                    }
                }

                // Create Row
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="has-text-white">${escapeHtml(serviceName)}</td>
                    <td><span class="tag ${statusClass}">${statusText}</span></td>
                    <td class="has-text-white">${uptimePercentage}</td>
                `;
                tbody.appendChild(tr);
            }
        }

        table.appendChild(tbody);

        // 8. Final Append
        if (hasHealthChecks) {
            this.container.appendChild(table);
        } else {
            this.container.innerHTML += '<p class="has-text-info">No health check information available.</p>';
        }
    }
}
