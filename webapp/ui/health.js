import { escapeHtml } from './utils.js';

export class HealthController {
    constructor(containerId, app) {
        this.container = document.getElementById(containerId);
        this.app = app;
        this.searchQuery = '';
        this.servicesData = [];
        this.uptimeData = null;
    }

    async render() {
        this.container.classList.remove('is-hidden');
        this.renderLoading();

        // Fetch Data
        const [stats, uptimeData] = await Promise.all([
            this.app.getServerStats(),
            this.app.getUptime()
        ]);

        if (!stats) {
            this.renderError();
            return;
        }

        this.uptimeData = uptimeData;
        this.parseServices(stats);
        this.renderView();
        this.attachListeners();
    }

    renderLoading() {
        this.container.innerHTML = `
        <!-- Sticky Health Header / Navigation Bar -->
        <div class="users-nav-bar health-nav-bar mb-3" id="health-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title">System Health</span>
                    <span class="tag is-info is-dark is-rounded charts-count-badge" id="healthCountBadge">Checking...</span>
                </div>
            </div>

            <div class="users-nav-right">
                <button type="button" class="button is-small is-dark is-outlined" disabled>↻ Refresh</button>
            </div>
        </div>

        <!-- Health Terminal Window -->
        <div class="users-window health-window" id="healthViewer">
            <div class="terminal-titlebar">
                <div class="terminal-dots">
                    <span class="terminal-dot dot-close"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div>
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span>health.system.threatco</span>
                </div>
                <div class="terminal-actions">
                    <span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>CHECKING...</span>
                </div>
            </div>

            <div class="terminal-table-container">
                <table class="terminal-table users-table health-table">
                    <thead>
                        <tr>
                            <th class="user-th-email">SERVICE</th>
                            <th class="user-th-role">STATUS</th>
                            <th class="user-th-services">UPTIME (RECENT)</th>
                            <th class="user-th-date">SAMPLES</th>
                            <th class="user-th-date">LAST CHECK</th>
                            <th class="user-th-actions">ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody id="healthTableBody">
                        <tr class="terminal-table-row">
                            <td colspan="6" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #64748b;">
                                <p class="has-text-info mb-2">Checking system health...</p>
                                <progress class="progress is-small is-info" max="100"></progress>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="terminal-statusbar">
                <span>Querying telemetry data...</span>
                <span class="is-pulled-right">threatco health • watchdog</span>
            </div>
        </div>`;
    }

    renderError() {
        this.container.innerHTML = `
        <div class="users-nav-bar health-nav-bar mb-3" id="health-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title">System Health</span>
                    <span class="tag is-danger is-dark is-rounded charts-count-badge" id="healthCountBadge">Error</span>
                </div>
            </div>

            <div class="users-nav-right">
                <button type="button" class="button is-small is-dark is-outlined" id="healthRefreshBtn" title="Retry health check">↻ Retry</button>
            </div>
        </div>

        <div class="users-window health-window" id="healthViewer">
            <div class="terminal-titlebar">
                <div class="terminal-dots">
                    <span class="terminal-dot dot-close"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div>
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span>health.system.threatco</span>
                </div>
                <div class="terminal-actions">
                    <span class="system-status-pill status-danger"><span class="status-indicator-dot dot-danger"></span>OFFLINE</span>
                </div>
            </div>

            <div class="terminal-table-container">
                <table class="terminal-table users-table health-table">
                    <thead>
                        <tr>
                            <th class="user-th-email">SERVICE</th>
                            <th class="user-th-role">STATUS</th>
                            <th class="user-th-services">UPTIME (RECENT)</th>
                            <th class="user-th-date">SAMPLES</th>
                            <th class="user-th-date">LAST CHECK</th>
                            <th class="user-th-actions">ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody id="healthTableBody">
                        <tr class="terminal-table-row">
                            <td colspan="6" class="terminal-placeholder" style="text-align: center; padding: 2.5rem; color: #ef4444;">Could not retrieve health stats.</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="terminal-statusbar">
                <span class="has-text-danger">Failed to retrieve health telemetry data.</span>
                <span class="is-pulled-right">threatco health • watchdog</span>
            </div>
        </div>`;

        document.getElementById('healthRefreshBtn')?.addEventListener('click', () => this.render());
    }

    parseServices(stats) {
        const DEGRADED_THRESHOLD = 0.2; // 20% failure rate
        this.servicesData = [];

        for (const key in stats) {
            if (key.startsWith('health-check-')) {
                const serviceName = key.replace('health-check-', '');
                const verboseHistory = stats[key] || [];

                const history = [];
                let lastTimestamp = null;
                if (Array.isArray(verboseHistory)) {
                    verboseHistory.forEach(entry => {
                        if (typeof entry === 'object' && entry !== null) {
                            if (entry.value !== undefined) {
                                history.push(entry.value);
                            } else if (entry.Value !== undefined) {
                                history.push(entry.Value);
                            }
                            const t = entry.time || entry.Time;
                            if (t) lastTimestamp = t;
                        } else if (typeof entry === 'number') {
                            history.push(entry);
                        }
                    });
                }

                let statusText = 'NO DATA';
                let statusClass = 'status-unknown';
                let dotClass = 'dot-unknown';
                let roleClass = 'role-user';
                let uptimePercentage = 'N/A';
                let isDown = false;
                let isDegraded = false;

                if (history.length > 0) {
                    const lastStatus = history[history.length - 1];
                    const totalChecks = history.length;
                    const failures = history.filter(s => s === 0).length;
                    const successRate = (totalChecks - failures) / totalChecks;
                    uptimePercentage = `${(successRate * 100).toFixed(1)}%`;

                    if (lastStatus === 0) {
                        statusText = 'DOWN';
                        statusClass = 'status-danger';
                        dotClass = 'dot-danger';
                        roleClass = 'role-down';
                        isDown = true;
                    } else {
                        const failureRate = failures / totalChecks;
                        if (failureRate > DEGRADED_THRESHOLD) {
                            statusText = 'DEGRADED';
                            statusClass = 'status-warning';
                            dotClass = 'dot-warning';
                            roleClass = 'role-degraded';
                            isDegraded = true;
                        } else {
                            statusText = 'UP';
                            statusClass = 'status-nominal';
                            dotClass = 'dot-nominal';
                            roleClass = 'role-up';
                        }
                    }
                }

                let lastCheckStr = '—';
                if (lastTimestamp) {
                    const d = new Date(lastTimestamp > 1e11 ? lastTimestamp : lastTimestamp * 1000);
                    if (!isNaN(d.getTime())) {
                        const pad = n => String(n).padStart(2, '0');
                        lastCheckStr = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
                    }
                }

                this.servicesData.push({
                    name: serviceName,
                    statusText,
                    statusClass,
                    dotClass,
                    roleClass,
                    uptimePercentage,
                    totalChecks: history.length,
                    lastCheckStr,
                    isDown,
                    isDegraded
                });
            }
        }

        this.servicesData.sort((a, b) => a.name.localeCompare(b.name));
    }

    getOverallStatus() {
        if (this.servicesData.some(s => s.isDown)) {
            return {
                text: 'OUTAGE DETECTED',
                statusClass: 'status-danger',
                dotClass: 'dot-danger'
            };
        }
        if (this.servicesData.some(s => s.isDegraded)) {
            return {
                text: 'SYSTEM DEGRADED',
                statusClass: 'status-warning',
                dotClass: 'dot-warning'
            };
        }
        if (this.servicesData.length > 0) {
            return {
                text: 'SYSTEM NOMINAL',
                statusClass: 'status-nominal',
                dotClass: 'dot-nominal'
            };
        }
        return {
            text: 'NO TELEMETRY',
            statusClass: 'status-unknown',
            dotClass: 'dot-unknown'
        };
    }

    renderView() {
        const overall = this.getOverallStatus();
        const totalServices = this.servicesData.length;
        const filtered = this.getFilteredServices();

        let countBadge = `${totalServices} services`;
        if (this.searchQuery) {
            countBadge = `${filtered.length} / ${totalServices} services`;
        }

        let uptimePill = '';
        if (this.uptimeData && this.uptimeData.uptime) {
            uptimePill = `<span class="service-meta-pill mr-2" title="Server start time: ${escapeHtml(this.uptimeData.start_time || '')}">UPTIME: ${escapeHtml(this.uptimeData.uptime)}</span>`;
        }

        const rowsHTML = this.buildTableRowsHTML(filtered);
        const statusText = this.buildStatusText(filtered.length);

        this.container.innerHTML = `
        <!-- Sticky Health Header / Navigation Bar -->
        <div class="users-nav-bar health-nav-bar mb-3" id="health-top">
            <div class="users-nav-left">
                <div class="users-nav-title-group">
                    <span class="users-nav-title">System Health</span>
                    <span class="tag is-info is-dark is-rounded charts-count-badge" id="healthCountBadge">${countBadge}</span>
                </div>
            </div>

            <div class="users-nav-right">
                <div class="field has-addons mb-0">
                    <div class="control">
                        <input id="healthSearchInput" name="q" type="text" class="input is-small terminal-search" placeholder="Search services..." value="${escapeHtml(this.searchQuery)}" autocomplete="off" />
                    </div>
                    <div class="control" id="healthClearControl" style="${this.searchQuery ? '' : 'display: none;'}">
                        <button type="button" class="button is-small is-dark" id="healthClearBtn" title="Clear filter">Clear</button>
                    </div>
                </div>
                <button type="button" class="button is-small is-dark is-outlined" id="healthRefreshBtn" title="Refresh health">↻ Refresh</button>
            </div>
        </div>

        <!-- Health Terminal Window -->
        <div class="users-window health-window" id="healthViewer">
            <div class="terminal-titlebar">
                <div class="terminal-dots">
                    <span class="terminal-dot dot-close"></span>
                    <span class="terminal-dot dot-min"></span>
                    <span class="terminal-dot dot-expand"></span>
                </div>
                <div class="terminal-title">
                    <span class="terminal-status-dot"></span>
                    <span>health.system.threatco</span>
                </div>
                <div class="terminal-actions">
                    ${uptimePill}
                    <span class="system-status-pill ${overall.statusClass}" id="healthOverallPill">
                        <span class="status-indicator-dot ${overall.dotClass}"></span>${overall.text}
                    </span>
                </div>
            </div>

            <div class="terminal-table-container">
                <table class="terminal-table users-table health-table">
                    <thead>
                        <tr>
                            <th class="user-th-email">SERVICE</th>
                            <th class="user-th-role">STATUS</th>
                            <th class="user-th-services">UPTIME (RECENT)</th>
                            <th class="user-th-date">SAMPLES</th>
                            <th class="user-th-date">LAST CHECK</th>
                            <th class="user-th-actions">ACTIONS</th>
                        </tr>
                    </thead>
                    <tbody id="healthTableBody">
                        ${rowsHTML}
                    </tbody>
                </table>
            </div>

            <div class="terminal-statusbar">
                <span id="healthStatusBarText">${statusText}</span>
                <span class="is-pulled-right">threatco health • watchdog</span>
            </div>
        </div>`;
    }

    getFilteredServices() {
        if (!this.searchQuery) return this.servicesData;
        const q = this.searchQuery.toLowerCase().trim();
        return this.servicesData.filter(s => s.name.toLowerCase().includes(q));
    }

    buildTableRowsHTML(services) {
        if (services.length === 0) {
            if (this.servicesData.length === 0) {
                return '<tr class="terminal-table-row"><td colspan="6" class="terminal-placeholder">No health check information available.</td></tr>';
            }
            return `<tr class="terminal-table-row"><td colspan="6" class="terminal-placeholder">No services matching "${escapeHtml(this.searchQuery)}" found.</td></tr>`;
        }

        return services.map(svc => `
        <tr class="terminal-table-row">
            <td class="user-cell-email">
                <span class="user-email-text">${escapeHtml(svc.name)}</span>
            </td>
            <td class="user-cell-role">
                <span class="role-badge ${svc.roleClass}">
                    <span class="status-indicator-dot ${svc.dotClass}" style="vertical-align: middle; margin-right: 4px;"></span>${svc.statusText}
                </span>
            </td>
            <td class="user-cell-services">
                ${svc.uptimePercentage !== 'N/A' 
                    ? `<div class="user-services-list"><span class="service-meta-pill">${svc.uptimePercentage}</span></div>` 
                    : `<span class="user-no-services">—</span>`}
            </td>
            <td class="user-cell-date">${svc.totalChecks > 0 ? `${svc.totalChecks} checks` : '—'}</td>
            <td class="user-cell-date">${svc.lastCheckStr}</td>
            <td class="user-cell-actions">
                <div class="user-action-group">
                    <button type="button" class="button is-small terminal-action-btn health-row-refresh-btn" data-service="${escapeHtml(svc.name)}" title="Refresh status">Refresh</button>
                </div>
            </td>
        </tr>`).join('');
    }

    buildStatusText(filteredCount) {
        const total = this.servicesData.length;
        let text = '';
        if (total === 0) {
            text = 'No monitored services found';
        } else if (this.searchQuery) {
            text = `Showing ${filteredCount} of ${total} services (filtered by "${escapeHtml(this.searchQuery)}")`;
        } else {
            text = `Showing ${total} monitored services`;
        }

        if (this.uptimeData && this.uptimeData.uptime) {
            text += ` • Server Uptime: ${escapeHtml(this.uptimeData.uptime)}`;
            if (this.uptimeData.start_time) {
                text += ` (started ${escapeHtml(this.uptimeData.start_time)})`;
            }
        }
        return text;
    }

    attachListeners() {
        const searchInput = document.getElementById('healthSearchInput');
        const clearBtn = document.getElementById('healthClearBtn');
        const refreshBtn = document.getElementById('healthRefreshBtn');

        searchInput?.addEventListener('input', (e) => {
            this.searchQuery = e.target.value;
            this.updateFilteredView();
        });

        clearBtn?.addEventListener('click', () => {
            this.searchQuery = '';
            if (searchInput) searchInput.value = '';
            this.updateFilteredView();
        });

        refreshBtn?.addEventListener('click', () => {
            this.render();
        });

        const tbody = document.getElementById('healthTableBody');
        tbody?.addEventListener('click', (e) => {
            const btn = e.target.closest('.health-row-refresh-btn');
            if (btn) {
                this.render();
            }
        });
    }

    updateFilteredView() {
        const filtered = this.getFilteredServices();
        const tbody = document.getElementById('healthTableBody');
        if (tbody) {
            tbody.innerHTML = this.buildTableRowsHTML(filtered);
        }

        const countBadge = document.getElementById('healthCountBadge');
        if (countBadge) {
            countBadge.textContent = this.searchQuery
                ? `${filtered.length} / ${this.servicesData.length} services`
                : `${this.servicesData.length} services`;
        }

        const statusBar = document.getElementById('healthStatusBarText');
        if (statusBar) {
            statusBar.innerHTML = this.buildStatusText(filtered.length);
        }

        const clearCtrl = document.getElementById('healthClearControl');
        if (clearCtrl) {
            clearCtrl.style.display = this.searchQuery ? '' : 'none';
        }
    }
}
