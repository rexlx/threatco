package views

// ServicesViewSection defines the modern terminal-styled layout for the services directory and news advisories.
var ServicesViewSection = `<section class="section has-background-black services-section" style="padding-top: 1rem; padding-bottom: 3rem;">
	<div class="container is-fluid">
		<!-- Sticky Services Header / Navigation Bar -->
		<div class="services-nav-bar" id="services-top">
			<div class="services-nav-left">
				<div class="services-nav-title-group">
					<span class="services-nav-title">Threat Intelligence Services</span>
					<span class="tag is-info is-dark is-rounded charts-count-badge" id="serviceCountBadge">%d services</span>
					<span class="tag is-dark is-rounded charts-count-badge" id="serviceTypeCountBadge">%d types</span>
				</div>
			</div>

			<div class="services-nav-right">
				<div class="field has-addons mb-0">
					<div class="control">
						<input id="serviceSearchInput" type="text" class="input is-small terminal-search" placeholder="Filter services or IOC types (e.g. virustotal, sha256)..." autocomplete="off" />
					</div>
					<div class="control">
						<button type="button" id="clearServiceFilterBtn" class="button is-small is-dark" title="Clear search">Clear</button>
					</div>
				</div>
				<button type="button" class="button is-small is-dark is-outlined" onclick="window.location.reload()" title="Refresh services">↻ Refresh</button>
			</div>
		</div>

		<!-- Services List Container -->
		<div class="services-window" id="serviceViewer">
			<div class="terminal-titlebar">
				<div class="terminal-dots">
					<span class="terminal-dot dot-close"></span>
					<span class="terminal-dot dot-min"></span>
					<span class="terminal-dot dot-expand"></span>
				</div>
				<div class="terminal-title">
					<span class="terminal-status-dot"></span>
					<span>services.registry.threatco</span>
				</div>
				<div class="terminal-actions">
					<span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>CONNECTORS LIVE</span>
				</div>
			</div>

			<div class="services-list" id="servicesList">
				%s
				<div id="servicesEmptyState" class="terminal-placeholder" style="display: none;">
					No services match the current filter query.
				</div>
			</div>

			<div class="terminal-statusbar">
				<span id="serviceSummaryText">Showing %d of %d registered services</span>
				<span class="is-pulled-right">threatco runtime • active</span>
			</div>
		</div>

		<!-- News & Advisories Section -->
		<div class="news-window mt-5" id="news">
			<div class="terminal-titlebar">
				<div class="terminal-dots">
					<span class="terminal-dot dot-close"></span>
					<span class="terminal-dot dot-min"></span>
					<span class="terminal-dot dot-expand"></span>
				</div>
				<div class="terminal-title">
					<span class="terminal-status-dot"></span>
					<span>threatco-bulletins.broadcast</span>
				</div>
				<div class="terminal-actions">
					<span class="tag is-info is-dark is-rounded charts-count-badge">SYSTEM ADVISORY</span>
				</div>
			</div>

			<div class="news-body">
				<div class="news-entry">
					<div class="news-entry-header">
						<div class="news-meta-left">
							<span class="news-badge is-advisory">BULLETIN</span>
							<span class="news-date">26 JUN 2025</span>
							<span class="news-headline">Threat Intelligence Engine & Connectors Operational</span>
						</div>
						<span class="system-status-pill status-nominal"><span class="status-indicator-dot dot-nominal"></span>ONLINE</span>
					</div>
					<div class="news-entry-content">
						All core threat intelligence connectors, normalization routines, and enrichment pipelines are operational. Review the registered service capabilities above for supported IOC selectors (hashes, IPv4/IPv6, domains, URLs, and CVEs). Click any IOC type badge above to filter services by analytical capability.
					</div>
					<div class="news-entry-footer">
						<span>Cluster: <code>production-primary</code></span>
						<span>Subsystem: <code>intel-connectors</code></span>
						<span>Security Protocol: <code>verified</code></span>
					</div>
				</div>
			</div>

			<div class="terminal-statusbar">
				<span>Channel: broadcast • threatco security operations</span>
				<span class="is-pulled-right">threatco runtime • active</span>
			</div>
		</div>
	</div>
</section>

<script>
(function() {
	function initServicesSearch() {
		const input = document.getElementById('serviceSearchInput');
		const clearBtn = document.getElementById('clearServiceFilterBtn');
		const countBadge = document.getElementById('serviceCountBadge');
		const summaryText = document.getElementById('serviceSummaryText');
		const rows = Array.from(document.querySelectorAll('.service-row-item'));
		const emptyState = document.getElementById('servicesEmptyState');
		if (!input || rows.length === 0) return;

		const totalCount = rows.length;

		function filterServices() {
			const query = input.value.trim().toLowerCase();
			let visibleCount = 0;

			rows.forEach(row => {
				const searchData = (row.getAttribute('data-search') || '').toLowerCase();
				const isMatch = !query || searchData.includes(query);
				if (isMatch) {
					row.style.display = '';
					visibleCount++;
				} else {
					row.style.display = 'none';
				}
			});

			if (countBadge) {
				countBadge.textContent = query ? visibleCount + ' / ' + totalCount : totalCount + ' services';
			}
			if (summaryText) {
				summaryText.textContent = query
					? 'Showing ' + visibleCount + ' of ' + totalCount + ' registered services (filtered)'
					: 'Showing ' + totalCount + ' of ' + totalCount + ' registered services';
			}
			if (emptyState) {
				emptyState.style.display = visibleCount === 0 ? 'block' : 'none';
			}
		}

		input.addEventListener('input', filterServices);

		if (clearBtn) {
			clearBtn.addEventListener('click', () => {
				input.value = '';
				filterServices();
				input.focus();
			});
		}

		document.querySelectorAll('.service-type-pill').forEach(pill => {
			pill.addEventListener('click', function(e) {
				e.stopPropagation();
				const typeText = this.getAttribute('data-type') || this.textContent.trim();
				input.value = typeText;
				filterServices();
				input.focus();
			});
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initServicesSearch);
	} else {
		initServicesSearch();
	}
})();
</script>
`

// ViewSection is preserved for backwards compatibility with any legacy callers.
var ViewSection string = ServicesViewSection
