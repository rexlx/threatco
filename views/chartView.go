package views

var ChartsViewSection = `<section class="section has-background-black charts-section" style="padding-top: 1rem; padding-bottom: 3rem;">
	<div class="container is-fluid">
		<!-- Sticky Chart Navigation Bar -->
		<div class="charts-nav-bar" id="charts-top">
			<div class="charts-nav-left">
				<div class="charts-nav-title-group">
					<span class="charts-nav-title">System Metrics</span>
					<span class="tag is-info is-dark is-rounded charts-count-badge" id="chartCountBadge">%d charts</span>
				</div>
			</div>

			<div class="charts-nav-center">
				<div class="field has-addons mb-0">
					<div class="control">
						<span class="button is-small is-dark is-static charts-jump-label">
							Jump to:
						</span>
					</div>
					<div class="control">
						<div class="select is-small is-info">
							<select id="chartNavSelect" aria-label="Select a chart to navigate to">
								<option value="">-- Select a chart --</option>
								%s
							</select>
						</div>
					</div>
					<div class="control">
						<button type="button" id="prevChartBtn" class="button is-small is-dark" title="Previous chart">‹</button>
					</div>
					<div class="control">
						<button type="button" id="nextChartBtn" class="button is-small is-dark" title="Next chart">›</button>
					</div>
				</div>

				<div class="buttons has-addons mb-0 charts-mode-buttons">
					<button type="button" id="viewAllChartsBtn" class="button is-small is-primary is-selected">All</button>
					<button type="button" id="viewSingleChartBtn" class="button is-small is-dark" title="Focus only on selected chart">Focus</button>
				</div>
			</div>

			<div class="charts-nav-right">
				<button type="button" id="backToTopBtn" class="button is-small is-dark is-outlined" title="Scroll to top">↑ Top</button>
				<button type="button" class="button is-small is-dark is-outlined" onclick="window.location.reload()" title="Refresh metrics">↻ Refresh</button>
			</div>
		</div>

		<!-- Charts Container -->
		<div id="chartsContainer" class="charts-container">
			%s
		</div>
	</div>
</section>

<script>
(function() {
    function initChartNav() {
        const select = document.getElementById('chartNavSelect');
        const prevBtn = document.getElementById('prevChartBtn');
        const nextBtn = document.getElementById('nextChartBtn');
        const viewAllBtn = document.getElementById('viewAllChartsBtn');
        const viewSingleBtn = document.getElementById('viewSingleChartBtn');
        const backToTopBtn = document.getElementById('backToTopBtn');
        const container = document.getElementById('chartsContainer');
        if (!select || !container) return;

        const chartCards = Array.from(container.querySelectorAll('.chart-card-wrapper'));
        if (chartCards.length === 0) return;

        let isFocusMode = false;

        function getChartDom(card) {
            return card.querySelector('.item');
        }

        function resizeChart(card) {
            const dom = getChartDom(card);
            if (dom && window.echarts) {
                const instance = window.echarts.getInstanceByDom(dom);
                if (instance) instance.resize();
            }
        }

        function highlightCard(card) {
            card.classList.add('chart-highlight');
            setTimeout(() => card.classList.remove('chart-highlight'), 1800);
        }

        function navigateToChart(chartId, focus = false) {
            if (!chartId) return;
            const target = document.getElementById(chartId);
            if (!target) return;

            select.value = chartId;

            if (focus || isFocusMode) {
                isFocusMode = true;
                viewSingleBtn.classList.add('is-primary', 'is-selected');
                viewSingleBtn.classList.remove('is-dark');
                viewAllBtn.classList.remove('is-primary', 'is-selected');
                viewAllBtn.classList.add('is-dark');

                chartCards.forEach(c => {
                    if (c.id === chartId) {
                        c.style.display = 'block';
                        resizeChart(c);
                        highlightCard(c);
                        c.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    } else {
                        c.style.display = 'none';
                    }
                });
            } else {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                highlightCard(target);
            }

            try {
                history.replaceState(null, null, '#' + chartId);
            } catch (e) {}
        }

        function showAll() {
            isFocusMode = false;
            chartCards.forEach(c => {
                c.style.display = 'block';
                resizeChart(c);
            });
            viewAllBtn.classList.add('is-primary', 'is-selected');
            viewAllBtn.classList.remove('is-dark');
            viewSingleBtn.classList.remove('is-primary', 'is-selected');
            viewSingleBtn.classList.add('is-dark');

            if (select.value) {
                const target = document.getElementById(select.value);
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    highlightCard(target);
                }
            }
        }

        select.addEventListener('change', (e) => {
            const val = e.target.value;
            if (val) {
                navigateToChart(val, isFocusMode);
            } else {
                showAll();
            }
        });

        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                const options = Array.from(select.options).filter(o => o.value !== "");
                if (options.length === 0) return;
                let curIdx = options.findIndex(o => o.value === select.value);
                if (curIdx <= 0) {
                    curIdx = options.length - 1;
                } else {
                    curIdx--;
                }
                navigateToChart(options[curIdx].value, isFocusMode);
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                const options = Array.from(select.options).filter(o => o.value !== "");
                if (options.length === 0) return;
                let curIdx = options.findIndex(o => o.value === select.value);
                if (curIdx < 0 || curIdx >= options.length - 1) {
                    curIdx = 0;
                } else {
                    curIdx++;
                }
                navigateToChart(options[curIdx].value, isFocusMode);
            });
        }

        if (viewAllBtn) {
            viewAllBtn.addEventListener('click', () => {
                showAll();
            });
        }

        if (viewSingleBtn) {
            viewSingleBtn.addEventListener('click', () => {
                let targetId = select.value;
                if (!targetId && chartCards.length > 0) {
                    targetId = chartCards[0].id;
                }
                if (targetId) {
                    navigateToChart(targetId, true);
                }
            });
        }

        if (backToTopBtn) {
            backToTopBtn.addEventListener('click', () => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        }

        // Handle per-card Focus buttons
        document.querySelectorAll('.focus-this-chart-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('data-target');
                if (targetId) {
                    navigateToChart(targetId, true);
                }
            });
        });

        // Check URL hash or query param on page load
        let initialTarget = '';
        const urlParams = new URLSearchParams(window.location.search);
        const queryChart = urlParams.get('chart');
        if (queryChart) {
            initialTarget = queryChart.startsWith('chart-') ? queryChart : 'chart-' + queryChart;
        } else if (window.location.hash) {
            initialTarget = window.location.hash.substring(1);
        }

        if (initialTarget && document.getElementById(initialTarget)) {
            setTimeout(() => {
                navigateToChart(initialTarget, false);
            }, 100);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initChartNav);
    } else {
        initChartNav();
    }
})();
</script>
`

var ChartsEmptySection = `<section class="section has-background-black" style="min-height: 75vh; display: flex; align-items: center; justify-content: center;">
	<div class="container" style="max-width: 620px;">
		<div class="box has-background-custom has-text-centered" style="border: 1px solid rgba(56, 189, 248, 0.25); padding: 3rem 2rem; box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5);">
			<span style="font-size: 2.75rem; display: block; margin-bottom: 1rem;">📊</span>
			<h2 class="title is-4 has-text-info">No Chart Data Available</h2>
			<p class="has-text-grey-light mb-5">The server collects runtime statistics at periodic intervals. Please allow a few collection cycles to occur before charts are displayed.</p>
			<button type="button" class="button is-small is-primary is-outlined" onclick="window.location.reload()">Check Again</button>
		</div>
	</div>
</section>`
