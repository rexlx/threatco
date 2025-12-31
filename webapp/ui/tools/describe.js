export class DescribeTool {
    constructor(app) {
        this.app = app;
        this.currentData = null; // Store parsed data for charting
        this.chartInstance = null; // Store ECharts instance
    }

    render() {
        return `
        <div id="tool-describe" class="block" style="scroll-margin-top: 80px;">
            <h4 class="title is-4 has-text-white">CSV Statistics & Visualization</h4>
            <p class="has-text-grey-light mb-4">Generate descriptive statistics and histograms for CSV data.</p>

            <div class="columns">
                <div class="column">
                    <div class="field">
                        <label class="label has-text-grey-light">Upload CSV</label>
                        <div class="file has-name is-fullwidth is-info">
                            <label class="file-label">
                                <input class="file-input" type="file" id="fileUploadDescribe" accept=".csv, .txt">
                                <span class="file-cta">
                                    <span class="file-icon">
                                        <i class="material-icons">upload_file</i>
                                    </span>
                                    <span class="file-label">
                                        Choose a file…
                                    </span>
                                </span>
                                <span class="file-name" id="fileNameDescribe">
                                    No file selected
                                </span>
                            </label>
                        </div>
                    </div>

                    <div class="field">
                        <label class="label has-text-grey-light">Raw Input</label>
                        <div class="control">
                            <textarea class="textarea has-background-dark has-text-white" id="inputDescribe" rows="6" placeholder="Paste csv data here or upload a file..."></textarea>
                        </div>
                    </div>
                    <button class="button is-info is-light is-fullwidth" id="btnRunDescribe">
                        <span class="icon"><i class="material-icons">analytics</i></span>
                        <span>Calculate & Visualize</span>
                    </button>
                </div>
            </div>

            <div class="field is-hidden" id="describeResultsContainer">
                <label class="label has-text-grey-light">Statistics</label>
                <div class="table-container">
                    <table class="table is-fullwidth is-bordered is-striped has-background-dark has-text-white" id="describeTable">
                        </table>
                </div>

                <div class="box has-background-dark mt-5">
                    <div class="level is-mobile">
                        <div class="level-left">
                            <h5 class="title is-5 has-text-info mb-0">Histogram</h5>
                        </div>
                        <div class="level-right">
                            <div class="field">
                                <div class="control has-icons-left">
                                    <div class="select is-small is-info">
                                        <select id="chartColumnSelect">
                                            <option disabled selected>Select Column</option>
                                        </select>
                                    </div>
                                    <span class="icon is-small is-left">
                                        <i class="material-icons">bar_chart</i>
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div id="describeChart" style="width: 100%; height: 400px;"></div>
                </div>
            </div>
        </div>`;
    }

    attachListeners() {
        const btn = document.getElementById('btnRunDescribe');
        if (btn) {
            btn.addEventListener('click', () => this.processData());
        }

        const fileInput = document.getElementById('fileUploadDescribe');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFileUpload(e));
        }

        const chartSelect = document.getElementById('chartColumnSelect');
        if (chartSelect) {
            chartSelect.addEventListener('change', (e) => {
                this.renderHistogram(e.target.value);
            });
        }
        
        // Handle window resize for responsive charts
        window.addEventListener('resize', () => {
            if (this.chartInstance) {
                this.chartInstance.resize();
            }
        });
    }

    handleFileUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        document.getElementById('fileNameDescribe').textContent = file.name;

        const reader = new FileReader();
        reader.onload = (e) => {
            const textArea = document.getElementById('inputDescribe');
            if (textArea) textArea.value = e.target.result;
        };
        reader.readAsText(file);
    }

    processData() {
        const input = document.getElementById('inputDescribe').value.trim();
        const container = document.getElementById('describeResultsContainer');
        const table = document.getElementById('describeTable');
        
        if (!input) {
            alert("Please provide CSV input.");
            return;
        }

        try {
            // Parse CSV
            const { headers, columns } = this.parseCSV(input);
            this.currentData = columns; // Store for charting

            // Calculate Stats
            const stats = this.calculateStats(headers, columns);
            
            // Render Table
            this.renderTable(table, stats);
            
            // Populate Chart Selector
            this.populateChartSelector(Object.keys(stats));

            // Show Results
            container.classList.remove('is-hidden');

            // Render initial chart (first valid column)
            const validCols = Object.keys(stats);
            if (validCols.length > 0) {
                document.getElementById('chartColumnSelect').value = validCols[0];
                this.renderHistogram(validCols[0]);
            }

        } catch (e) {
            alert("Error processing CSV: " + e.message);
            console.error(e);
        }
    }

    populateChartSelector(validColumns) {
        const select = document.getElementById('chartColumnSelect');
        select.innerHTML = '';
        validColumns.forEach(col => {
            const option = document.createElement('option');
            option.value = col;
            option.textContent = col;
            select.appendChild(option);
        });
    }

    renderHistogram(columnName) {
        if (!this.currentData || !this.currentData[columnName]) return;
        
        const data = this.currentData[columnName];
        const chartDom = document.getElementById('describeChart');
        
        if (!window.echarts) {
            chartDom.innerHTML = '<p class="has-text-danger">ECharts library not loaded. Please include echarts.min.js in index.html</p>';
            return;
        }

        if (this.chartInstance) {
            this.chartInstance.dispose();
        }
        this.chartInstance = echarts.init(chartDom, 'dark');

        // Calculate Bins (Square Root Rule)
        const binCount = Math.ceil(Math.sqrt(data.length));
        const min = Math.min(...data);
        const max = Math.max(...data);
        
        // Generate histogram data
        const binWidth = (max - min) / binCount;
        const bins = [];
        const counts = new Array(binCount).fill(0);

        // Initialize x-axis labels
        for (let i = 0; i < binCount; i++) {
            const start = min + (i * binWidth);
            const end = min + ((i + 1) * binWidth);
            bins.push(`${start.toFixed(2)}-${end.toFixed(2)}`);
        }

        // Fill buckets
        data.forEach(val => {
            let idx = Math.floor((val - min) / binWidth);
            if (idx >= binCount) idx = binCount - 1;
            counts[idx]++;
        });

        const option = {
            backgroundColor: 'transparent',
            tooltip: {
                trigger: 'axis',
                axisPointer: { type: 'shadow' }
            },
            grid: {
                left: '3%', right: '4%', bottom: '3%', containLabel: true
            },
            xAxis: {
                type: 'category',
                data: bins,
                axisLabel: { color: '#ccc', rotate: 30 },
                axisLine: { lineStyle: { color: '#555' } }
            },
            yAxis: {
                type: 'value',
                axisLabel: { color: '#ccc' },
                splitLine: { lineStyle: { color: '#333' } }
            },
            series: [{
                name: 'Frequency',
                type: 'bar',
                data: counts,
                itemStyle: { color: '#3298dc' }, // Bulma info color
                barWidth: '90%'
            }]
        };

        this.chartInstance.setOption(option);
    }

    parseCSV(text) {
        const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
        if (lines.length < 2) throw new Error("Not enough data rows");

        const headers = lines[0].split(',').map(h => h.trim());
        const columns = {};
        
        headers.forEach(h => columns[h] = []);

        for (let i = 1; i < lines.length; i++) {
            const row = lines[i].split(',');
            if (row.length !== headers.length) continue; 

            row.forEach((val, idx) => {
                const num = parseFloat(val.trim());
                if (!isNaN(num)) {
                    columns[headers[idx]].push(num);
                }
            });
        }
        return { headers, columns };
    }

    calculateStats(headers, columns) {
        const results = {};
        headers.forEach(header => {
            const data = columns[header].sort((a, b) => a - b);
            if (data.length === 0) return; 

            const count = data.length;
            const sum = data.reduce((a, b) => a + b, 0);
            const mean = sum / count;
            
            const squareDiffs = data.map(val => Math.pow(val - mean, 2));
            const avgSquareDiff = squareDiffs.reduce((a, b) => a + b, 0) / (count > 1 ? count - 1 : 1); 
            const std = Math.sqrt(avgSquareDiff);

            results[header] = {
                count: count,
                mean: mean,
                std: std,
                min: data[0],
                '25%': this.getPercentile(data, 0.25),
                '50%': this.getPercentile(data, 0.50),
                '75%': this.getPercentile(data, 0.75),
                max: data[data.length - 1]
            };
        });
        return results;
    }

    getPercentile(sortedData, q) {
        const pos = (sortedData.length - 1) * q;
        const base = Math.floor(pos);
        const rest = pos - base;
        if ((sortedData[base + 1] !== undefined)) {
            return sortedData[base] + rest * (sortedData[base + 1] - sortedData[base]);
        } else {
            return sortedData[base];
        }
    }

    renderTable(table, stats) {
        const metrics = ['count', 'mean', 'std', 'min', '25%', '50%', '75%', 'max'];
        const validCols = Object.keys(stats);

        if (validCols.length === 0) {
            table.innerHTML = '<thead><tr><th>No numerical data found</th></tr></thead>';
            return;
        }

        let html = `<thead><tr><th class="has-text-info">Metric</th>`;
        validCols.forEach(col => {
            html += `<th class="has-text-info">${col}</th>`;
        });
        html += `</tr></thead><tbody>`;

        metrics.forEach(metric => {
            html += `<tr><td class="has-text-grey-light has-text-weight-bold">${metric}</td>`;
            validCols.forEach(col => {
                let val = stats[col][metric];
                if (typeof val === 'number') {
                    val = metric === 'count' ? val : val.toFixed(4);
                }
                html += `<td class="has-text-white">${val}</td>`;
            });
            html += `</tr>`;
        });
        html += `</tbody>`;
        table.innerHTML = html;
    }
}