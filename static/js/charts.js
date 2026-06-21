/**
 * ClearCage — ApexCharts helpers
 * Pre-configured chart builders for the dashboard.
 */

const ClearCageCharts = {
    // Color palette matching daisyUI dark theme
    COLORS: ["#4ade80", "#facc15", "#f87171", "#ef4444", "#6366f1", "#06b6d4"],

    /**
     * Create a donut chart for verdict distribution.
     * @param {string} containerId - HTML element ID
     * @param {Object} data - {category: count, ...}
     */
    donut(containerId, data) {
        const entries = Object.entries(data);
        new ApexCharts(document.getElementById(containerId), {
            chart: { type: "donut", height: 250 },
            labels: entries.map(([k]) => k.charAt(0).toUpperCase() + k.slice(1)),
            series: entries.map(([, v]) => v),
            colors: this.COLORS,
            legend: { position: "bottom" },
        }).render();
    },

    /**
     * Create a bar chart for status breakdown.
     * @param {string} containerId - HTML element ID
     * @param {Object} data - {status: count, ...}
     */
    bar(containerId, data) {
        const entries = Object.entries(data);
        new ApexCharts(document.getElementById(containerId), {
            chart: { type: "bar", height: 250 },
            series: [{ name: "Count", data: entries.map(([, v]) => v) }],
            xaxis: { categories: entries.map(([k]) => k.charAt(0).toUpperCase() + k.slice(1)) },
            plotOptions: { bar: { horizontal: false, borderRadius: 4 } },
            colors: [this.COLORS[4]],
        }).render();
    },

    /**
     * Create a line chart for analysis trends over time.
     * @param {string} containerId - HTML element ID
     * @param {Array} data - [{date, count}, ...]
     */
    trend(containerId, data) {
        new ApexCharts(document.getElementById(containerId), {
            chart: { type: "area", height: 250 },
            series: [{ name: "Analyses", data: data.map(d => d.count) }],
            xaxis: { categories: data.map(d => d.date) },
            colors: [this.COLORS[4]],
            stroke: { curve: "smooth" },
            fill: { type: "gradient", gradient: { opacityFrom: 0.6, opacityTo: 0.1 } },
        }).render();
    },
};
