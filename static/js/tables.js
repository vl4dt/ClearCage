/**
 * ClearCage — Tabulator helpers
 * Pre-configured table builders for history and dashboard.
 */

const ClearCageTables = {
    /**
     * Standard verdict badge formatter.
     */
    verdictFormatter(cell) {
        const v = cell.getValue();
        if (!v) return '<span class="text-base-content/40">—</span>';
        const colors = {
            clean: "text-success",
            suspicious: "text-warning",
            malicious: "text-error",
            critical: "text-error",
        };
        return `<span class="${colors[v.category] || ''}">${v.category} (${v.score})</span>`;
    },

    /**
     * Standard status badge formatter.
     */
    statusFormatter(cell) {
        const colors = {
            queued: "badge-ghost",
            running: "badge-info",
            complete: "badge-success",
            failed: "badge-error",
        };
        return `<span class="badge ${colors[cell.getValue()] || 'badge-ghost'}">${cell.getValue()}</span>`;
    },

    /**
     * Standard type badge formatter.
     */
    typeFormatter(cell) {
        const v = cell.getValue();
        return v === "file"
            ? '<span class="badge badge-primary">File</span>'
            : '<span class="badge badge-secondary">URL</span>';
    },

    /**
     * ISO date to locale string formatter.
     */
    dateFormatter(cell) {
        return cell.getValue() ? new Date(cell.getValue()).toLocaleString() : '';
    },

    /**
     * Build a standard analysis history table.
     * @param {string} containerId - HTML element ID
     * @param {Array} items - Analysis items from API
     */
    history(containerId, items) {
        return new Tabulator(containerId, {
            data: items || [],
            columns: [
                {
                    title: "ID", field: "id", width: 120, formatter: "link",
                    formatterParams: { url: "/analysis/{value}", target: "_blank" },
                },
                { title: "Type", field: "type", width: 80, hozAlign: "center", formatter: this.typeFormatter },
                { title: "Target", field: "target", minWidth: 200, tooltip: true },
                { title: "Status", field: "status", width: 100, hozAlign: "center", formatter: this.statusFormatter },
                { title: "Verdict", field: "verdict", width: 150, formatter: this.verdictFormatter },
                { title: "Created", field: "created_at", width: 160, formatter: this.dateFormatter },
            ],
            layout: "fitColumns",
            placeholder: "No analyses found",
        });
    },
};
