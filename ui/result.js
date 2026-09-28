"use strict";

const FileGuardResultUI = {

    elements: {
        screen: null,
        status: null,
        summary: null,
        findings: null
    },

    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.screen =
            document.getElementById(
                "screen-results"
            );

        this.elements.status =
            document.getElementById(
                "result-status"
            );

        this.elements.summary =
            document.getElementById(
                "result-summary"
            );

        this.elements.findings =
            document.getElementById(
                "result-findings"
            );

        this.initialized = true;
    },

    render(result) {
        this.init();

        if (
            !result ||
            typeof result !== "object"
        ) {
            return;
        }

        if (this.elements.status) {
            this.elements.status.textContent =
                this.getResultStatus(result);
        }

        this.renderSummary(result);

        if (
            window.FileGuardFindingsUI &&
            typeof window.FileGuardFindingsUI.render ===
                "function"
        ) {
            window.FileGuardFindingsUI.render(
                result.findings
            );
        }

        if (
            window.FileGuardWorkspace &&
            typeof window.FileGuardWorkspace.render ===
                "function"
        ) {
            window.FileGuardWorkspace.render(
                result
            );
        }
    },

    renderSummary(result) {
        if (!this.elements.summary) {
            return;
        }

        const file =
            result.file || {};

        const identity =
            result.identity || {};

        const detection =
            result.detection || {};

        const findingSummary =
            result.findingSummary ||
            this.createEmptyFindingSummary();

        const correlationSummary =
            result.correlationSummary ||
            this.createEmptyCorrelationSummary();

        const evidenceSummary =
            result.evidenceSummary ||
            this.createEmptyEvidenceSummary();

        const analyzerSummary =
            result.analyzers ||
            {};

        this.elements.summary.innerHTML = `
            <div class="file-summary">

                <div class="summary-item">
                    <span class="summary-label">
                        FILE
                    </span>

                    <span class="summary-value">
                        ${this.escapeHTML(
                            file.name || "UNKNOWN"
                        )}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        SIZE
                    </span>

                    <span class="summary-value">
                        ${this.formatBytes(
                            file.size
                        )}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        DETECTED FORMAT
                    </span>

                    <span class="summary-value">
                        ${this.escapeHTML(
                            detection.format ||
                            detection.formatId ||
                            identity.extension ||
                            "UNKNOWN"
                        )}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        FINDINGS
                    </span>

                    <span class="summary-value">
                        ${findingSummary.total || 0}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        HIGH
                    </span>

                    <span class="summary-value">
                        ${findingSummary.high || 0}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        MEDIUM
                    </span>

                    <span class="summary-value">
                        ${findingSummary.medium || 0}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        CORRELATIONS
                    </span>

                    <span class="summary-value">
                        ${correlationSummary.total || 0}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        EVIDENCE
                    </span>

                    <span class="summary-value">
                        ${evidenceSummary.total || 0}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        ANALYZERS
                    </span>

                    <span class="summary-value">
                        ${this.getAnalyzerList(
                            analyzerSummary
                        )}
                    </span>
                </div>


                <div class="summary-item">
                    <span class="summary-label">
                        DURATION
                    </span>

                    <span class="summary-value">
                        ${this.formatDuration(
                            result.durationMs
                        )}
                    </span>
                </div>

            </div>
        `;
    },

    getResultStatus(result) {
        if (
            result.status === "completed"
        ) {
            return "ANALYSIS COMPLETE";
        }

        if (
            result.status === "failed"
        ) {
            return "ANALYSIS FAILED";
        }

        if (result.status) {
            return String(
                result.status
            )
                .replace(
                    /[-_]+/g,
                    " "
                )
                .toUpperCase();
        }

        return "UNKNOWN";
    },

    getAnalyzerList(analyzers) {
        const active = [];

        if (analyzers.generic) {
            active.push(
                "GENERIC"
            );
        }

        if (analyzers.archive) {
            active.push(
                "ARCHIVE"
            );
        }

        if (analyzers.apk) {
            active.push(
                "APK"
            );
        }

        if (analyzers.correlation) {
            active.push(
                "CORRELATION"
            );
        }

        return active.length > 0
            ? this.escapeHTML(
                active.join(
                    " / "
                )
            )
            : "CORE";
    },

    createEmptyFindingSummary() {
        return {
            total: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        };
    },

    createEmptyCorrelationSummary() {
        return {
            total: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        };
    },

    createEmptyEvidenceSummary() {
        return {
            total: 0,
            high: 0,
            normal: 0
        };
    },

    formatBytes(bytes) {
        if (
            typeof bytes !== "number" ||
            !Number.isFinite(bytes) ||
            bytes < 0
        ) {
            return "—";
        }

        if (bytes === 0) {
            return "0 B";
        }

        const units = [
            "B",
            "KB",
            "MB",
            "GB",
            "TB"
        ];

        const exponent =
            Math.min(
                Math.floor(
                    Math.log(bytes) /
                    Math.log(1024)
                ),
                units.length - 1
            );

        const value =
            bytes /
            Math.pow(
                1024,
                exponent
            );

        const rounded =
            exponent === 0
                ? Math.round(value)
                : value.toFixed(
                    value >= 100
                        ? 0
                        : value >= 10
                            ? 1
                            : 2
                );

        return `${rounded} ${units[exponent]}`;
    },

    formatDuration(
        durationMs
    ) {
        if (
            typeof durationMs !== "number" ||
            !Number.isFinite(durationMs) ||
            durationMs < 0
        ) {
            return "—";
        }

        if (
            durationMs < 1000
        ) {
            return `${Math.round(
                durationMs
            )} ms`;
        }

        return `${(
            durationMs / 1000
        ).toFixed(2)} s`;
    },

    escapeHTML(value) {
        if (
            value === null ||
            value === undefined
        ) {
            return "";
        }

        return String(value)
            .replace(
                /&/g,
                "&amp;"
            )
            .replace(
                /</g,
                "&lt;"
            )
            .replace(
                />/g,
                "&gt;"
            )
            .replace(
                /"/g,
                "&quot;"
            )
            .replace(
                /'/g,
                "&#039;"
            );
    },

    hide() {
        this.init();

        if (this.elements.screen) {
            this.elements.screen.hidden =
                true;

            this.elements.screen.setAttribute(
                "aria-hidden",
                "true"
            );
        }
    }
};

window.FileGuardResultUI =
    FileGuardResultUI;
