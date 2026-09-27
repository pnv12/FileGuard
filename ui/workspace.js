"use strict";

const FileGuardWorkspaceUI = {
    elements: {
        workspace: null,
        tabs: null,
        panels: null
    },

    initialized: false,

    currentPanel: "overview",

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.workspace =
            document.querySelector(".workspace");

        this.elements.tabs =
            document.querySelector(".workspace-tabs");

        this.elements.panels =
            document.querySelector(".workspace-content");

        this.bindEvents();

        this.initialized = true;
    },

    bindEvents() {
        if (!this.elements.tabs) {
            return;
        }

        this.elements.tabs.addEventListener(
            "click",
            (event) => {
                const tab =
                    event.target.closest(
                        ".workspace-tab"
                    );

                if (!tab) {
                    return;
                }

                const panel =
                    tab.dataset.panel;

                if (!panel) {
                    return;
                }

                document.dispatchEvent(
                    new CustomEvent(
                        "fileguard:workspace-tab-selected",
                        {
                            detail: {
                                panel
                            }
                        }
                    )
                );
            }
        );
    },

    render(result) {
        this.init();

        if (
            !result ||
            typeof result !== "object"
        ) {
            return;
        }

        this.renderOverview(result);
        this.renderIdentity(result);
        this.renderStructure(result);
        this.renderSecurity(result);
        this.renderNetwork(result);
        this.renderMetadata(result);
        this.renderFiles(result);

        if (
            window.FileGuardEvidenceUI &&
            typeof window.FileGuardEvidenceUI.render ===
                "function"
        ) {
            window.FileGuardEvidenceUI.render(
                result.evidence
            );
        }

        this.showPanel(
            this.currentPanel
        );
    },

    showPanel(panelName) {
        this.init();

        if (
            typeof panelName !== "string" ||
            panelName.length === 0
        ) {
            panelName = "overview";
        }

        this.currentPanel = panelName;

        const tabs =
            document.querySelectorAll(
                ".workspace-tab"
            );

        tabs.forEach((tab) => {
            tab.classList.toggle(
                "active",
                tab.dataset.panel === panelName
            );
        });

        const panels =
            document.querySelectorAll(
                ".workspace-panel"
            );

        panels.forEach((panel) => {
            const active =
                panel.dataset.panelContent ===
                panelName;

            panel.classList.toggle(
                "active",
                active
            );

            panel.hidden = !active;
        });
    },

    renderOverview(result) {
        const container =
            this.getPanel("overview");

        if (!container) {
            return;
        }

        const findingSummary =
            result.findingSummary ||
            {};

        const correlationSummary =
            result.correlationSummary ||
            {};

        const evidenceSummary =
            result.evidenceSummary ||
            {};

        const detection =
            result.detection ||
            {};

        const plan =
            result.analysisPlan ||
            {};

        container.innerHTML = `
            <div class="workspace-section">

                <div class="workspace-section-label">
                    OVERVIEW
                </div>

                <div class="workspace-grid">

                    ${this.renderValue(
                        "STATUS",
                        this.formatValue(
                            result.status
                        )
                    )}

                    ${this.renderValue(
                        "FORMAT",
                        this.formatValue(
                            detection.format ||
                            detection.formatId ||
                            result.identity?.extension
                        )
                    )}

                    ${this.renderValue(
                        "CONFIDENCE",
                        this.formatValue(
                            detection.confidenceLevel
                        )
                    )}

                    ${this.renderValue(
                        "FINDINGS",
                        findingSummary.total
                    )}

                    ${this.renderValue(
                        "HIGH",
                        findingSummary.high
                    )}

                    ${this.renderValue(
                        "MEDIUM",
                        findingSummary.medium
                    )}

                    ${this.renderValue(
                        "LOW",
                        findingSummary.low
                    )}

                    ${this.renderValue(
                        "CORRELATIONS",
                        correlationSummary.total
                    )}

                    ${this.renderValue(
                        "EVIDENCE",
                        evidenceSummary.total
                    )}

                    ${this.renderValue(
                        "DURATION",
                        this.formatDuration(
                            result.durationMs
                        )
                    )}

                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    ANALYSIS PLAN
                </div>

                <div class="workspace-list">

                    ${this.renderListValue(
                        "ENABLED ANALYZERS",
                        plan.enabledAnalyzers
                    )}

                    ${this.renderListValue(
                        "REASONS",
                        plan.reasons
                    )}

                </div>

            </div>


            <div class="workspace-note">

                FileGuard reports observed characteristics
                and evidence. A finding is not, by itself,
                proof that a file is malicious.

            </div>
        `;
    },

    renderIdentity(result) {
        const container =
            this.getPanel("identity");

        if (!container) {
            return;
        }

        const identity =
            result.identity ||
            {};

        const file =
            result.file ||
            {};

        const hashes =
            result.hashes ||
            {};

        container.innerHTML = `
            <div class="workspace-section">

                <div class="workspace-section-label">
                    FILE IDENTITY
                </div>

                <div class="workspace-grid">

                    ${this.renderValue(
                        "NAME",
                        file.name
                    )}

                    ${this.renderValue(
                        "SIZE",
                        this.formatBytes(
                            file.size
                        )
                    )}

                    ${this.renderValue(
                        "EXTENSION",
                        identity.extension
                    )}

                    ${this.renderValue(
                        "MIME TYPE",
                        identity.mimeType ||
                        file.type
                    )}

                    ${this.renderValue(
                        "DETECTED FORMAT",
                        result.detection?.format ||
                        result.detection?.formatId
                    )}

                    ${this.renderValue(
                        "LAST MODIFIED",
                        this.formatDate(
                            file.lastModified
                        )
                    )}

                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    CRYPTOGRAPHIC HASHES
                </div>

                <div class="workspace-list">

                    ${this.renderHash(
                        "SHA-256",
                        hashes.sha256
                    )}

                    ${this.renderHash(
                        "SHA-384",
                        hashes.sha384
                    )}

                    ${this.renderHash(
                        "SHA-512",
                        hashes.sha512
                    )}

                </div>

            </div>
        `;
    },

    renderStructure(result) {
        const container =
            this.getPanel("structure");

        if (!container) {
            return;
        }

        const structure =
            result.structure ||
            {};

        const detection =
            result.detection ||
            {};

        const archive =
            result.archive ||
            null;

        container.innerHTML = `
            <div class="workspace-section">

                <div class="workspace-section-label">
                    DETECTION
                </div>

                <div class="workspace-grid">

                    ${this.renderValue(
                        "PRIMARY FORMAT",
                        detection.primary ||
                        detection.format ||
                        detection.formatId
                    )}

                    ${this.renderValue(
                        "CONFIDENCE",
                        detection.confidenceLevel
                    )}

                    ${this.renderValue(
                        "EXTENSION MATCH",
                        this.formatBoolean(
                            detection.extensionMatches
                        )
                    )}

                    ${this.renderValue(
                        "MIME MATCH",
                        this.formatBoolean(
                            detection.mimeMatches
                        )
                    )}

                    ${this.renderValue(
                        "SIGNATURE MATCHES",
                        this.getLength(
                            detection.matches
                        )
                    )}

                    ${this.renderValue(
                        "ANOMALIES",
                        this.getLength(
                            detection.anomalies
                        )
                    )}

                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    STRUCTURE
                </div>

                <div class="workspace-grid">

                    ${this.renderValue(
                        "AVAILABLE",
                        this.formatBoolean(
                            structure.available
                        )
                    )}

                    ${this.renderValue(
                        "STATUS",
                        structure.status
                    )}

                    ${this.renderValue(
                        "FORMAT",
                        structure.format
                    )}

                    ${this.renderValue(
                        "CONTAINER",
                        structure.containerType
                    )}

                    ${this.renderValue(
                        "ENTRY COUNT",
                        structure.entryCount
                    )}

                </div>

            </div>


            ${
                archive
                    ? `
                        <div class="workspace-section">

                            <div class="workspace-section-label">
                                ARCHIVE
                            </div>

                            <pre class="workspace-code">${this.escapeHTML(
                                this.formatJSON(
                                    archive
                                )
                            )}</pre>

                        </div>
                    `
                    : ""
            }
        `;
    },

    renderSecurity(result) {
        const container =
            this.getPanel("security");

        if (!container) {
            return;
        }

        const findings =
            Array.isArray(result.findings)
                ? result.findings
                : [];

        const correlations =
            Array.isArray(result.correlations)
                ? result.correlations
                : [];

        const apk =
            result.apk ||
            null;

        container.innerHTML = `
            <div class="workspace-section">

                <div class="workspace-section-label">
                    FINDING SUMMARY
                </div>

                <div class="workspace-grid">

                    ${this.renderValue(
                        "TOTAL",
                        result.findingSummary?.total || 0
                    )}

                    ${this.renderValue(
                        "HIGH",
                        result.findingSummary?.high || 0
                    )}

                    ${this.renderValue(
                        "MEDIUM",
                        result.findingSummary?.medium || 0
                    )}

                    ${this.renderValue(
                        "LOW",
                        result.findingSummary?.low || 0
                    )}

                    ${this.renderValue(
                        "INFO",
                        result.findingSummary?.info || 0
                    )}

                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    SECURITY FINDINGS
                </div>

                <div class="workspace-list">

                    ${
                        findings.length > 0
                            ? findings
                                .map(
                                    (finding) =>
                                        this.renderSecurityFinding(
                                            finding
                                        )
                                )
                                .join("")
                            : this.renderEmptyLine(
                                "No findings were generated."
                            )
                    }

                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    CORRELATIONS
                </div>

                <div class="workspace-list">

                    ${
                        correlations.length > 0
                            ? correlations
                                .map(
                                    (correlation) =>
                                        this.renderCorrelation(
                                            correlation
                                        )
                                )
                                .join("")
                            : this.renderEmptyLine(
                                "No correlations were generated."
                            )
                    }

                </div>

            </div>


            ${
                apk
                    ? `
                        <div class="workspace-section">

                            <div class="workspace-section-label">
                                ANDROID ANALYSIS
                            </div>

                            <pre class="workspace-code">${this.escapeHTML(
                                this.formatJSON(
                                    apk
                                )
                            )}</pre>

                        </div>
                    `
                    : ""
            }
        `;
    },

    renderNetwork(result) {
        const container =
            this.getPanel("network");

        if (!container) {
            return;
        }

        const apk =
            result.apk ||
            {};

        const network =
            apk.network ||
            result.network ||
            null;

        const urls =
            this.extractNetworkValues(
                network,
                "urls"
            );

        const domains =
            this.extractNetworkValues(
                network,
                "domains"
            );

        const ips =
            this.extractNetworkValues(
                network,
                "ips"
            );

        container.innerHTML = `
            <div class="workspace-section">

                <div class="workspace-section-label">
                    NETWORK INDICATORS
                </div>

                <div class="workspace-grid">

                    ${this.renderValue(
                        "URLS",
                        urls.length
                    )}

                    ${this.renderValue(
                        "DOMAINS",
                        domains.length
                    )}

                    ${this.renderValue(
                        "IP ADDRESSES",
                        ips.length
                    )}

                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    URLS
                </div>

                <div class="workspace-list">
                    ${
                        urls.length > 0
                            ? urls
                                .map(
                                    (value) =>
                                        this.renderIndicator(
                                            value
                                        )
                                )
                                .join("")
                            : this.renderEmptyLine(
                                "No URLs extracted."
                            )
                    }
                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    DOMAINS
                </div>

                <div class="workspace-list">
                    ${
                        domains.length > 0
                            ? domains
                                .map(
                                    (value) =>
                                        this.renderIndicator(
                                            value
                                        )
                                )
                                .join("")
                            : this.renderEmptyLine(
                                "No domains extracted."
                            )
                    }
                </div>

            </div>


            <div class="workspace-section">

                <div class="workspace-section-label">
                    IP ADDRESSES
                </div>

                <div class="workspace-list">
                    ${
                        ips.length > 0
                            ? ips
                                .map(
                                    (value) =>
                                        this.renderIndicator(
                                            value
             
