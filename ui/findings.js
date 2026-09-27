"use strict";

const FileGuardFindingsUI = {
    elements: {
        container: null
    },

    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.container =
            document.getElementById("result-findings");

        this.initialized = true;
    },

    render(findings) {
        this.init();

        if (!this.elements.container) {
            return;
        }

        const normalized =
            Array.isArray(findings)
                ? findings
                : [];

        if (normalized.length === 0) {
            this.renderEmpty();
            return;
        }

        this.elements.container.innerHTML =
            normalized
                .map((finding, index) => {
                    return this.renderFinding(
                        finding,
                        index
                    );
                })
                .join("");
    },

    renderFinding(finding, index) {
        const severity =
            this.normalizeSeverity(
                finding?.severity
            );

        const confidence =
            this.normalizeConfidence(
                finding?.confidence
            );

        const title =
            finding?.title ||
            "Finding";

        const description =
            finding?.description ||
            "No description available.";

        const recommendation =
            finding?.recommendation ||
            "Review the available evidence before taking further action.";

        const source =
            finding?.source ||
            "unknown";

        const evidence =
            finding?.evidence ||
            null;

        const findingId =
            finding?.id ||
            `finding-${index + 1}`;

        return `
            <article
                class="finding-card finding-${severity.toLowerCase()}"
                data-finding-id="${this.escapeHTML(
                    findingId
                )}"
            >

                <div class="finding-header">

                    <div class="finding-severity">
                        ${this.escapeHTML(
                            severity
                        )}
                    </div>

                    <div class="finding-source">
                        ${this.escapeHTML(
                            String(source).toUpperCase()
                        )}
                    </div>

                </div>


                <div class="finding-body">

                    <h3 class="finding-title">
                        ${this.escapeHTML(title)}
                    </h3>

                    <p class="finding-description">
                        ${this.escapeHTML(description)}
                    </p>


                    <div class="finding-meta">

                        <div class="finding-meta-item">

                            <span class="finding-meta-label">
                                CONFIDENCE
                            </span>

                            <span class="finding-meta-value">
                                ${this.escapeHTML(
                                    confidence
                                )}
                            </span>

                        </div>


                        <div class="finding-meta-item">

                            <span class="finding-meta-label">
                                ID
                            </span>

                            <span class="finding-meta-value">
                                ${this.escapeHTML(
                                    findingId
                                )}
                            </span>

                        </div>

                    </div>


                    ${
                        evidence
                            ? this.renderEvidence(
                                evidence
                            )
                            : ""
                    }


                    <div class="finding-recommendation">

                        <span class="finding-recommendation-label">
                            NEXT ACTION
                        </span>

                        <span class="finding-recommendation-text">
                            ${this.escapeHTML(
                                recommendation
                            )}
                        </span>

                    </div>

                </div>

            </article>
        `;
    },

    renderEvidence(evidence) {
        return `
            <details class="finding-evidence">

                <summary>
                    SHOW EVIDENCE
                </summary>

                <pre>${this.escapeHTML(
                    this.formatEvidence(
                        evidence
                    )
                )}</pre>

            </details>
        `;
    },

    renderEmpty() {
        this.elements.container.innerHTML = `
            <div class="findings-empty">

                <div class="findings-empty-label">
                    FINDINGS
                </div>

                <div class="findings-empty-title">
                    NO SECURITY-RELEVANT FINDINGS
                </div>

                <div class="findings-empty-description">
                    FileGuard did not generate any findings
                    from the analyzers that were executed.
                    This is not a malware verdict.
                </div>

            </div>
        `;
    },

    normalizeSeverity(severity) {
        const value =
            typeof severity === "string"
                ? severity.toUpperCase()
                : "INFO";

        const allowed = [
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"
        ];

        return allowed.includes(value)
            ? value
            : "INFO";
    },

    normalizeConfidence(confidence) {
        const value =
            typeof confidence === "string"
                ? confidence.toUpperCase()
                : "UNKNOWN";

        const allowed = [
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN"
        ];

        return allowed.includes(value)
            ? value
            : "UNKNOWN";
    },

    formatEvidence(evidence) {
        if (typeof evidence === "string") {
            return evidence;
        }

        try {
            return JSON.stringify(
                evidence,
                null,
                2
            );
        } catch {
            return String(evidence);
        }
    },

    escapeHTML(value) {
        if (value === null || value === undefined) {
            return "";
        }

        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    },

    clear() {
        this.init();

        if (this.elements.container) {
            this.elements.container.innerHTML = "";
        }
    }
};

window.FileGuardFindingsUI = FileGuardFindingsUI;
