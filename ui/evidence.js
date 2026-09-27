"use strict";

const FileGuardEvidenceUI = {
    elements: {
        container: null
    },

    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.container =
            document.getElementById("evidence-panel");

        this.initialized = true;
    },

    render(evidence) {
        this.init();

        if (!this.elements.container) {
            return;
        }

        const normalized =
            Array.isArray(evidence)
                ? evidence
                : [];

        if (normalized.length === 0) {
            this.renderEmpty();
            return;
        }

        this.elements.container.innerHTML =
            normalized
                .map((item, index) => {
                    return this.renderItem(
                        item,
                        index
                    );
                })
                .join("");
    },

    renderItem(item, index) {
        const importance =
            this.normalizeImportance(
                item?.importance
            );

        const source =
            item?.source ||
            "unknown";

        const type =
            item?.type ||
            "unknown";

        const description =
            item?.description ||
            "No description available.";

        const id =
            item?.id ||
            `evidence-${index + 1}`;

        return `
            <article
                class="evidence-card evidence-${importance.toLowerCase()}"
                data-evidence-id="${this.escapeHTML(id)}"
            >

                <div class="evidence-header">

                    <div class="evidence-importance">
                        ${this.escapeHTML(importance)}
                    </div>

                    <div class="evidence-source">
                        ${this.escapeHTML(
                            String(source).toUpperCase()
                        )}
                    </div>

                </div>


                <div class="evidence-body">

                    <div class="evidence-type">
                        ${this.escapeHTML(
                            String(type).toUpperCase()
                        )}
                    </div>

                    <div class="evidence-description">
                        ${this.escapeHTML(
                            description
                        )}
                    </div>


                    <div class="evidence-id">
                        <span class="evidence-id-label">
                            ID
                        </span>

                        <span class="evidence-id-value">
                            ${this.escapeHTML(id)}
                        </span>
                    </div>


                    <details class="evidence-details">

                        <summary>
                            INSPECT DATA
                        </summary>

                        <pre>${this.escapeHTML(
                            this.formatData(item?.data)
                        )}</pre>

                    </details>

                </div>

            </article>
        `;
    },

    renderEmpty() {
        this.elements.container.innerHTML = `
            <div class="evidence-empty">

                <div class="evidence-empty-label">
                    EVIDENCE
                </div>

                <div class="evidence-empty-title">
                    NO EVIDENCE AVAILABLE
                </div>

                <div class="evidence-empty-description">
                    The executed analyzers did not produce
                    additional evidence records.
                </div>

            </div>
        `;
    },

    normalizeImportance(value) {
        const normalized =
            typeof value === "string"
                ? value.toUpperCase()
                : "NORMAL";

        if (
            normalized === "HIGH" ||
            normalized === "NORMAL"
        ) {
            return normalized;
        }

        return "NORMAL";
    },

    formatData(data) {
        if (
            data === null ||
            data === undefined
        ) {
            return "NO DATA";
        }

        if (typeof data === "string") {
            return data;
        }

        try {
            return JSON.stringify(
                data,
                null,
                2
            );
        } catch {
            return String(data);
        }
    },

    escapeHTML(value) {
        if (
            value === null ||
            value === undefined
        ) {
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

window.FileGuardEvidenceUI =
    FileGuardEvidenceUI;
