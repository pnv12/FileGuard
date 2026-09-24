"use strict";

/*
 * FILEGUARD
 * Application Entry Point
 *
 * V1.0
 *
 * This file controls the initial interface flow.
 * Actual analysis engines will be implemented
 * in the core/, analyzers/ and utils/ modules.
 */


const FileGuard = {
    elements: {
        fileInput: null,
        selectFileButton: null,
        dropZone: null,

        analysisSection: null,
        analysisStatus: null,
        analysisSteps: null,

        resultSection: null,
        resultStatus: null,
        resultContent: null
    },

    state: {
        selectedFile: null,
        isAnalyzing: false,
        analysisResult: null
    },


    /*
     * ─────────────────────────────
     * INITIALIZATION
     * ─────────────────────────────
     */

    init() {
        this.cacheElements();
        this.bindEvents();

        console.info("FileGuard initialized.");
    },


    cacheElements() {
        this.elements.fileInput =
            document.getElementById("file-input");

        this.elements.selectFileButton =
            document.getElementById("select-file-button");

        this.elements.dropZone =
            document.getElementById("drop-zone");

        this.elements.analysisSection =
            document.getElementById("analysis-section");

        this.elements.analysisStatus =
            document.getElementById("analysis-status");

        this.elements.analysisSteps =
            document.getElementById("analysis-steps");

        this.elements.resultSection =
            document.getElementById("result-section");

        this.elements.resultStatus =
            document.getElementById("result-status");

        this.elements.resultContent =
            document.getElementById("result-content");
    },


    bindEvents() {

        this.elements.selectFileButton.addEventListener(
            "click",
            () => {
                this.openFilePicker();
            }
        );


        this.elements.fileInput.addEventListener(
            "change",
            (event) => {
                const files = event.target.files;

                if (!files || files.length === 0) {
                    return;
                }

                this.handleFile(files[0]);
            }
        );


        this.elements.dropZone.addEventListener(
            "dragover",
            (event) => {
                event.preventDefault();

                this.elements.dropZone.classList.add(
                    "drag-over"
                );
            }
        );


        this.elements.dropZone.addEventListener(
            "dragleave",
            () => {
                this.elements.dropZone.classList.remove(
                    "drag-over"
                );
            }
        );


        this.elements.dropZone.addEventListener(
            "drop",
            (event) => {
                event.preventDefault();

                this.elements.dropZone.classList.remove(
                    "drag-over"
                );

                const files = event.dataTransfer.files;

                if (!files || files.length === 0) {
                    return;
                }

                this.handleFile(files[0]);
            }
        );

    },


    /*
     * ─────────────────────────────
     * FILE SELECTION
     * ─────────────────────────────
     */

    openFilePicker() {
        if (this.state.isAnalyzing) {
            return;
        }

        this.elements.fileInput.click();
    },


    handleFile(file) {

        if (!(file instanceof File)) {
            return;
        }

        this.state.selectedFile = file;

        console.info(
            "Selected file:",
            file.name
        );

        this.startAnalysis();
    },


    /*
     * ─────────────────────────────
     * ANALYSIS FLOW
     * ─────────────────────────────
     */

    async startAnalysis() {

        if (!this.state.selectedFile) {
            return;
        }

        if (this.state.isAnalyzing) {
            return;
        }

        this.state.isAnalyzing = true;

        this.showAnalysisInterface();

        this.renderAnalysisSteps();

        await this.runDemoAnalysis();

        this.state.isAnalyzing = false;
    },


    showAnalysisInterface() {

        this.elements.analysisSection.classList.remove(
            "hidden"
        );

        this.elements.resultSection.classList.add(
            "hidden"
        );

        this.elements.analysisStatus.textContent =
            "RUNNING";
    },


    renderAnalysisSteps() {

        const steps = [
            {
                id: "identify",
                name: "IDENTIFY FILE"
            },
            {
                id: "hashes",
                name: "CALCULATE HASHES"
            },
            {
                id: "structure",
                name: "READ STRUCTURE"
            },
            {
                id: "metadata",
                name: "CHECK METADATA"
            },
            {
                id: "security",
                name: "RUN SECURITY RULES"
            },
            {
                id: "report",
                name: "BUILD REPORT"
            }
        ];


        this.elements.analysisSteps.innerHTML =
            steps.map((step, index) => {

                return `
                    <div
                        class="analysis-step"
                        data-step="${step.id}"
                    >
                        <div class="analysis-step-number">
                            ${String(index + 1).padStart(2, "0")}
                        </div>

                        <div class="analysis-step-name">
                            ${step.name}
                        </div>

                        <div class="analysis-step-status">
                            WAITING
                        </div>
                    </div>
                `;

            }).join("");
    },


    async runDemoAnalysis() {

        const steps = [
            "identify",
            "hashes",
            "structure",
            "metadata",
            "security",
            "report"
        ];


        for (const stepId of steps) {

            await this.delay(350);

            this.setStepActive(stepId);

            await this.delay(450);

            this.setStepComplete(stepId);
        }


        await this.delay(300);

        this.elements.analysisStatus.textContent =
            "COMPLETE";

        this.createInitialResult();
    },


    setStepActive(stepId) {

        const step =
            this.elements.analysisSteps.querySelector(
                `[data-step="${stepId}"]`
            );

        if (!step) {
            return;
        }

        step.classList.add("active");

        const status =
            step.querySelector(
                ".analysis-step-status"
            );

        if (status) {
            status.textContent = "RUNNING";
        }
    },


    setStepComplete(stepId) {

        const step =
            this.elements.analysisSteps.querySelector(
                `[data-step="${stepId}"]`
            );

        if (!step) {
            return;
        }

        step.classList.remove("active");

        step.classList.add("completed");

        const status =
            step.querySelector(
                ".analysis-step-status"
            );

        if (status) {
            status.textContent = "DONE";
        }
    },


    /*
     * ─────────────────────────────
     * INITIAL RESULT
     * ─────────────────────────────
     */

    createInitialResult() {

        const file = this.state.selectedFile;

        if (!file) {
            return;
        }


        const size =
            this.formatFileSize(file.size);


        this.state.analysisResult = {
            fileName: file.name,
            fileSize: file.size,
            formattedSize: size,
            mimeType: file.type || "unknown",
            lastModified: file.lastModified
                ? new Date(file.lastModified)
                : null
        };


        this.renderInitialResult();
    },


    renderInitialResult() {

        const result =
            this.state.analysisResult;

        if (!result) {
            return;
        }


        this.elements.resultSection.classList.remove(
            "hidden"
        );


        this.elements.resultStatus.textContent =
            "COMPLETE";


        this.elements.resultContent.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    FILEGUARD VERDICT
                </div>

                <div class="result-verdict-title">
                    ANALYSIS COMPLETE
                </div>

                <div class="result-verdict-description">
                    The file has been received by the local
                    analysis engine. Detailed structural,
                    integrity, metadata and security analysis
                    will be provided by the dedicated engines.
                </div>

            </div>


            <div class="file-summary">

                <div class="summary-item">

                    <div class="summary-label">
                        FILE
                    </div>

                    <div class="summary-value">
                        ${this.escapeHtml(result.fileName)}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        SIZE
                    </div>

                    <div class="summary-value">
                        ${result.formattedSize}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        MIME TYPE
                    </div>

                    <div class="summary-value">
                        ${this.escapeHtml(result.mimeType)}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        STATUS
                    </div>

                    <div class="summary-value">
                        READY FOR DEEP ANALYSIS
                    </div>

                </div>

            </div>
        `;


        this.elements.resultSection.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    },


    /*
     * ─────────────────────────────
     * UTILITIES
     * ─────────────────────────────
     */

    formatFileSize(bytes) {

        if (!Number.isFinite(bytes) || bytes < 0) {
            return "UNKNOWN";
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
            Math.pow(1024, exponent);


        const decimals =
            exponent === 0
                ? 0
                : value >= 100
                    ? 0
                    : value >= 10
                        ? 1
                        : 2;


        return `${value.toFixed(decimals)} ${units[exponent]}`;
    },


    escapeHtml(value) {

        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    },


    delay(milliseconds) {

        return new Promise(resolve => {
            setTimeout(resolve, milliseconds);
        });
    }
};


/*
 * Start application after the document
 * has finished loading.
 */

document.addEventListener(
    "DOMContentLoaded",
    () => {
        FileGuard.init();
    }
);
