"use strict";

/*
 * FILEGUARD
 * Application Controller
 *
 * V1.1
 *
 * Connects:
 * - Upload UI
 * - Core Analyzer
 * - Analysis workspace
 * - Result workspace
 */


const FileGuardApp = {

    elements: {
        analysisSection: null,
        analysisStatus: null,
        analysisFile: null,
        analysisSteps: null,

        resultSection: null,
        resultStatus: null,
        resultContent: null,

        workspaceSection: null,
        workspaceContent: null,
        workspaceTabs: []
    },


    currentFile: null,
    currentResult: null,


    /*
     * ─────────────────────────────
     * INITIALIZATION
     * ─────────────────────────────
     */

    init() {

        this.cacheElements();

        this.bindEvents();

        this.initializeUpload();


        console.log(
            "FileGuard: application initialized."
        );
    },


    /*
     * ─────────────────────────────
     * CACHE DOM
     * ─────────────────────────────
     */

    cacheElements() {

        this.elements.analysisSection =
            document.getElementById(
                "analysis-section"
            );

        this.elements.analysisStatus =
            document.getElementById(
                "analysis-status"
            );

        this.elements.analysisFile =
            document.getElementById(
                "analysis-file"
            );

        this.elements.analysisSteps =
            document.getElementById(
                "analysis-steps"
            );


        this.elements.resultSection =
            document.getElementById(
                "result-section"
            );

        this.elements.resultStatus =
            document.getElementById(
                "result-status"
            );

        this.elements.resultContent =
            document.getElementById(
                "result-content"
            );


        this.elements.workspaceSection =
            document.getElementById(
                "workspace-section"
            );

        this.elements.workspaceContent =
            document.getElementById(
                "workspace-content"
            );


        this.elements.workspaceTabs =
            Array.from(
                document.querySelectorAll(
                    ".workspace-tab"
                )
            );
    },


    /*
     * ─────────────────────────────
     * EVENTS
     * ─────────────────────────────
     */

    bindEvents() {

        window.addEventListener(
            "fileguard:file-selected",
            (event) => {

                const file =
                    event.detail &&
                    event.detail.file;


                if (file) {
                    this.handleFile(file);
                }
            }
        );


        for (
            const tab
            of this.elements.workspaceTabs
        ) {

            tab.addEventListener(
                "click",
                () => {

                    const panel =
                        tab.dataset.panel;


                    this.activateWorkspaceTab(
                        panel
                    );
                }
            );
        }
    },


    /*
     * ─────────────────────────────
     * UPLOAD UI
     * ─────────────────────────────
     */

    initializeUpload() {

        if (
            !window.FileGuardUploadUI
        ) {

            console.error(
                "FileGuardUploadUI is not available."
            );

            return;
        }


        window.FileGuardUploadUI.init();
    },


    /*
     * ─────────────────────────────
     * FILE HANDLING
     * ─────────────────────────────
     */

    async handleFile(file) {

        if (!(file instanceof File)) {
            return;
        }


        this.currentFile = file;
        this.currentResult = null;


        this.showAnalysisWorkspace();

        this.prepareAnalysisUI(file);


        try {

            const result =
                await window.FileGuardAnalyzer.analyze(
                    file,
                    (progress) => {

                        this.handleProgress(
                            progress
                        );
                    }
                );


            this.currentResult = result;


            this.showResult(result);

        } catch (error) {

            console.error(
                "FileGuard analysis failed:",
                error
            );


            this.showAnalysisError(
                error
            );
        }
    },


    /*
     * ─────────────────────────────
     * ANALYSIS UI
     * ─────────────────────────────
     */

    showAnalysisWorkspace() {

        this.elements.analysisSection
            .classList.remove("hidden");

        this.elements.resultSection
            .classList.add("hidden");

        this.elements.workspaceSection
            .classList.add("hidden");
    },


    prepareAnalysisUI(file) {

        this.elements.analysisStatus.textContent =
            "RUNNING";


        this.elements.analysisFile.textContent =
            `${file.name} · ${this.formatBytes(file.size)}`;


        this.elements.analysisSteps.innerHTML = "";


        const steps = [

            {
                id: "identity",
                number: "01",
                name: "FILE IDENTITY"
            },

            {
                id: "hashes",
                number: "02",
                name: "CRYPTOGRAPHIC HASHES"
            },

            {
                id: "generic",
                number: "03",
                name: "GENERAL ANALYSIS"
            },

            {
                id: "findings",
                number: "04",
                name: "FINDINGS"
            },

            {
                id: "complete",
                number: "05",
                name: "ANALYSIS COMPLETE"
            }

        ];


        for (const step of steps) {

            const element =
                document.createElement("div");


            element.className =
                "analysis-step";


            element.dataset.step =
                step.id;


            element.innerHTML = `

                <div class="analysis-step-number">
                    ${step.number}
                </div>

                <div class="analysis-step-name">
                    ${step.name}
                </div>

                <div class="analysis-step-status">
                    WAITING
                </div>

            `;


            this.elements.analysisSteps
                .appendChild(element);
        }
    },


    /*
     * ─────────────────────────────
     * REAL ANALYSIS PROGRESS
     * ─────────────────────────────
     */

    handleProgress(progress) {

        if (!progress) {
            return;
        }


        const step =
            this.elements.analysisSteps
                .querySelector(
                    `[data-step="${progress.step}"]`
                );


        if (!step) {
            return;
        }


        const status =
            step.querySelector(
                ".analysis-step-status"
            );


        if (
            progress.status === "running"
        ) {

            step.classList.add(
                "active"
            );

            step.classList.remove(
                "completed"
            );

            status.textContent =
                "RUNNING";


            this.elements.analysisStatus
                .textContent =
                "ANALYZING";


            return;
        }


        if (
            progress.status === "completed"
        ) {

            step.classList.remove(
                "active"
            );

            step.classList.add(
                "completed"
            );

            status.textContent =
                "DONE";


            return;
        }
    },


    /*
     * ─────────────────────────────
     * RESULT
     * ─────────────────────────────
     */

    showResult(result) {

        this.elements.analysisStatus
            .textContent =
            "COMPLETE";


        this.elements.resultStatus
            .textContent =
            "COMPLETE";


        this.elements.resultSection
            .classList.remove("hidden");


        this.renderResult(result);


        this.elements.workspaceSection
            .classList.remove("hidden");


        this.renderWorkspace(
            "overview"
        );


        this.elements.resultSection
            .scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
    },


    /*
     * ─────────────────────────────
     * RESULT CONTENT
     * ─────────────────────────────
     */

    renderResult(result) {

        const file =
            result.file || {};

        const identity =
            result.identity || {};

        const hashes =
            result.hashes || {};

        const findings =
            Array.isArray(result.findings)
                ? result.findings
                : [];


        const findingText =
            findings.length === 0
                ? "No rule-based findings were generated by the current analysis layer."
                : `${findings.length} finding${findings.length === 1 ? "" : "s"} generated.`;


        this.elements.resultContent.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    FILEGUARD ANALYSIS
                </div>

                <div class="result-verdict-title">
                    BASELINE ANALYSIS COMPLETE
                </div>

                <p class="result-verdict-description">
                    File identity and cryptographic integrity
                    data were collected locally. No malware
                    verdict is generated by this analysis layer
                    without supporting security evidence.
                </p>

            </div>


            <div class="file-summary">

                <div class="summary-item">

                    <div class="summary-label">
                        FILE
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            file.name || "Unknown"
                        )}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        SIZE
                    </div>

                    <div class="summary-value">
                        ${this.formatBytes(
                            file.size
                        )}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        MIME TYPE
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            file.type || "unknown"
                        )}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        EXTENSION
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            identity.extension
                                ? "." + identity.extension
                                : "none"
                        )}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        SHA-256
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            hashes.sha256 || "Unavailable"
                        )}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        SHA-384
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            hashes.sha384 || "Unavailable"
                        )}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        SHA-512
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            hashes.sha512 || "Unavailable"
                        )}
                    </div>

                </div>


                <div class="summary-item">

                    <div class="summary-label">
                        FINDINGS
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            findingText
                        )}
                    </div>

                </div>

            </div>
        `;
    },


    /*
     * ─────────────────────────────
     * WORKSPACE
     * ─────────────────────────────
     */

    activateWorkspaceTab(panel) {

        for (
            const tab
            of this.elements.workspaceTabs
        ) {

            tab.classList.toggle(
                "active",
                tab.dataset.panel === panel
            );
        }


        this.renderWorkspace(panel);
    },


    renderWorkspace(panel) {

        if (!this.currentResult) {
            return;
        }


        switch (panel) {

            case "identity":
                this.renderIdentityPanel();
                break;

            case "structure":
                this.renderStructurePanel();
                break;

            case "security":
                this.renderSecurityPanel();
                break;

            case "network":
                this.renderUnavailablePanel(
                    "NETWORK ANALYSIS"
                );
                break;

            case "metadata":
                this.renderMetadataPanel();
                break;

            case "files":
                this.renderFilesPanel();
                break;

            case "evidence":
                this.renderEvidencePanel();
                break;

            case "overview":
            default:
                this.renderOverviewPanel();
                break;
        }
    },


    /*
     * ─────────────────────────────
     * WORKSPACE PANELS
     * ─────────────────────────────
     */

    renderOverviewPanel() {

        const result =
            this.currentResult;


        const findings =
            result.findings || [];


        this.elements.workspaceContent.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    ANALYSIS STATUS
                </div>

                <div class="result-verdict-title">
                    LOCAL BASELINE READY
                </div>

                <p class="result-verdict-description">
                    The current engine has established file
                    identity, calculated cryptographic hashes
                    and completed the generic analysis layer.
                    Specialized analyzers will add deeper
                    evidence in later versions.
                </p>

            </div>


            <div class="file-summary">

                <div class="summary-item">
                    <div class="summary-label">
                        ANALYZER
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            result.analyzer || "generic"
                        )}
                    </div>
                </div>


                <div class="summary-item">
                    <div class="summary-label">
                        ANALYSIS TIME
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            `${result.durationMs || 0} ms`
                        )}
                    </div>
                </div>


                <div class="summary-item">
                    <div class="summary-label">
                        FINDINGS
                    </div>

                    <div class="summary-value">
                        ${findings.length}
                    </div>
                </div>


                <div class="summary-item">
                    <div class="summary-label">
                        MODE
                    </div>

                    <div class="summary-value">
                        LOCAL-FIRST
                    </div>
                </div>

            </div>
        `;
    },


    renderIdentityPanel() {

        const identity =
            this.currentResult.identity || {};


        this.elements.workspaceContent.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    IDENTITY
                </div>

                <div class="result-verdict-title">
                    FILE IDENTIFIED
                </div>

                <p class="result-verdict-description">
                    Basic file identity was collected directly
                    from the selected browser File object.
                </p>

            </div>


            <div class="file-summary">

                <div class="summary-item">
                    <div class="summary-label">
                        NAME
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            identity.name || "Unknown"
                        )}
                    </div>
                </div>


                <div class="summary-item">
                    <div class="summary-label">
                        EXTENSION
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            identity.extension
                                ? "." + identity.extension
                                : "none"
                        )}
                    </div>
                </div>


                <div class="summary-item">
                    <div class="summary-label">
                        MIME
                    </div>

                    <div class="summary-value">
                        ${this.escapeHTML(
                            identity.mimeType || "unknown"
                        )}
                    </div>
                </div>


                <div class="summary-item">
                    <div class="summary-label">
                        SIZE
                    </div>

                    <div class="summary-value">
                        ${this.formatBytes(
                            identity.size
                        )}
                    </div>
                </div>

            </div>
        `;
    },


    renderStructurePanel() {

        const structure =
            this.currentResult.structure;


        this.elements.workspaceContent.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    STRUCTURE
                </div>

                <div class="result-verdict-title">
                    ${structure && structure.available
                        ? "STRUCTURE LAYER AVAILABLE"
                        : "STRUCTURE ANALYSIS PENDING"}
                </div>

                <p class="result-verdict-description">
                    The generic structural engine is registered,
                    but deep byte-level and container inspection
                    is not yet enabled in this version.
   
