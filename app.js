"use strict";

/*
 * FILEGUARD
 * Application Controller
 *
 * V1.3
 *
 * Connects:
 * - Upload UI
 * - Core Analyzer
 * - File Detection
 * - Archive Analyzer
 * - Result Workspace
 * - Investigation Panels
 */


const FileGuardApp = {

    VERSION: "1.3.0",


    elements: {

        analysisSection: null,
        analysisStatus: null,
        analysisFile: null,
        analysisSteps: null,

        resultSection: null,
        resultStatus: null,
        resultSummary: null,
        resultFindings: null,

        workspaceTabs: [],
        workspacePanels: [],

        overviewPanel: null,
        identityPanel: null,
        structurePanel: null,
        securityPanel: null,
        networkPanel: null,
        metadataPanel: null,
        filesPanel: null,
        evidencePanel: null,

        errorSection: null,
        errorMessage: null

    },


    currentFile: null,
    currentResult: null,


    /*
     * INITIALIZATION
     */

    init() {

        this.cacheElements();

        this.bindEvents();

        this.initializeUpload();

        console.log(
            "FileGuard: application initialized.",
            this.VERSION
        );
    },


    /*
     * DOM CACHE
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

        this.elements.resultSummary =
            document.getElementById(
                "result-summary"
            );

        this.elements.resultFindings =
            document.getElementById(
                "result-findings"
            );


        this.elements.workspaceTabs =
            Array.from(
                document.querySelectorAll(
                    ".workspace-tab"
                )
            );


        this.elements.workspacePanels =
            Array.from(
                document.querySelectorAll(
                    ".workspace-panel"
                )
            );


        this.elements.overviewPanel =
            document.getElementById(
                "overview-panel"
            );

        this.elements.identityPanel =
            document.getElementById(
                "identity-panel"
            );

        this.elements.structurePanel =
            document.getElementById(
                "structure-panel"
            );

        this.elements.securityPanel =
            document.getElementById(
                "security-panel"
            );

        this.elements.networkPanel =
            document.getElementById(
                "network-panel"
            );

        this.elements.metadataPanel =
            document.getElementById(
                "metadata-panel"
            );

        this.elements.filesPanel =
            document.getElementById(
                "files-panel"
            );

        this.elements.evidencePanel =
            document.getElementById(
                "evidence-panel"
            );


        this.elements.errorSection =
            document.getElementById(
                "error-section"
            );

        this.elements.errorMessage =
            document.getElementById(
                "error-message"
            );
    },


    /*
     * EVENTS
     */

    bindEvents() {

        window.addEventListener(
            "fileguard:file-selected",
            (event) => {

                const file =
                    event.detail &&
                    event.detail.file;


                if (file) {

                    this.handleFile(
                        file
                    );
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

                    this.activateWorkspaceTab(
                        tab.dataset.panel
                    );
                }
            );
        }
    },


    /*
     * UPLOAD
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
     * FILE ANALYSIS
     */

    async handleFile(file) {

        if (
            !(file instanceof File)
        ) {

            return;
        }


        this.currentFile =
            file;

        this.currentResult =
            null;


        this.hideError();

        this.showAnalysisWorkspace();

        this.prepareAnalysisUI(
            file
        );


        try {

            if (
                !window.FileGuardAnalyzer
            ) {

                throw new Error(
                    "FileGuardAnalyzer is not available."
                );
            }


            const result =
                await window.FileGuardAnalyzer.analyze(
                    file,
                    (progress) => {

                        this.handleProgress(
                            progress
                        );

                    }
                );


            this.currentResult =
                result;


            this.showResult(
                result
            );

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
     * ANALYSIS WORKSPACE
     */

    showAnalysisWorkspace() {

        this.setHidden(
            this.elements.analysisSection,
            false
        );

        this.setHidden(
            this.elements.resultSection,
            true
        );
    },


    prepareAnalysisUI(file) {

        if (
            this.elements.analysisStatus
        ) {

            this.elements.analysisStatus.textContent =
                "RUNNING";
        }


        if (
            this.elements.analysisFile
        ) {

            this.elements.analysisFile.textContent =
                `${file.name} · ${this.formatBytes(file.size)}`;
        }


        if (
            !this.elements.analysisSteps
        ) {

            return;
        }


        this.elements.analysisSteps.innerHTML =
            "";


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
                id: "detection",
                number: "03",
                name: "FILE DETECTION"
            },

            {
                id: "archive",
                number: "04",
                name: "ARCHIVE / STRUCTURE"
            },

            {
                id: "generic",
                number: "05",
                name: "GENERAL ANALYSIS"
            },

            {
                id: "findings",
                number: "06",
                name: "FINDINGS"
            },

            {
                id: "complete",
                number: "07",
                name: "ANALYSIS COMPLETE"
            }

        ];


        for (
            const step
            of steps
        ) {

            const element =
                document.createElement(
                    "div"
                );


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
                .appendChild(
                    element
                );
        }
    },


    /*
     * REAL PROGRESS
     */

    handleProgress(progress) {

        if (
            !progress ||
            !this.elements.analysisSteps
        ) {

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
            progress.status ===
            "running"
        ) {

            step.classList.add(
                "active"
            );

            step.classList.remove(
                "completed"
            );


            if (status) {

                status.textContent =
                    "RUNNING";
            }


            if (
                this.elements.analysisStatus
            ) {

                this.elements.analysisStatus
                    .textContent =
                    "ANALYZING";
            }


            return;
        }


        if (
            progress.status ===
            "completed"
        ) {

            step.classList.remove(
                "active"
            );

            step.classList.add(
                "completed"
            );


            if (status) {

                status.textContent =
                    "DONE";
            }
        }
    },


    /*
     * RESULT
     */

    showResult(result) {

        if (
            this.elements.analysisStatus
        ) {

            this.elements.analysisStatus
                .textContent =
                "COMPLETE";
        }


        if (
            this.elements.resultStatus
        ) {

            this.elements.resultStatus
                .textContent =
                "COMPLETE";
        }


        this.setHidden(
            this.elements.resultSection,
            false
        );


        this.renderResult(
            result
        );


        this.activateWorkspaceTab(
            "overview"
        );


        this.elements.resultSection
            ?.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
    },


    /*
     * RESULT SUMMARY
     */

    renderResult(result) {

        const file =
            result.file ||
            {};

        const identity =
            result.identity ||
            {};

        const hashes =
            result.hashes ||
            {};

        const detection =
            result.detection ||
            {};

        const archive =
            result.archive ||
            null;

        const findings =
            Array.isArray(
                result.findings
            )
                ? result.findings
                : [];


        const highestSeverity =
            this.getHighestSeverity(
                findings
            );


        if (
            this.elements.resultSummary
        ) {

            this.elements.resultSummary.innerHTML = `

                <div class="result-verdict">

                    <div class="result-verdict-label">
                        FILEGUARD ANALYSIS
                    </div>

                    <div class="result-verdict-title">
                        ${this.escapeHTML(
                            detection.format ||
                            "FILE ANALYZED"
                        )}
                    </div>

                    <p class="result-verdict-description">
                        File identity, cryptographic integrity,
                        byte-level format detection and applicable
                        structural analysis were performed locally.
                        Security findings are evidence-based signals,
                        not a claim that the file is malware.
                    </p>

                </div>


                <div class="file-summary">

                    ${this.summaryItem(
                        "FILE",
                        file.name || "Unknown"
                    )}

                    ${this.summaryItem(
                        "SIZE",
                        this.formatBytes(file.size)
                    )}

                    ${this.summaryItem(
                        "DETECTED FORMAT",
                        detection.format || "Unknown"
                    )}

                    ${this.summaryItem(
                        "CATEGORY",
                        detection.category || "Unknown"
                    )}

                    ${this.summaryItem(
                        "CONFIDENCE",
                        detection.confidenceLevel
                            ? `${detection.confidenceLevel} · ${detection.confidenceScore ?? 0}%`
                            : "Unavailable"
                    )}

                    ${this.summaryItem(
                        "CONTAINER",
                        archive
                            ? archive.containerType
                            : "None"
                    )}

                    ${this.summaryItem(
                        "FINDINGS",
                        String(findings.length)
                    )}

                    ${this.summaryItem(
                        "HIGHEST SEVERITY",
                        highestSeverity
                    )}

                    ${this.summaryItem(
                        "SHA-256",
                        hashes.sha256 || "Unavailable"
                    )}

                </div>
            `;
        }


        if (
            this.elements.resultFindings
        ) {

            this.renderFindingSummary(
                findings
            );
        }
    },


    renderFindingSummary(findings) {

        if (
            findings.length === 0
        ) {

            this.elements.resultFindings.innerHTML = `

                <div class="result-verdict">

                    <div class="result-verdict-label">
                        FINDINGS
                    </div>

                    <div class="result-verdict-title">
                        NO RULE-BASED FINDINGS
                    </div>

                    <p class="result-verdict-description">
                        No security-relevant rule finding was
                        generated by the analyzers currently
                        enabled for this file.
                    </p>

                </div>
            `;

            return;
        }


        this.elements.resultFindings.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    FINDINGS
                </div>

                <div class="result-verdict-title">
                    ${findings.length}
                    ${findings.length === 1
                        ? "FINDING"
                        : "FINDINGS"}
                </div>

            </div>


            <div class="file-summary">

                ${findings
                    .map(
                        (finding) =>
                            this.renderFindingCard(
                                finding
                            )
                    )
                    .join("")}

            </div>
        `;
    },


    renderFindingCard(finding) {

        const severity =
            finding.severity ||
            "INFO";


        const confidence =
            finding.confidence ||
            "MEDIUM";


        return `

            <div class="summary-item">

                <div class="summary-label">
                    ${this.escapeHTML(
                        severity
                    )}
                </div>

                <div class="summary-value">

                    <strong>
                        ${this.escapeHTML(
                            finding.title ||
                            "Unnamed finding"
                        )}
                    </strong>

                    <br>

                    ${this.escapeHTML(
                        finding.description ||
                        "No description available."
                    )}

                    <br><br>

                    <span>
                        CONFIDENCE:
                        ${this.escapeHTML(
                            confidence
                        )}
                    </span>

                </div>

            </div>
        `;
    },


    /*
     * WORKSPACE TABS
     */

    activateWorkspaceTab(panel) {

        if (
            !panel
        ) {

            panel =
                "overview";
        }


        for (
            const tab
            of this.elements.workspaceTabs
        ) {

            tab.classList.toggle(
                "active",
                tab.dataset.panel === panel
            );
        }


        for (
            const workspacePanel
            of this.elements.workspacePanels
        ) {

            workspacePanel.classList.toggle(
                "active",
                workspacePanel.dataset.panelContent ===
                panel
            );
        }


        this.renderWorkspace(
            panel
        );
    },


    renderWorkspace(panel) {

        if (
            !this.currentResult
        ) {

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
     * OVERVIEW
     */

    renderOverviewPanel() {

        const result =
            this.currentResult;

        const detection =
            result.detection ||
            {};

        const archive =
            result.archive ||
            null;

        const findings =
            result.findings ||
            [];


        this.elements.overviewPanel.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    ANALYSIS STATUS
                </div>

                <div class="result-verdict-title">
                    LOCAL ANALYSIS COMPLETE
                </div>

                <p class="result-verdict-description">
                    FileGuard established the file identity,
                    cryptographic hashes, detected format and
                    applicable specialized analysis.
                </p>

            </div>


            <div class="file-summary">

         
