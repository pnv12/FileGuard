"use strict";

/*
 * FILEGUARD
 * Application Controller
 *
 * V1.5.0
 *
 * Responsibilities:
 * - Upload UI integration
 * - Analysis lifecycle
 * - Real analysis progress
 * - Result rendering
 * - Workspace navigation
 * - Error handling
 *
 * The controller does not perform file analysis itself.
 * Analysis is delegated to FileGuardAnalyzer.
 */


const FileGuardApp = {

    VERSION: "1.5.0",

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


    init() {

        this.cacheElements();

        this.bindEvents();

        this.initializeUpload();

        console.log(
            "FileGuard: application initialized.",
            this.VERSION
        );
    },


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


    bindEvents() {

        window.addEventListener(
            "fileguard:file-selected",
            event => {

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

                    this.activateWorkspaceTab(
                        tab.dataset.panel
                    );
                }
            );
        }
    },


    initializeUpload() {

        if (!window.FileGuardUploadUI) {

            console.error(
                "FileGuardUploadUI is not available."
            );

            return;
        }

        window.FileGuardUploadUI.init();
    },


    async handleFile(file) {

        if (!(file instanceof File)) {
            return;
        }


        this.currentFile = file;

        this.currentResult = null;


        this.hideError();

        this.showAnalysisWorkspace();

        this.prepareAnalysisUI(file);


        try {

            if (!window.FileGuardAnalyzer) {

                throw new Error(
                    "FileGuardAnalyzer is not available."
                );
            }


            const result =
                await window.FileGuardAnalyzer.analyze(
                    file,
                    progress => {

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

        if (this.elements.analysisStatus) {

            this.elements.analysisStatus.textContent =
                "RUNNING";
        }


        if (this.elements.analysisFile) {

            this.elements.analysisFile.textContent =
                `${file.name} · ${this.formatBytes(
                    file.size
                )}`;
        }


        if (!this.elements.analysisSteps) {
            return;
        }


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
                id: "detection",
                number: "03",
                name: "FILE DETECTION"
            },

            {
                id: "plan",
                number: "04",
                name: "ANALYSIS PLAN"
            },

            {
                id: "archive",
                number: "05",
                name: "ARCHIVE / STRUCTURE"
            },

            {
                id: "generic",
                number: "06",
                name: "GENERAL ANALYSIS"
            },

            {
                id: "apk",
                number: "07",
                name: "ANDROID ANALYSIS"
            },

            {
                id: "findings",
                number: "08",
                name: "FINDINGS"
            },

            {
                id: "correlation",
                number: "09",
                name: "CORRELATION"
            },

            {
                id: "evidence",
                number: "10",
                name: "EVIDENCE"
            },

            {
                id: "complete",
                number: "11",
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
                    ${this.escapeHTML(
                        step.name
                    )}
                </div>

                <div class="analysis-step-status">
                    WAITING
                </div>

            `;


            this.elements.analysisSteps.appendChild(
                element
            );
        }
    },


    handleProgress(progress) {

        if (
            !progress ||
            !this.elements.analysisSteps
        ) {
            return;
        }


        const step =
            this.elements.analysisSteps.querySelector(
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


            if (this.elements.analysisStatus) {

                this.elements.analysisStatus.textContent =
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


            if (
                progress.step ===
                "complete"
            ) {

                if (
                    this.elements.analysisStatus
                ) {

                    this.elements.analysisStatus.textContent =
                        "COMPLETE";
                }
            }
        }
    },


    showResult(result) {

        if (
            this.elements.analysisStatus
        ) {

            this.elements.analysisStatus.textContent =
                "COMPLETE";
        }


        if (
            this.elements.resultStatus
        ) {

            this.elements.resultStatus.textContent =
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


        if (
            this.elements.resultSection &&
            typeof this.elements.resultSection.scrollIntoView ===
                "function"
        ) {

            this.elements.resultSection.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        }
    },


    renderResult(result) {

        const file =
            result.file || {};

        const hashes =
            result.hashes || {};

        const detection =
            result.detection || {};

        const analysisPlan =
            result.analysisPlan || null;

        const archive =
            result.archive || null;

        const apk =
            result.apk || null;


        const findings =
            Array.isArray(result.findings)
                ? result.findings
                : [];


        const correlations =
            Array.isArray(result.correlations)
                ? result.correlations
                : [];


        const evidence =
            Array.isArray(result.evidence)
                ? result.evidence
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
                        File identity, cryptographic hashes,
                        format detection, routed analyzers,
                        findings, correlation and evidence
                        were processed locally.
                        These results are analytical signals,
                        not a malware verdict.
                    </p>

                </div>


                <div class="file-summary">

                    ${this.summaryItem(
                        "FILE",
                        file.name || "Unknown"
                    )}


                    ${this.summaryItem(
                        "SIZE",
                        this.formatBytes(
                            file.size
                        )
                    )}


                    ${this.summaryItem(
                        "DETECTED FORMAT",
                        detection.format ||
                        "Unknown"
                    )}


                    ${this.summaryItem(
                        "CATEGORY",
                        detection.category ||
                        "Unknown"
                    )}


                    ${this.summaryItem(
                        "CONFIDENCE",
                        detection.confidenceLevel
                            ? `${detection.confidenceLevel} · ${
                                detection.confidenceScore ??
                                0
                            }%`
                            : "Unavailable"
                    )}


                    ${this.summaryItem(
                        "PRIMARY ANALYZER",
                        analysisPlan &&
                        analysisPlan.primaryAnalyzer
                            ? analysisPlan.primaryAnalyzer
                            : "None"
                    )}


                    ${this.summaryItem(
                        "ACTIVE ANALYZERS",
                        analysisPlan &&
                        Array.isArray(
                            analysisPlan.enabledAnalyzers
                        )
                            ? analysisPlan.enabledAnalyzers.join(
                                ", "
                            )
                            : "None"
                    )}


                    ${this.summaryItem(
                        "CONTAINER",
                        archive
                            ? archive.containerType ||
                              "Detected"
                            : "None"
                    )}


                    ${this.summaryItem(
                        "APK ANALYSIS",
                        apk
                            ? "AVAILABLE"
                            : analysisPlan &&
                              analysisPlan.pendingAnalyzers &&
                              analysisPlan.pendingAnalyzers.includes(
                                  "apk"
                              )
                                ? "PENDING"
                                : "NOT APPLICABLE"
                    )}


                    ${this.summaryItem(
                        "FINDINGS",
                        String(
                            findings.length
                        )
                    )}


                    ${this.summaryItem(
                        "CORRELATIONS",
                        String(
                            correlations.length
                        )
                    )}


                    ${this.summaryItem(
                        "EVIDENCE",
                        String(
                            evidence.length
                        )
                    )}


                    ${this.summaryItem(
                        "HIGHEST SEVERITY",
                        highestSeverity
                    )}


                    ${this.summaryItem(
                        "SHA-256",
                        hashes.sha256 ||
                        "Unavailable"
                    )}

                </div>
            `;
        }


        this.renderFindingSummary(
            findings,
            correlations
        );


        this.renderWorkspace(
            result
        );
    },


    renderFindingSummary(
        findings,
        correlations
    ) {

        if (
            !this.elements.resultFindings
        ) {
            return;
        }


        if (
            findings.length === 0 &&
            correlations.length === 0
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
                        No security-relevant rule finding
                        was generated by the analyzers
                        currently enabled for this file.
                    </p>

                </div>

            `;

            return;
        }


        const findingCards =
            findings
                .map(
                    finding =>
                        this.renderFindingCard(
                            finding
                        )
                )
                .join("");


        const correlationCards =
            correlations
                .map(
                    correlation =>
                        this.renderCorrelationCard(
                            correlation
                        )
                )
                .join("");


        this.elements.resultFindings.innerHTML = `

            <div class="result-verdict">

                <div class="result-verdict-label">
                    INVESTIGATION SIGNALS
                </div>

                <div class="result-verdict-title">

                    ${findings.length}
                    ${
                        findings.length === 1
                            ? "FINDING"
                            : "FINDINGS"
                    }

                    /

                    ${correlations.length}
                    ${
                        correlations.length === 1
                            ? "CORRELATION"
                            : "CORRELATIONS"
                    }

                </div>

            </div>


            ${
                findingCards
                    ? `
                        <div class="file-summary">
                            ${findingCards}
                        </div>
                    `
                    : ""
            }


            ${
                correlationCards
                    ? `

                        <div class="result-verdict">

                            <div class="result-verdict-label">
                                CORRELATION ENGINE
         
