"use strict";

/*
 * FILEGUARD
 * Application Controller
 *
 * V2.0.0
 *
 * Responsibilities:
 * - Upload UI integration
 * - Analysis lifecycle
 * - Real analysis progress
 * - Result rendering
 * - Investigation workspace
 * - APK security data presentation
 * - Findings / correlations / evidence presentation
 * - Error handling
 *
 * The controller does not perform analysis.
 * Analysis is delegated to FileGuardAnalyzer.
 */


const FileGuardApp = {

    VERSION: "2.0.0",


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
     * ─────────────────────────────
     * INITIALIZATION
     * ─────────────────────────────
     */

    init() {

        this.cacheElements();

        this.bindEvents();

        this.initializeUpload();

        console.log(
            "FileGuard initialized.",
            this.VERSION
        );
    },


    cacheElements() {

        const get =
            id =>
                document.getElementById(id);


        this.elements.analysisSection =
            get("analysis-section");

        this.elements.analysisStatus =
            get("analysis-status");

        this.elements.analysisFile =
            get("analysis-file");

        this.elements.analysisSteps =
            get("analysis-steps");


        this.elements.resultSection =
            get("result-section");

        this.elements.resultStatus =
            get("result-status");

        this.elements.resultSummary =
            get("result-summary");

        this.elements.resultFindings =
            get("result-findings");


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
            get("overview-panel");

        this.elements.identityPanel =
            get("identity-panel");

        this.elements.structurePanel =
            get("structure-panel");

        this.elements.securityPanel =
            get("security-panel");

        this.elements.networkPanel =
            get("network-panel");

        this.elements.metadataPanel =
            get("metadata-panel");

        this.elements.filesPanel =
            get("files-panel");

        this.elements.evidencePanel =
            get("evidence-panel");


        this.elements.errorSection =
            get("error-section");

        this.elements.errorMessage =
            get("error-message");
    },


    bindEvents() {

        window.addEventListener(
            "fileguard:file-selected",
            event => {

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
     * FILE LIFECYCLE
     * ─────────────────────────────
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
                    progress => {

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


    /*
     * ─────────────────────────────
     * PROGRESS
     * ─────────────────────────────
     */

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
                `${file.name} · ${this.formatBytes(
                    file.size
                )}`;
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


            if (
                this.elements.analysisStatus
            ) {

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


    /*
     * ─────────────────────────────
     * RESULT
     * ─────────────────────────────
     */

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
            Array.isArray(
                result.findings
            )
                ? result.findings
                : [];


        const correlations =
            Array.isArray(
                result.correlations
            )
                ? result.correlations
                : [];


        const evidence =
            Array.isArray(
                result.evidence
            )
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
                        These are analytical signals,
                        not a malware verdict.
                    </p>

                </div>


                <div class="file-summary">

                    ${this.summaryItem(
                        "FILE",
                        file.name ||
                        "Unknown"
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


    /*
     * ─────────────────────────────
     * FINDINGS
     * ─────────────────────────────
     */

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
                        No rule-based finding was generated
                        by the currently enabled analyzers.
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
                            </div>

                        </div>

                        <div class="file-summary">
                   
