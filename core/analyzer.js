"use strict";

/*
 * FILEGUARD
 * Core Analyzer
 *
 * V1.8.0
 *
 * Pipeline:
 *
 * File
 *  ↓
 * Identity
 *  ↓
 * Hashes
 *  ↓
 * Detection
 *  ↓
 * Analysis Plan / Router
 *  ↓
 * Selected Analyzers
 *  ↓
 * Findings
 *  ↓
 * Correlation
 *  ↓
 * Evidence
 *  ↓
 * Result
 *
 * The core analyzer orchestrates analysis.
 * It does not contain format-specific routing rules.
 */


const FileGuardAnalyzer = {

    VERSION: "1.8.0",


    /*
     * ─────────────────────────────
     * MAIN ANALYSIS PIPELINE
     * ─────────────────────────────
     */

    async analyze(
        file,
        onProgress = null
    ) {

        this.validateFile(file);


        const startedAt =
            performance.now();


        /*
         * IDENTITY
         */

        this.reportProgress(
            onProgress,
            "identity",
            "running"
        );


        const identity =
            this.buildIdentity(file);


        this.reportProgress(
            onProgress,
            "identity",
            "completed",
            identity
        );


        /*
         * HASHES
         */

        this.reportProgress(
            onProgress,
            "hashes",
            "running"
        );


        if (
            !window.FileGuardHash ||
            typeof window.FileGuardHash.calculateAll !==
                "function"
        ) {

            throw new Error(
                "FileGuardHash module is not available."
            );
        }


        const hashes =
            await window.FileGuardHash.calculateAll(
                file
            );


        this.reportProgress(
            onProgress,
            "hashes",
            "completed",
            hashes
        );


        /*
         * DETECTION
         */

        this.reportProgress(
            onProgress,
            "detection",
            "running"
        );


        if (
            !window.FileGuardDetector ||
            typeof window.FileGuardDetector.detect !==
                "function"
        ) {

            throw new Error(
                "FileGuardDetector module is not available."
            );
        }


        const detection =
            await window.FileGuardDetector.detect(
                file
            );


        this.reportProgress(
            onProgress,
            "detection",
            "completed",
            detection
        );


        /*
         * ANALYSIS PLAN
         *
         * The router decides which analyzers
         * are relevant for this file.
         */

        this.reportProgress(
            onProgress,
            "plan",
            "running"
        );


        if (
            !window.FileGuardAnalysisPlan ||
            typeof window.FileGuardAnalysisPlan.create !==
                "function"
        ) {

            throw new Error(
                "FileGuardAnalysisPlan module is not available."
            );
        }


        const analysisPlan =
            window.FileGuardAnalysisPlan.create(
                identity,
                detection
            );


        this.reportProgress(
            onProgress,
            "plan",
            "completed",
            analysisPlan
        );


        /*
         * ANALYZERS
         */

        let generic = null;
        let archive = null;
        let apk = null;


        /*
         * GENERIC ANALYZER
         */

        if (
            this.planIncludes(
                analysisPlan,
                "generic"
            )
        ) {

            this.reportProgress(
                onProgress,
                "generic",
                "running"
            );


            if (
                window.FileGuardGenericAnalyzer &&
                typeof window.FileGuardGenericAnalyzer.analyze ===
                    "function"
            ) {

                generic =
                    await window.FileGuardGenericAnalyzer.analyze(
                        file
                    );
            }


            this.reportProgress(
                onProgress,
                "generic",
                "completed",
                generic
            );
        }


        /*
         * ARCHIVE ANALYZER
         */

        if (
            this.planIncludes(
                analysisPlan,
                "archive"
            )
        ) {

            this.reportProgress(
                onProgress,
                "archive",
                "running"
            );


            if (
                window.FileGuardArchiveAnalyzer &&
                typeof window.FileGuardArchiveAnalyzer.analyze ===
                    "function"
            ) {

                archive =
                    await window.FileGuardArchiveAnalyzer.analyze(
                        file
                    );
            }


            this.reportProgress(
                onProgress,
                "archive",
                "completed",
                archive
            );
        }


        /*
         * APK ANALYZER
         *
         * The router can already identify APK files,
         * but the deep APK analyzer is not implemented yet.
         */

        if (
            this.planIncludes(
                analysisPlan,
                "apk"
            )
        ) {

            this.reportProgress(
                onProgress,
                "apk",
                "running"
            );


            if (
                window.FileGuardAPKAnalyzer &&
                typeof window.FileGuardAPKAnalyzer.analyze ===
                    "function"
            ) {

                apk =
                    await window.FileGuardAPKAnalyzer.analyze(
                        file,
                        {
                            identity,
                            detection,
                            archive
                        }
                    );
            }


            this.reportProgress(
                onProgress,
                "apk",
                "completed",
                apk
            );
        }


        /*
         * FINDINGS
         */

        this.reportProgress(
            onProgress,
            "findings",
            "running"
        );


        const rawFindings =
            this.collectInitialFindings(
                identity,
                detection,
                generic,
                archive,
                apk
            );


        let findings =
            rawFindings;


        if (
            window.FileGuardFindings &&
            typeof window.FileGuardFindings.normalize ===
                "function"
        ) {

            findings =
                window.FileGuardFindings.normalize(
                    rawFindings
                );
        }


        const findingSummary =
            window.FileGuardFindings &&
            typeof window.FileGuardFindings.summarize ===
                "function"

                ? window.FileGuardFindings.summarize(
                    findings
                )

                : {
                    total: findings.length,
                    high: 0,
                    medium: 0,
                    low: 0,
                    info: 0
                };


        this.reportProgress(
            onProgress,
            "findings",
            "completed",
            {
                findings,
                summary: findingSummary
            }
        );


        /*
         * CORRELATION
         */

        this.reportProgress(
            onProgress,
            "correlation",
            "running"
        );


        let correlations = [];


        if (
            window.FileGuardCorrelation &&
            typeof window.FileGuardCorrelation.correlate ===
                "function"
        ) {

            correlations =
                window.FileGuardCorrelation.correlate(
                    findings,
                    {
                        identity,
                        detection,
                        analysisPlan,
                        archive,
                        generic,
                        apk
                    }
                );
        }


        const correlationSummary =
            window.FileGuardCorrelation &&
            typeof window.FileGuardCorrelation.summarize ===
                "function"

                ? window.FileGuardCorrelation.summarize(
                    correlations
                )

                : {
                    total: correlations.length,
                    high: 0,
                    medium: 0,
                    low: 0,
                    info: 0
                };


        this.reportProgress(
            onProgress,
            "correlation",
            "completed",
            {
                correlations,
                summary: correlationSummary
            }
        );


        /*
         * EVIDENCE
         */

        this.reportProgress(
            onProgress,
            "evidence",
            "running"
        );


        const evidence =
            this.buildEvidence(
                detection,
                archive,
                findings,
                correlations,
                apk
            );


        const evidenceSummary =
            window.FileGuardEvidence &&
            typeof window.FileGuardEvidence.summarize ===
                "function"

                ? window.FileGuardEvidence.summarize(
                    evidence
                )

                : null;


        this.reportProgress(
            onProgress,
            "evidence",
            "completed",
            {
                evidence,
                summary: evidenceSummary
            }
        );


        /*
         * FINAL STRUCTURE
         */

        const durationMs =
            Math.round(
                performance.now() -
                startedAt
            );


        const structure =
            archive
                ? {
                    available: true,

                    status:
                        archive.status,

                    format:
                        archive.format,

                    containerType:
                        archive.containerType,

                    entryCount:
                        archive.entryCount,

                    statistics:
                        archive.statistics,

                    features:
                        archive.features
                }

                : generic
                    ? generic.structure
                    : null;


        /*
         * FINAL RESULT
         */

        const result = {

            status:
                "completed",

            analyzer:
                "core",

            analyzerVersion:
                this.VERSION,

            durationMs,


            file: {

                name:
                    file.name,

                size:
                    file.size,

                type:
                    file.type ||
                    "unknown",

                lastModified:
                    file.lastModified ||
                    null
            },


            analysisPlan,


            identity,


            hashes,


            detection,


            archive,


            apk,


            structure,


            metadata:
                generic
                    ? generic.metadata
                    : null,


            findings,


            findingSummary,


            correlations,


            correlationSummary,


            evidence,


            evidenceSummary,


            analyzers: {

                generic:
                    Boolean(
                        generic
                    ),

                archive:
                    Boolean(
                        archive
                    ),

                apk:
                    Boolean(
                        apk
                    ),

                correlation:
                    correlations.length >
                    0
            }

        };


        this.reportProgress(
            onProgress,
            "complete",
            "completed",
            result
        );


        return result;
    },


    /*
     * ─────────────────────────────
     * PLAN HELPERS
     * ─────────────────────────────
     */

    planIncludes(
        analysisPlan,
        analyzerId
    ) {

        if (
            !analysisPlan ||
            !Array.isArray(
                analysisPlan.enabledAnalyzers
            )
        ) {
            return false;
        }


        return analysisPlan.enabledAnalyzers.includes(
            analyzerId
        );
    },


    /*
     * ─────────────────────────────
     * EVIDENCE
     * ─────────────────────────────
     */

    buildEvidence(
        detection,
        archive,
        findings,
        correlations,
        apk
    ) {

        if (
            !window.FileGuardEvidence
        ) {
            return [];
        }


        const detectorEvidence =
            typeof window.FileGuardEvidence.fromDetection ===
                "function"

                ? window.FileGuardEvidence.fromDetection(
                    detection
                )

                : [];


        const archiveEvidence =
            typeof window.FileGuardEvidence.fromArchive ===
                "function"

                ? window.FileGuardEvidence.fromArchive(
                    archive
                )

                : [];


        const findingEvidence =
            typeof window.FileGuardEvidence.fromFindings ===
                "function"

                ? window.FileGuardEvidence.fromFindings(
                    findings
                )

                : [];


        const correlationEvidence =
            typeof window.FileGuardEvidence.fromFindings ===
                "function"

                ? window.FileGuardEvidence.fromFindings(
                    correlations
                )

                : [];


        /*
         * APK evidence will be integrated here once
         * the deep APK analyzer exists.
         */

        const apkEvidence =
            apk &&
            Array.isArray(
                apk.evidence
            )

                ? apk.evidence

                : [];


        if (
            typeof window.FileGuardEvidence.merge ===
                "function"
        ) {

            return window.FileGuardEvidence.merge(
                detectorEvidence,
                archiveEvidence,
                findingEvidence,
                correlationEvidence,
                apkEvidence
            );
        }


        return [
            ...detectorEvidence,
            ...archiveEvidence,
            ...findingEvidence,
            ...correlationEvidence,
            ...apkEvidence
        ];
    },


    /*
     * ─────────────────────────────
     * FINDINGS
     * ─────────────────────────────
     */

    collectInitialFindings(
        identity,
        detection,
        generic,
        archive,
        apk
    ) {

        const findings = [];


        /*
         * DETECTOR FINDINGS
         */

        if (
            detection &&
            Array.isArray(
                detection.anomalies
            )
        ) {

            for (
                const anomaly
                of detection.anomalies
            ) {

                findings.push({

                    id:
                        `detector-${anomaly.id}`,

                    severity:
                        anomaly.severity ||
                        "INFO",

                    confidence:
                        detection.confidenceLevel ||
                        "MEDIUM",

                    title:
                        anomaly.title ||
                        "File detection anomaly",

                    description:
                        "The file detector identified a characteristic that requires review.",

                    evidence:
                        anomaly.evidence ||
                        null,

                    recommendation:
                        this.getFindingRecommendation(
                            anomaly.id
                        ),

                    source:
                        "detector"
                });
            }
        }


        /*
         * ARCHIVE FINDINGS
         */

        if (
            archive &&
            Array.isArray(
                archive.findings
            )
        ) {

            for (
                const finding
                of archive.findings
            ) {

                findings.push({

                    ...finding,

                    source:
                        finding.source ||
                        "archive"
                });
            }
        }


        /*
         * GENERIC EXTENSION / MIME MISMATCH
         */

        if (
            generic &&
            generic.identity &&
            generic.identity.mimeType !==
                "unknown" &&
            identity.extension &&
            detection &&
            detection.extensionMatches === false
        ) {

            const extension =
                identity.extension;


            const mimeType =
                generic.identity.mimeType;


            const expectedExtensions =
                this.getExpectedExtensions(
                    mimeType
                );


            if (
                expectedExtensions.length > 0 &&
                !expectedExtensions.includes(
                    extension
                )
            ) {

                findings.push({

                    id:
                        "extension-mime-mismatch",

                    severity:
                        "LOW",

                    confidence:
                        "MEDIUM",

                    title:
                        "Extension and MIME type differ",

                    description:
                        "The filename extension does not match the detected browser MIME type.",

                    evidence: {

                        extension,

                        mimeType,

                        expectedExtensions
                    },

                    recommendation:
                        "Verify the file type before opening or processing it.",

                    source:
                        "generic"
                });
            }
        }


        /*
         * APK FINDINGS
         */

        if (
            apk &&
            Array.isArray(
                apk.findings
            )
        ) {

            for (
                const finding
                of apk.findings
            ) {

                findings.push({

                    ...finding,

                    source:
                        finding.source ||
                        "apk"
                });
            }
        }


        return findings;
    },


    /*
     * ─────────────────────────────
     * RECOMMENDATIONS
     * ─────────────────────────────
     */

    getFindingRecommendation(
        anomalyId
    ) {

        const recommendations = {

            "unknown-format":
                "Treat the file as an unknown binary until its structure can be inspected.",

            "extension-mismatch":
                "Verify the file source and inspect the detected format before opening it.",

            "mime-mismatch":
                "Do not rely on the browser MIME type alone. Verify the file structure and source.",

            "multiple-signatures":
                "Inspect the file structure and container contents before drawing a security conclusion."
        };


        return (
            recommendations[
                anomalyId
            ] ||

            "Review the associated evidence before taking further action."
        );
    },


    /*
     * ─────────────────────────────
     * MIME → EXPEC
