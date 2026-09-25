"use strict";

/*
 * FILEGUARD
 * Core Analyzer
 *
 * V1.3
 *
 * Central orchestration layer.
 *
 * Pipeline:
 *
 * File
 * ↓
 * Identity
 * ↓
 * Cryptographic Hashes
 * ↓
 * File Detection
 * ↓
 * Specialized Analyzer
 * ↓
 * Generic Analyzer
 * ↓
 * Findings
 * ↓
 * Normalized Result
 */


const FileGuardAnalyzer = {

    VERSION: "1.3.0",


    async analyze(
        file,
        onProgress = null
    ) {

        this.validateFile(file);


        const startedAt =
            performance.now();


        /*
         * STEP 01
         * FILE IDENTITY
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
         * STEP 02
         * CRYPTOGRAPHIC HASHES
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
         * STEP 03
         * FILE DETECTION
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
         * STEP 04
         * SPECIALIZED ANALYSIS
         *
         * ZIP-based formats are routed to
         * the archive analyzer.
         */

        let archive =
            null;


        const archiveCapable =
            detection &&
            (
                detection.formatId === "zip" ||
                detection.formatId === "docx" ||
                detection.formatId === "xlsx" ||
                detection.formatId === "pptx" ||
                detection.formatId === "jar"
            );


        if (
            archiveCapable &&
            window.FileGuardArchiveAnalyzer &&
            typeof window.FileGuardArchiveAnalyzer.analyze ===
                "function"
        ) {

            this.reportProgress(
                onProgress,
                "archive",
                "running"
            );


            archive =
                await window.FileGuardArchiveAnalyzer.analyze(
                    file
                );


            this.reportProgress(
                onProgress,
                "archive",
                "completed",
                archive
            );
        }


        /*
         * STEP 05
         * GENERIC ANALYSIS
         */

        this.reportProgress(
            onProgress,
            "generic",
            "running"
        );


        let generic = null;


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


        /*
         * STEP 06
         * FINDINGS
         */

        this.reportProgress(
            onProgress,
            "findings",
            "running"
        );


        const findings =
            this.collectInitialFindings(
                identity,
                detection,
                generic,
                archive
            );


        this.reportProgress(
            onProgress,
            "findings",
            "completed",
            findings
        );


        /*
         * FINAL RESULT
         */

        const durationMs =
            Math.round(
                performance.now() -
                startedAt
            );


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


            identity,

            hashes,

            detection,

            archive,

            structure:
                archive
                    ? {
                        available:
                            true,

                        status:
                            archive.status,

                        containerType:
                            archive.containerType,

                        entryCount:
                            archive.entryCount,

                        statistics:
                            archive.statistics,

                        features:
                            archive.features
                    }
                    : (
                        generic
                            ? generic.structure
                            : null
                    ),

            metadata:
                generic
                    ? generic.metadata
                    : null,

            findings,

            analyzers: {

                generic:
                    Boolean(generic),

                archive:
                    Boolean(archive),

                apk:
                    false

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


    buildIdentity(file) {

        return {

            name:
                file.name,

            extension:
                this.getExtension(
                    file.name
                ),

            mimeType:
                file.type ||
                "unknown",

            size:
                file.size,

            lastModified:
                file.lastModified ||
                null,

            lastModifiedISO:
                file.lastModified
                    ? new Date(
                        file.lastModified
                    ).toISOString()
                    : null

        };
    },


    collectInitialFindings(
        identity,
        detection,
        generic,
        archive
    ) {

        const findings = [];


        /*
         * Detector findings.
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
                        )

                });
            }
        }


        /*
         * Archive findings.
         *
         * These are already evidence-based
         * findings produced by the archive analyzer.
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
                        "archive"

                });
            }
        }


        /*
         * Generic MIME mismatch fallback.
         */

        if (
            generic &&
            generic.identity &&
            generic.identity.mimeType !==
                "unknown" &&
            identity.extension &&
            !detection
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


        return findings;
    },


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
            recommendations[anomalyId] ||
            "Review the associated evidence before taking further action."
        );
    },


    getExpectedExtensions(
        mimeType
    ) {

        const map = {

            "application/pdf": [
                "pdf"
            ],

            "image/jpeg": [
                "jpg",
                "jpeg"
            ],

            "image/png": [
                "png"
            ],

            "image/gif": [
                "gif"
            ],

            "image/webp": [
                "webp"
            ],

            "text/plain": [
                "txt",
                "log"
            ],

            "application/json": [
                "json"
            ],

            "text/csv": [
                "csv"
            ],

            "application/zip": [
                "zip"
            ],

            "application/vnd.android.package-archive": [
                "apk"
            ],

            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [
                "docx"
            ],

            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [
                "xlsx"
            ],

            "application/vnd.openxmlformats-officedocument.presentationml.presentation": [
                "pptx"
            ]

        };


        return (
            map[mimeType] ||
            []
        );
    },


    getExtension(fileName) {

        if (
            typeof fileName !== "string" ||
            fileName.length === 0
        ) {

            return "";
        }


        const lastDot =
            fileName.lastIndexOf(".");


        if (
            lastDot <= 0 ||
            lastDot === fileName.length - 1
        ) {

            return "";
        }


        return fileName
            .slice(
                lastDot + 1
            )
            .toLowerCase();
    },


    reportProgress(
        callback,
        step,
        status,
        data = null
    ) {

        if (
            typeof callback !==
                "function"
        ) {

            return;
        }


        callback({

            step,

            status,

            data,

            timestamp:
                Date.now()

        });
    },


    validateFile(file) {

        if (
            !(file instanceof File)
        ) {

            throw new TypeError(
                "FileGuardAnalyzer requires a File object."
            );
        }
    }

};


window.FileGuardAnalyzer =
    FileGuardAnalyzer;
