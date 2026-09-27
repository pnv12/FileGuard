"use strict";

const FileGuardAnalyzer = {
    VERSION: "2.0.0",

    async analyze(file, onProgress = null) {
        if (!(file instanceof File)) {
            throw new TypeError("Invalid File object.");
        }

        const start = performance.now();
        const progress = (step, status, data = null) => {
            if (typeof onProgress === "function") {
                onProgress({
                    step,
                    status,
                    data,
                    timestamp: Date.now()
                });
            }
        };

        progress("identity", "running");
        const identity = this.identity(file);
        progress("identity", "completed", identity);

        progress("hashes", "running");
        this.require("FileGuardHash", "calculateAll");
        const hashes =
            await FileGuardHash.calculateAll(file);
        progress("hashes", "completed", hashes);

        progress("detection", "running");
        this.require("FileGuardDetector", "detect");
        const detection =
            await FileGuardDetector.detect(file);
        progress("detection", "completed", detection);

        progress("plan", "running");
        this.require("FileGuardAnalysisPlan", "create");
        const plan =
            FileGuardAnalysisPlan.create(
                identity,
                detection
            );
        progress("plan", "completed", plan);

        let generic = null;
        let archive = null;
        let apk = null;

        if (this.has(plan, "generic")) {
            progress("generic", "running");

            if (
                window.FileGuardGenericAnalyzer &&
                typeof FileGuardGenericAnalyzer.analyze ===
                    "function"
            ) {
                generic =
                    await FileGuardGenericAnalyzer.analyze(
                        file
                    );
            }

            progress("generic", "completed", generic);
        }

        if (this.has(plan, "archive")) {
            progress("archive", "running");

            if (
                window.FileGuardArchiveAnalyzer &&
                typeof FileGuardArchiveAnalyzer.analyze ===
                    "function"
            ) {
                archive =
                    await FileGuardArchiveAnalyzer.analyze(
                        file
                    );
            }

            progress("archive", "completed", archive);
        }

        if (this.has(plan, "apk")) {
            progress("apk", "running");

            if (
                window.FileGuardAPKAnalyzer &&
                typeof FileGuardAPKAnalyzer.analyze ===
                    "function"
            ) {
                apk =
                    await FileGuardAPKAnalyzer.analyze(
                        file,
                        {
                            identity,
                            detection,
                            plan,
                            archive
                        }
                    );
            }

            progress("apk", "completed", apk);
        }

        progress("findings", "running");

        let findings =
            this.collectFindings(
                identity,
                detection,
                generic,
                archive,
                apk
            );

        if (
            window.FileGuardFindings &&
            typeof FileGuardFindings.normalize ===
                "function"
        ) {
            findings =
                FileGuardFindings.normalize(
                    findings
                );
        }

        const findingSummary =
            window.FileGuardFindings &&
            typeof FileGuardFindings.summarize ===
                "function"
                ? FileGuardFindings.summarize(
                    findings
                )
                : {
                    total: findings.length
                };

        progress("findings", "completed", {
            findings,
            summary: findingSummary
        });

        progress("correlation", "running");

        let correlations = [];

        if (
            window.FileGuardCorrelation &&
            typeof FileGuardCorrelation.correlate ===
                "function"
        ) {
            correlations =
                FileGuardCorrelation.correlate(
                    findings,
                    {
                        identity,
                        detection,
                        plan,
                        generic,
                        archive,
                        apk
                    }
                );
        }

        const correlationSummary =
            window.FileGuardCorrelation &&
            typeof FileGuardCorrelation.summarize ===
                "function"
                ? FileGuardCorrelation.summarize(
                    correlations
                )
                : {
                    total: correlations.length
                };

        progress("correlation", "completed", {
            correlations,
            summary: correlationSummary
        });

        progress("evidence", "running");

        const evidence =
            this.evidence(
                detection,
                archive,
                findings,
                correlations,
                apk
            );

        const evidenceSummary =
            window.FileGuardEvidence &&
            typeof FileGuardEvidence.summarize ===
                "function"
                ? FileGuardEvidence.summarize(
                    evidence
                )
                : {
                    total: evidence.length
                };

        progress("evidence", "completed", {
            evidence,
            summary: evidenceSummary
        });

        const result = {
            status: "completed",
            analyzer: "core",
            analyzerVersion: this.VERSION,

            durationMs: Math.round(
                performance.now() - start
            ),

            file: {
                name: file.name,
                size: file.size,
                type: file.type || "unknown",
                lastModified:
                    file.lastModified || null
            },

            identity,
            hashes,
            detection,
            analysisPlan: plan,

            generic,
            archive,
            apk,

            structure:
                archive || generic
                    ? this.structure(
                        archive,
                        generic
                    )
                    : null,

            metadata:
                generic &&
                generic.metadata
                    ? generic.metadata
                    : null,

            findings,
            findingSummary,

            correlations,
            correlationSummary,

            evidence,
            evidenceSummary,

            analyzers: {
                generic: !!generic,
                archive: !!archive,
                apk: !!apk,
                correlation:
                    correlations.length > 0
            }
        };

        progress(
            "complete",
            "completed",
            result
        );

        return result;
    },

    require(name, method) {
        const module = window[name];

        if (!module) {
            throw new Error(
                `${name} module is not available.`
            );
        }

        if (
            method &&
            typeof module[method] !==
                "function"
        ) {
            throw new Error(
                `${name}.${method} is not available.`
            );
        }
    },

    identity(file) {
        const name = file.name || "";
        const dot = name.lastIndexOf(".");

        return {
            name,
            filename: name,

            extension:
                dot > 0
                    ? name
                        .slice(dot + 1)
                        .toLowerCase()
                    : "",

            mimeType:
                file.type || "unknown",

            size: file.size,

            lastModified:
                file.lastModified || null
        };
    },

    has(plan, id) {
        return !!(
            plan &&
            Array.isArray(
                plan.enabledAnalyzers
            ) &&
            plan.enabledAnalyzers.includes(id)
        );
    },

    collectFindings(
        identity,
        detection,
        generic,
        archive,
        apk
    ) {
        const result = [];

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
                if (!anomaly) {
                    continue;
                }

                result.push({
                    id:
                        `detector-${anomaly.id || "anomaly"}`,

                    severity:
                        anomaly.severity || "INFO",

                    confidence:
                        anomaly.confidence ||
                        detection.confidenceLevel ||
                        "MEDIUM",

                    title:
                        anomaly.title ||
                        "File detection anomaly",

                    description:
                        anomaly.description ||
                        "The detector identified a characteristic that requires review.",

                    evidence:
                        anomaly.evidence || null,

                    recommendation:
                        this.recommendation(
                            anomaly.id
                        ),

                    source: "detector",
                    category: "detection"
                });
            }
        }

        if (
            detection &&
            detection.extensionMatches === false
        ) {
            result.push({
                id: "extension-mismatch",
                severity: "LOW",
                confidence: "HIGH",
                title:
                    "Filename extension does not match detected format.",
                description:
                    "The file extension differs from the format detected from its contents.",
                evidence: {
                    extension:
                        identity.extension,
                    detectedFormat:
                        detection.format ||
                        detection.primary ||
                        "unknown"
                },
                recommendation:
                    "Verify the file source and detected format before opening it.",
                source: "detector",
                category: "identity"
            });
        }

        for (
            const source of [
                archive,
                generic,
                apk
            ]
        ) {
            if (
                source &&
                Array.isArray(
                    source.findings
                )
            ) {
                result.push(
                    ...source.findings.map(
                        finding => ({
                            ...finding,
                            source:
                                finding.source ||
                                source.analyzer ||
                                "analyzer"
                        })
                    )
                );
            }
        }

        return result;
    },

    evidence(
        detection,
        archive,
        findings,
        correlations,
        apk
    ) {
        if (!window.FileGuardEvidence) {
            return [];
        }

        const groups = [];

        if (
            typeof FileGuardEvidence.fromDetection ===
            "function"
        ) {
            groups.push(
                FileGuardEvidence.fromDetection(
                    detection
                )
            );
        }

        if (
            typeof FileGuardEvidence.fromArchive ===
            "function"
        ) {
            groups.push(
                FileGuardEvidence.fromArchive(
                    archive
                )
            );
        }

        if (
            typeof FileGuardEvidence.fromFindings ===
            "function"
        ) {
            groups.push(
                FileGuardEvidence.fromFindings(
                    findings
                ),
                FileGuardEvidence.fromFindings(
                    correlations
                )
            );
        }

        if (
            apk &&
            Array.isArray(apk.evidence)
        ) {
            groups.push(apk.evidence);
        }

        if (
            typeof FileGuardEvidence.merge ===
            "function"
        ) {
            return FileGuardEvidence.merge(
                ...groups
            );
        }

        return groups.flat();
    },

    structure(archive, generic) {
        if (archive) {
            return {
                available: true,
                status: archive.status || "unknown",
                format: archive.format || null,
                containerType:
                    archive.containerType || null,
                entryCount:
                    archive.entryCount || 0,
                statistics:
                    archive.statistics || null,
                features:
                    archive.features || null
            };
        }

        return (
            generic.structure || {
                available: false
            }
        );
    },

    recommendation(id) {
        const map = {
            "unknown-format":
                "Treat the file as unidentified until its structure and source are understood.",

            "extension-mismatch":
                "Verify the file source and detected format before opening it.",

            "mime-mismatch":
                "Verify the file structure instead of relying only on its MIME type.",

            "multiple-signatures":
                "Inspect the file structure before drawing a security conclusion."
        };

        return (
            map[id] ||
            "Review the associated evidence before taking further action."
        );
    }
};

window.FileGuardAnalyzer =
    FileGuardAnalyzer;
