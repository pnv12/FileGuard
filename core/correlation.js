"use strict";

const FileGuardCorrelation = {
    VERSION: "1.0.0",

    correlate(findings, context = {}) {
        if (!Array.isArray(findings)) {
            return [];
        }

        const normalized =
            window.FileGuardFindings &&
            typeof window.FileGuardFindings.normalize === "function"
                ? window.FileGuardFindings.normalize(findings)
                : findings;

        const correlations = [];

        this.ruleMultipleAnomalies(
            normalized,
            correlations
        );

        this.ruleContainerAnomalies(
            normalized,
            context,
            correlations
        );

        this.ruleUnknownFormatSignals(
            normalized,
            context,
            correlations
        );

        this.ruleArchiveStructureSignals(
            normalized,
            context,
            correlations
        );

        return this.deduplicate(
            correlations
        );
    },


    ruleMultipleAnomalies(
        findings,
        output
    ) {
        const structural =
            findings.filter(f =>
                f.category === "detection" ||
                f.category === "structure"
            );

        if (structural.length < 2) {
            return;
        }

        const ids =
            structural.map(f => f.id);

        output.push(
            this.createCorrelation(
                "multiple-structural-signals",
                "Multiple structural signals require review",
                "The file contains more than one independent structural or detection signal that should be considered together.",
                structural,
                {
                    severity: "LOW",
                    confidence: "MEDIUM",
                    recommendation:
                        "Review the individual findings and their evidence before opening or processing the file."
                }
            )
        );
    },


    ruleContainerAnomalies(
        findings,
        context,
        output
    ) {
        if (!context.archive) {
            return;
        }

        const archiveFindings =
            findings.filter(
                f => f.source === "archive"
            );

        if (archiveFindings.length < 2) {
            return;
        }

        output.push(
            this.createCorrelation(
                "multiple-container-signals",
                "Multiple container-structure signals",
                "Several archive-level observations occur in the same container and should be investigated together.",
                archiveFindings,
                {
                    severity: "MEDIUM",
                    confidence: "MEDIUM",
                    recommendation:
                        "Inspect the listed archive findings and the affected entries before extracting or executing contained content."
                }
            )
        );
    },


    ruleUnknownFormatSignals(
        findings,
        context,
        output
    ) {
        if (
            !context.detection ||
            context.detection.formatId !== "unknown"
        ) {
            return;
        }

        const related =
            findings.filter(
                f =>
                    f.source === "detector" ||
                    f.source === "generic"
            );

        if (related.length === 0) {
            return;
        }

        output.push(
            this.createCorrelation(
                "unknown-format-with-signals",
                "Unknown format with additional observations",
                "The file format could not be confidently identified and additional file characteristics were observed.",
                related,
                {
                    severity: "LOW",
                    confidence: "MEDIUM",
                    recommendation:
                        "Treat the file as unidentified and inspect its source and structure before opening it."
                }
            )
        );
    },


    ruleArchiveStructureSignals(
        findings,
        context,
        output
    ) {
        if (!context.archive) {
            return;
        }

        const features =
            context.archive.features || {};

        const suspiciousFeatures = [];

        if (features.pathTraversal) {
            suspiciousFeatures.push(
                "pathTraversal"
            );
        }

        if (features.absolutePaths) {
            suspiciousFeatures.push(
                "absolutePaths"
            );
        }

        if (features.encryptedEntries) {
            suspiciousFeatures.push(
                "encryptedEntries"
            );
        }

        if (features.highCompressionRatio) {
            suspiciousFeatures.push(
                "highCompressionRatio"
            );
        }

        if (
            features.nestedArchives ||
            features.nestedContainers
        ) {
            suspiciousFeatures.push(
                "nestedArchives"
            );
        }

        if (suspiciousFeatures.length < 2) {
            return;
        }

        const related =
            findings.filter(
                f => f.source === "archive"
            );

        output.push(
            this.createCorrelation(
                "combined-archive-features",
                "Multiple archive features require investigation",
                "The container exposes multiple structural characteristics that can increase analysis complexity or require additional inspection.",
                related,
                {
                    severity: "MEDIUM",
                    confidence: "HIGH",
                    recommendation:
                        "Inspect the affected entries individually and avoid automatically extracting or executing their contents."
                },
                {
                    features:
                        suspiciousFeatures
                }
            )
        );
    },


    createCorrelation(
        id,
        title,
        description,
        relatedFindings,
        options = {},
        extraEvidence = null
    ) {
        return {
            id:
                `correlation-${id}`,

            severity:
                options.severity || "LOW",

            confidence:
                options.confidence || "MEDIUM",

            title,

            description,

            evidence: {
                type: "correlation",
                relatedFindingIds:
                    relatedFindings.map(
                        finding => finding.id
                    ),
                relatedFindings:
                    relatedFindings.map(
                        finding => ({
                            id: finding.id,
                            title: finding.title,
                            severity: finding.severity,
                            confidence: finding.confidence,
                            source: finding.source
                        })
                    ),
                extra:
                    extraEvidence
            },

            recommendation:
                options.recommendation ||
                "Review the related findings and their evidence.",

            source: "correlation",

            category: "correlation",

            status: "open"
        };
    },


    deduplicate(correlations) {
        const map = new Map();

        for (const correlation of correlations) {
            if (!correlation || !correlation.id) {
                continue;
            }

            if (
                !map.has(correlation.id)
            ) {
                map.set(
                    correlation.id,
                    correlation
                );
            }
        }

        return Array.from(
            map.values()
        );
    },


    summarize(correlations) {
        if (!Array.isArray(correlations)) {
            return {
                total: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            };
        }

        const summary = {
            total: correlations.length,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        };

        for (const item of correlations) {
            const severity =
                String(
                    item.severity || "INFO"
                ).toLowerCase();

            if (
                Object.prototype.hasOwnProperty.call(
                    summary,
                    severity
                )
            ) {
                summary[severity]++;
            }
        }

        return summary;
    }
};

window.FileGuardCorrelation =
    FileGuardCorrelation;
