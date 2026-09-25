"use strict";

const FileGuardFindings = {
    VERSION: "1.0.0",

    SEVERITIES: ["HIGH", "MEDIUM", "LOW", "INFO"],
    CONFIDENCES: ["HIGH", "MEDIUM", "LOW", "UNKNOWN"],

    normalize(findings) {
        if (!Array.isArray(findings)) {
            return [];
        }

        const result = [];

        for (const raw of findings) {
            const item = this.normalizeOne(raw);

            if (item) {
                result.push(item);
            }
        }

        return this.deduplicate(result);
    },

    normalizeOne(raw) {
        if (!raw || typeof raw !== "object") {
            return null;
        }

        const severity = this.normalizeSeverity(raw.severity);
        const confidence = this.normalizeConfidence(raw.confidence);
        const id = this.normalizeId(raw.id, raw.title);

        return {
            id,
            severity,
            confidence,

            title: String(
                raw.title || "Untitled finding"
            ),

            description: String(
                raw.description || ""
            ),

            evidence:
                raw.evidence === undefined
                    ? null
                    : raw.evidence,

            recommendation: String(
                raw.recommendation ||
                "Review the associated evidence before taking further action."
            ),

            source: String(
                raw.source || "unknown"
            ),

            category: String(
                raw.category ||
                this.getCategory(raw.source)
            ),

            status: String(
                raw.status || "open"
            )
        };
    },

    normalizeSeverity(value) {
        const valueUpper = String(
            value || "INFO"
        ).toUpperCase();

        if (this.SEVERITIES.includes(valueUpper)) {
            return valueUpper;
        }

        return "INFO";
    },

    normalizeConfidence(value) {
        const valueUpper = String(
            value || "UNKNOWN"
        ).toUpperCase();

        if (this.CONFIDENCES.includes(valueUpper)) {
            return valueUpper;
        }

        return "UNKNOWN";
    },

    normalizeId(id, title) {
        if (
            id !== undefined &&
            id !== null &&
            String(id).trim() !== ""
        ) {
            return String(id)
                .trim()
                .toLowerCase()
                .replace(/[^a-z0-9._-]+/g, "-");
        }

        const base = String(
            title || "finding"
        )
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "");

        return base || "finding";
    },

    getCategory(source) {
        const map = {
            detector: "detection",
            archive: "structure",
            generic: "identity",
            apk: "android",
            correlation: "correlation"
        };

        return (
            map[String(source || "").toLowerCase()] ||
            "general"
        );
    },

    deduplicate(findings) {
        const map = new Map();

        for (const finding of findings) {
            const key = this.getDedupKey(finding);
            const existing = map.get(key);

            if (!existing) {
                map.set(key, finding);
                continue;
            }

            map.set(
                key,
                this.mergeFinding(existing, finding)
            );
        }

        return this.sort(
            Array.from(map.values())
        );
    },

    getDedupKey(finding) {
        return [
            finding.id,
            finding.title.toLowerCase(),
            finding.source
        ].join("|");
    },

    mergeFinding(a, b) {
        return {
            ...a,

            severity: this.maxSeverity(
                a.severity,
                b.severity
            ),

            confidence: this.maxConfidence(
                a.confidence,
                b.confidence
            ),

            description:
                a.description || b.description,

            evidence:
                a.evidence !== null &&
                a.evidence !== undefined
                    ? a.evidence
                    : b.evidence,

            recommendation:
                a.recommendation ||
                b.recommendation,

            category:
                a.category ||
                b.category,

            status:
                a.status === "open"
                    ? a.status
                    : b.status
        };
    },

    maxSeverity(a, b) {
        const rank = {
            INFO: 0,
            LOW: 1,
            MEDIUM: 2,
            HIGH: 3
        };

        return rank[b] > rank[a] ? b : a;
    },

    maxConfidence(a, b) {
        const rank = {
            UNKNOWN: 0,
            LOW: 1,
            MEDIUM: 2,
            HIGH: 3
        };

        return rank[b] > rank[a] ? b : a;
    },

    sort(findings) {
        const rank = {
            HIGH: 0,
            MEDIUM: 1,
            LOW: 2,
            INFO: 3
        };

        return findings
            .slice()
            .sort((a, b) => {
                const severity =
                    rank[a.severity] -
                    rank[b.severity];

                if (severity !== 0) {
                    return severity;
                }

                const sourceCompare =
                    a.source.localeCompare(
                        b.source
                    );

                if (sourceCompare !== 0) {
                    return sourceCompare;
                }

                return a.title.localeCompare(
                    b.title
                );
            });
    },

    summarize(findings) {
        const list = this.normalize(
            findings
        );

        const counts = {
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            INFO: 0
        };

        const sources = new Set();
        const categories = new Set();

        for (const finding of list) {
            counts[finding.severity]++;

            sources.add(
                finding.source
            );

            categories.add(
                finding.category
            );
        }

        return {
            total: list.length,

            counts,

            actionable:
                counts.HIGH +
                counts.MEDIUM +
                counts.LOW,

            high: counts.HIGH,
            medium: counts.MEDIUM,
            low: counts.LOW,
            info: counts.INFO,

            sources:
                Array.from(sources),

            categories:
                Array.from(categories)
        };
    },

    validate(finding) {
        if (
            !finding ||
            typeof finding !== "object"
        ) {
            return false;
        }

        return (
            typeof finding.id === "string" &&
            this.SEVERITIES.includes(
                finding.severity
            ) &&
            this.CONFIDENCES.includes(
                finding.confidence
            ) &&
            typeof finding.title === "string" &&
            typeof finding.description === "string" &&
            typeof finding.source === "string"
        );
    }
};

window.FileGuardFindings =
    FileGuardFindings;
