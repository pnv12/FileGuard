"use strict";

/*
 * FILEGUARD
 * Core Analyzer
 *
 * V1.1
 *
 * Central orchestration layer for file analysis.
 *
 * Responsibilities:
 * - validate input
 * - collect file identity
 * - calculate cryptographic hashes
 * - run the generic analyzer
 * - expose analysis progress
 * - return one normalized analysis result
 */


const FileGuardAnalyzer = {

    /*
     * ─────────────────────────────
     * PUBLIC API
     * ─────────────────────────────
     */

    async analyze(file, onProgress = null) {

        this.validateFile(file);

        const startedAt = performance.now();


        /*
         * STEP 1
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
         * STEP 2
         * CRYPTOGRAPHIC HASHES
         */

        this.reportProgress(
            onProgress,
            "hashes",
            "running"
        );


        if (
            !window.FileGuardHash ||
            typeof window.FileGuardHash.calculateAll !== "function"
        ) {
            throw new Error(
                "FileGuardHash module is not available."
            );
        }


        const hashes =
            await window.FileGuardHash.calculateAll(file);


        this.reportProgress(
            onProgress,
            "hashes",
            "completed",
            hashes
        );


        /*
         * STEP 3
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
            typeof window.FileGuardGenericAnalyzer.analyze === "function"
        ) {
            generic =
                await window.FileGuardGenericAnalyzer.analyze(file);
        }


        this.reportProgress(
            onProgress,
            "generic",
            "completed",
            generic
        );


        /*
         * STEP 4
         * INITIAL FINDINGS
         */

        const findings =
            this.collectInitialFindings(
                identity,
                generic
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
                performance.now() - startedAt
            );


        const result = {

            status: "completed",

            analyzer: "generic",

            durationMs,

            file: {
                name: file.name,
                size: file.size,
                type: file.type || "unknown",
                lastModified:
                    file.lastModified || null
            },

            identity,

            hashes,

            structure:
                generic
                    ? generic.structure
                    : null,

            metadata:
                generic
                    ? generic.metadata
                    : null,

            findings,

            analyzers: {
                generic: Boolean(generic),
                archive: false,
                apk: false
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
     * FILE IDENTITY
     * ─────────────────────────────
     */

    buildIdentity(file) {

        return {

            name: file.name,

            extension:
                this.getExtension(file.name),

            mimeType:
                file.type || "unknown",

            size:
                file.size,

            lastModified:
                file.lastModified || null,

            lastModifiedISO:
                file.lastModified
                    ? new Date(
                        file.lastModified
                    ).toISOString()
                    : null

        };
    },


    /*
     * ─────────────────────────────
     * INITIAL FINDINGS
     * ─────────────────────────────
     *
     * V1 intentionally keeps this
     * conservative.
     *
     * No malware verdict is generated
     * without actual security evidence.
     */

    collectInitialFindings(
        identity,
        generic
    ) {

        const findings = [];


        /*
         * Extension / MIME mismatch
         *
         * This is only an informational
         * structural signal at this stage.
         */

        if (
            generic &&
            generic.identity &&
            generic.identity.mimeType !== "unknown" &&
            identity.extension
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
                        "Verify the file type before opening or processing it."

                });
            }
        }


        return findings;
    },


    /*
     * ─────────────────────────────
     * MIME MAPPING
     * ─────────────────────────────
     */

    getExpectedExtensions(mimeType) {

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


        return map[mimeType] || [];
    },


    /*
     * ─────────────────────────────
     * EXTENSION
     * ─────────────────────────────
     */

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
            .slice(lastDot + 1)
            .toLowerCase();
    },


    /*
     * ─────────────────────────────
     * PROGRESS
     * ─────────────────────────────
     */

    reportProgress(
        callback,
        step,
        status,
        data = null
    ) {

        if (
            typeof callback !== "function"
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


    /*
     * ─────────────────────────────
     * VALIDATION
     * ─────────────────────────────
     */

    validateFile(file) {

        if (!(file instanceof File)) {

            throw new TypeError(
                "FileGuardAnalyzer requires a File object."
            );
        }
    }

};


/*
 * Expose the analyzer globally.
 */

window.FileGuardAnalyzer =
    FileGuardAnalyzer;
