"use strict";

/*
 * FILEGUARD
 * Analysis Plan / Router
 *
 * V1.0.0
 *
 * Converts file identity + detection results
 * into a deterministic list of analyzers that
 * should run.
 *
 * The router decides WHAT should be analyzed.
 * Individual analyzers decide HOW to analyze it.
 *
 * No security verdicts are produced here.
 */


const FileGuardAnalysisPlan = {

    VERSION: "1.0.0",


    /*
     * ─────────────────────────────
     * MAIN API
     * ─────────────────────────────
     */

    create(identity, detection) {

        const safeIdentity =
            identity || {};

        const safeDetection =
            detection || {};


        const candidates = [];


        /*
         * GENERIC ANALYSIS
         *
         * Every file receives the generic analyzer.
         */

        candidates.push({
            id: "generic",
            reason: "Universal file identity and baseline analysis.",
            required: true,
            enabled: true
        });


        /*
         * ARCHIVE / CONTAINER ANALYSIS
         *
         * ZIP-based formats are routed here.
         *
         * The archive analyzer itself determines whether
         * the container is ZIP, APK, JAR, Office Open XML,
         * or another ZIP-based structure.
         */

        if (
            this.isArchiveCandidate(
                safeIdentity,
                safeDetection
            )
        ) {

            candidates.push({
                id: "archive",
                reason: "The file appears to be a ZIP-based container.",
                required: true,
                enabled: true
            });
        }


        /*
         * APK ANALYSIS
         *
         * The deep APK analyzer does not exist yet.
         *
         * We still expose the routing decision now so the
         * architecture is ready for it.
         */

        const apkCandidate =
            this.isApkCandidate(
                safeIdentity,
                safeDetection
            );


        if (apkCandidate) {

            candidates.push({
                id: "apk",
                reason: "The file appears to be an Android application package.",
                required: true,
                enabled: false,
                pending: true
            });
        }


        /*
         * FUTURE ANALYZERS
         *
         * These are deliberately not enabled yet.
         *
         * The router is designed so they can be added
         * without changing the central analyzer pipeline.
         */

        const futureCandidates = [
            {
                id: "pdf",
                enabled: false,
                reason: "PDF-specific structural and metadata analysis."
            },

            {
                id: "office",
                enabled: false,
                reason: "Office document structural and macro-related analysis."
            },

            {
                id: "image",
                enabled: false,
                reason: "Image metadata and embedded-content analysis."
            },

            {
                id: "executable",
                enabled: false,
                reason: "PE/ELF executable analysis."
            },

            {
                id: "media",
                enabled: false,
                reason: "Audio/video container and metadata analysis."
            }
        ];


        const enabledAnalyzers =
            candidates
                .filter(
                    analyzer =>
                        analyzer.enabled
                )
                .map(
                    analyzer =>
                        analyzer.id
                );


        const pendingAnalyzers =
            candidates
                .filter(
                    analyzer =>
                        analyzer.pending === true
                )
                .map(
                    analyzer =>
                        analyzer.id
                );


        return {

            version:
                this.VERSION,

            generatedAt:
                Date.now(),

            primaryAnalyzer:
                this.selectPrimaryAnalyzer(
                    candidates
                ),

            candidates,

            futureCandidates,

            enabledAnalyzers,

            pendingAnalyzers,

            flags: {

                containerCandidate:
                    this.isArchiveCandidate(
                        safeIdentity,
                        safeDetection
                    ),

                apkCandidate,

                unknownFormat:
                    safeDetection.formatId ===
                    "unknown"
            }

        };
    },


    /*
     * ─────────────────────────────
     * ARCHIVE ROUTING
     * ─────────────────────────────
     */

    isArchiveCandidate(
        identity,
        detection
    ) {

        if (
            detection &&
            detection.formatId === "zip"
        ) {
            return true;
        }


        const extension =
            String(
                identity.extension ||
                ""
            ).toLowerCase();


        const archiveExtensions = [

            "zip",
            "apk",
            "jar",

            "docx",
            "xlsx",
            "pptx",

            "odt",
            "ods",
            "odp",

            "epub",

            "vsix",
            "crx"

        ];


        if (
            archiveExtensions.includes(
                extension
            )
        ) {
            return true;
        }


        const mimeType =
            String(
                identity.mimeType ||
                ""
            ).toLowerCase();


        const archiveMimes = [

            "application/zip",

            "application/java-archive",

            "application/vnd.android.package-archive",

            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",

            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",

            "application/vnd.openxmlformats-officedocument.presentationml.presentation",

            "application/epub+zip",

            "application/x-chrome-extension"

        ];


        return archiveMimes.includes(
            mimeType
        );
    },


    /*
     * ─────────────────────────────
     * APK ROUTING
     * ─────────────────────────────
     */

    isApkCandidate(
        identity,
        detection
    ) {

        const extension =
            String(
                identity.extension ||
                ""
            ).toLowerCase();


        if (
            extension === "apk"
        ) {
            return true;
        }


        if (
            detection &&
            detection.formatId === "apk"
        ) {
            return true;
        }


        if (
            String(
                identity.mimeType ||
                ""
            ).toLowerCase() ===
            "application/vnd.android.package-archive"
        ) {
            return true;
        }


        return false;
    },


    /*
     * ─────────────────────────────
     * PRIMARY ANALYZER
     * ─────────────────────────────
     */

    selectPrimaryAnalyzer(
        candidates
    ) {

        const enabled =
            candidates.filter(
                analyzer =>
                    analyzer.enabled
            );


        /*
         * Archive takes precedence over generic
         * whenever a container is detected.
         */

        const archive =
            enabled.find(
                analyzer =>
                    analyzer.id ===
                    "archive"
            );


        if (archive) {
            return "archive";
        }


        const generic =
            enabled.find(
                analyzer =>
                    analyzer.id ===
                    "generic"
            );


        if (generic) {
            return "generic";
        }


        return null;
    }

};


window.FileGuardAnalysisPlan =
    FileGuardAnalysisPlan;
