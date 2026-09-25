"use strict";

/*
 * FILEGUARD
 * Analysis Plan / Router
 *
 * V1.1.0
 *
 * Determines which analyzers should run for a file.
 *
 * Routing philosophy:
 * - Generic analysis is always available.
 * - Archive analysis is enabled for containers.
 * - APK analysis is enabled for Android packages.
 * - Future specialized analyzers remain disabled until implemented.
 */


const FileGuardAnalysisPlan = {

    VERSION: "1.1.0",


    create(
        identity = {},
        detection = {}
    ) {

        const safeIdentity =
            identity &&
            typeof identity === "object"
                ? identity
                : {};


        const safeDetection =
            detection &&
            typeof detection === "object"
                ? detection
                : {};


        const candidates = [];


        /*
         * GENERIC
         *
         * Every file receives basic identity analysis.
         */

        candidates.push({

            id:
                "generic",

            reason:
                "General file identity and baseline analysis.",

            required:
                true,

            enabled:
                true,

            pending:
                false

        });


        /*
         * ARCHIVE / CONTAINER
         */

        const archiveCandidate =
            this.isArchiveCandidate(
                safeIdentity,
                safeDetection
            );


        if (archiveCandidate) {

            candidates.push({

                id:
                    "archive",

                reason:
                    "The file appears to be a ZIP-based or archive container.",

                required:
                    true,

                enabled:
                    true,

                pending:
                    false

            });
        }


        /*
         * APK
         *
         * APK is a specialized ZIP-based Android package.
         *
         * The archive analyzer runs first and supplies the
         * entry index to the APK analyzer.
         */

        const apkCandidate =
            this.isApkCandidate(
                safeIdentity,
                safeDetection
            );


        if (apkCandidate) {

            candidates.push({

                id:
                    "apk",

                reason:
                    "The file appears to be an Android application package.",

                required:
                    true,

                enabled:
                    true,

                pending:
                    false

            });
        }


        /*
         * FUTURE ANALYZERS
         *
         * These remain disabled until their dedicated
         * implementations are added.
         */

        const futureCandidates = [

            {
                id:
                    "pdf",

                enabled:
                    false,

                reason:
                    "PDF-specific structural and metadata analysis."
            },

            {
                id:
                    "office",

                enabled:
                    false,

                reason:
                    "Office document structural and macro-related analysis."
            },

            {
                id:
                    "image",

                enabled:
                    false,

                reason:
                    "Image metadata and embedded-content analysis."
            },

            {
                id:
                    "executable",

                enabled:
                    false,

                reason:
                    "PE/ELF executable analysis."
            },

            {
                id:
                    "media",

                enabled:
                    false,

                reason:
                    "Audio/video container and metadata analysis."
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
                    archiveCandidate,

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
            detection.formatId ===
                "zip"
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
            extension ===
            "apk"
        ) {

            return true;
        }


        if (
            detection &&
            detection.formatId ===
            "apk"
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
         * APK is more specific than generic/archive,
         * therefore it becomes the primary analyzer
         * whenever an APK candidate exists.
         */

        const apk =
            enabled.find(
                analyzer =>
                    analyzer.id ===
                    "apk"
            );


        if (apk) {

            return "apk";
        }


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
