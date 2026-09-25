"use strict";

/*
 * FILEGUARD
 * APK Analyzer
 *
 * V1.0.0
 *
 * Deep local-first Android APK analysis.
 *
 * This analyzer:
 * - validates APK structure;
 * - inspects AndroidManifest.xml;
 * - extracts basic package/application metadata;
 * - detects permissions;
 * - detects exported components;
 * - checks debuggable / backup / cleartext settings;
 * - inventories DEX files;
 * - inventories native libraries and architectures;
 * - inventories APK signature files;
 * - extracts selected textual indicators;
 * - produces findings and evidence.
 *
 * IMPORTANT:
 * This analyzer does NOT claim that an APK is malware.
 * It reports observable characteristics only.
 */


const FileGuardAPKAnalyzer = {

    VERSION: "1.0.0",

    MAX_TEXT_SCAN_SIZE: 8 * 1024 * 1024,

    MAX_STRING_LENGTH: 200,

    MAX_STRINGS: 500,

    APK_MAGIC: 0x04034B50,

    ZIP_LOCAL_FILE_HEADER: 0x04034B50,

    ZIP64_EXTRA_FIELD: 0x0001,

    COMPRESSION_STORE: 0,

    COMPRESSION_DEFLATE: 8,


    /*
     * ─────────────────────────────
     * MAIN API
     * ─────────────────────────────
     */

    async analyze(file, context = {}) {

        this.validateFile(file);

        const startedAt =
            performance.now();


        const result = {

            analyzer:
                "apk",

            analyzerVersion:
                this.VERSION,

            status:
                "unknown",

            identity: {

                packageName:
                    null,

                versionName:
                    null,

                versionCode:
                    null,

                minSdk:
                    null,

                targetSdk:
                    null,

                compileSdk:
                    null

            },

            application: {

                label:
                    null,

                debuggable:
                    null,

                allowBackup:
                    null,

                usesCleartextTraffic:
                    null

            },

            permissions: [],

            components: {

                activities: [],

                services: [],

                receivers: [],

                providers: []

            },

            exportedComponents: [],

            dex: [],

            nativeLibraries: [],

            nativeArchitectures: [],

            signatures: [],

            files: {

                manifest:
                    false,

                dex:
                    0,

                nativeLibraries:
                    0,

                signatureFiles:
                    0

            },

            strings: {

                urls: [],

                domains: [],

                ipAddresses: [],

                interesting: []

            },

            findings: [],

            evidence: [],

            limitations: [],

            statistics: {

                entries:
                    0,

                files:
                    0,

                directories:
                    0,

                totalUncompressedBytes:
                    0

            },

            durationMs:
                null

        };


        /*
         * APK files are ZIP containers.
         *
         * Prefer the already completed archive
         * analysis supplied by the core pipeline.
         */

        const archive =
            context.archive || null;


        if (
            archive &&
            Array.isArray(archive.entries)
        ) {

            result.statistics.entries =
                archive.entries.length;

            result.statistics.files =
                archive.statistics &&
                Number.isFinite(
                    archive.statistics.files
                )
                    ? archive.statistics.files
                    : archive.entries.filter(
                        entry =>
                            entry.type !==
                            "directory"
                    ).length;

            result.statistics.directories =
                archive.statistics &&
                Number.isFinite(
                    archive.statistics.directories
                )
                    ? archive.statistics.directories
                    : archive.entries.filter(
                        entry =>
                            entry.type ===
                            "directory"
                    ).length;

            result.statistics.totalUncompressedBytes =
                archive.statistics &&
                Number.isFinite(
                    archive.statistics.uncompressedBytes
                )
                    ? archive.statistics.uncompressedBytes
                    : 0;
        }


        const buffer =
            await file.arrayBuffer();

        const bytes =
            new Uint8Array(buffer);


        /*
         * BASIC APK VALIDATION
         */

        if (
            bytes.length < 4 ||
            this.readUInt32LE(bytes, 0) !==
                this.APK_MAGIC
        ) {

            result.status =
                "invalid";

            result.findings.push(
                this.finding(
                    "apk-invalid-zip-signature",
                    "MEDIUM",
                    "HIGH",
                    "APK ZIP signature was not found.",
                    "The file was routed to APK analysis but does not begin with a valid ZIP local-file signature.",
                    {
                        expected:
                            "0x04034b50"
                    },
                    "Do not treat the file as a valid APK until its container structure is verified."
                )
            );

            result.durationMs =
                Math.round(
                    performance.now() -
                    startedAt
                );

            return result;
        }


        /*
         * ENTRY INDEX
         */

        const entries =
            Array.isArray(
                archive &&
                archive.entries
            )
                ? archive.entries
                : [];


        const entryMap =
            new Map();


        for (const entry of entries) {

            if (
                entry &&
                typeof entry.name ===
                    "string"
            ) {

                entryMap.set(
                    entry.name,
                    entry
                );
            }
        }


        /*
         * MANIFEST
         */

        const manifestEntry =
            this.findEntry(
                entries,
                "AndroidManifest.xml"
            );


        if (manifestEntry) {

            result.files.manifest =
                true;


            const manifestBytes =
                await this.extractEntry(
                    bytes,
                    manifestEntry
                );


            if (manifestBytes) {

                const manifest =
                    this.parseBinaryXML(
                        manifestBytes
                    );


                if (manifest) {

                    this.analyzeManifest(
                        manifest,
                        result
                    );

                } else {

                    result.limitations.push(
                        "AndroidManifest.xml was found, but binary AXML parsing was not completed."
                    );

                    result.findings.push(
                        this.finding(
                            "manifest-parse-unavailable",
                            "INFO",
                            "MEDIUM",
                            "AndroidManifest.xml was found but could not be fully parsed.",
                            "The APK contains the Android manifest, but the current local parser could not reconstruct its XML structure.",
                            {
                                file:
                                    "AndroidManifest.xml",
                                size:
                                    manifestBytes.length
                            },
                            "Use a dedicated Android binary XML parser for complete manifest inspection."
                        )
                    );
                }

            } else {

                result.limitations.push(
                    "AndroidManifest.xml could not be extracted from the APK."
                );

                result.findings.push(
                    this.finding(
                        "manifest-extraction-failed",
                        "MEDIUM",
                        "HIGH",
                        "AndroidManifest.xml could not be extracted.",
                        "The manifest entry exists but its compressed content could not be decoded by the local ZIP reader.",
                        {
                            file:
                                "AndroidManifest.xml",
                            compression:
                                manifestEntry.compression
                        },
                        "Validate the APK with another ZIP parser before relying on manifest-dependent findings."
                    )
                );
            }

        } else {

            result.findings.push(
                this.finding(
                    "apk-manifest-missing",
                    "HIGH",
                    "HIGH",
                    "AndroidManifest.xml is missing.",
                    "A valid Android application package normally contains AndroidManifest.xml.",
                    {
                        expected:
                            "AndroidManifest.xml"
                    },
                    "Treat the file as structurally invalid or incomplete until verified."
                )
            );
        }


        /*
         * DEX INVENTORY
         */

        const dexEntries =
            entries.filter(
                entry =>
                    entry &&
                    entry.type !== "directory" &&
                    /^classes(?:\d+)?\.dex$/i.test(
                        entry.name
                    )
            );


        result.dex =
            dexEntries.map(
                entry => ({
                    name:
                        entry.name,

                    compressedSize:
                        entry.compressedSize,

                    uncompressedSize:
                        entry.uncompressedSize,

                    compression:
                        entry.compression
                })
            );


        result.files.dex =
            dexEntries.length;


        if (dexEntries.length === 0) {

            result.findings.push(
                this.finding(
                    "apk-no-dex",
                    "MEDIUM",
                    "HIGH",
                    "No DEX file was found.",
                    "The APK does not contain a standard classes*.dex file.",
                    {
                        expected:
                            "classes.dex"
                    },
                    "Verify the container and determine whether this is a valid Android package."
                )
            );

        } else {

            const firstDex =
                await this.extractEntry(
                    bytes,
                    dexEntries[0]
                );


            if (
                firstDex &&
                firstDex.length >= 8
            ) {

                const magic =
                    this.decodeAscii(
                        firstDex,
                        0,
                        8
                    );


                if (
                    !magic.startsWith(
                        "dex\n"
                    )
                ) {

                    result.findings.push(
                        this.finding(
                            "dex-invalid-header",
                            "MEDIUM",
                            "HIGH",
                            "A DEX entry does not contain the expected DEX magic.",
                            "The first DEX file was extracted but its header did not match the standard DEX signature.",
                            {
                                file:
                                    dexEntries[0].name,
                                magic
                            },
                            "Inspect the APK with a DEX-aware parser."
                        )
                    );
                }
            }
        }


        /*
         * NATIVE LIBRARIES
         */

        const nativeEntries =
            entries.filter(
                entry =>
                    entry &&
                    entry.type !== "directory" &&
                    /^lib\/[^/]+\/.+\.so$/i.test(
                        entry.name
                    )
            );


        result.nativeLibraries =
            nativeEntries.map(
                entry => {

                    const parts =
                        entry.name.split(
                            "/"
                        );

                    return {

                        name:
                            entry.name,

                        architecture:
                            parts.length >= 2
                                ? parts[1]
                                : null,

                        compressedSize:
                            entry.compressedSize,

                        uncompressedSize:
                            entry.uncompressedSize
                    };
                }
            );


        result.nativeArchitectures =
            Array.from(
                new Set(
                    result.nativeLibraries
                        .map(
                            item =>
                                item.architecture
                        )
                        .filter(
                            Boolean
                        )
                )
            );


        result.files.nativeLibraries =
            nativeEntries.length;


        /*
         * SIGNATURE FILES
         */

        const signatureEntries =
            entries.filter(
                entry =>
                    entry &&
                    entry.type !== "directory" &&
                    (
                        /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(
                            entry.name
                        ) ||
                        /^META-INF\/.+\.SF$/i.test(
                            entry.name
                        ) ||
                        entry.name ===
                            "META-INF/MANIFEST.MF"
                    )
            );


        result.signatures =
            signatureEntries.map(
                entry => ({
                    name:
                        entry.name,

                    type:
                        this.getSignatureFileType(
                            entry.name
                        ),

                    size:
                        entry.uncompressedSize
                })
            );


        result.files.signatureFiles =
            signatureEntries.length;


        if (
            signatureEntries.length === 0
        ) {

            result.findings.push(
                this.finding(
                    "apk-signature-files-missing",
                    "MEDIUM",
                    "MEDIUM",
                    "No standard APK signature-related files were detected.",
                    "The META-INF directory does not contain recognizable legacy APK signing metadata.",
                    {
                        directory:
                            "META-INF/"
                    },
                    "Inspect APK signing information with a dedicated Android signing parser."
                )
            );
        }


        /*
         * TEXTUAL INDICATORS
         *
         * Scan selected small textual files.
         */

        await this.extractTextIndicators(
            bytes,
            entries,
            result
        );


        /*
         * BASIC SECURITY FINDINGS
         */

        this.generateSecurityFindings(
            result
        );


        /*
         * FINAL STATUS
         */

        result.status =
            "completed";


        result.durationMs =
            Math.round(
                performance.now() -
                startedAt
            );


        return result;
    },


    /*
     * ─────────────────────────────
     * MANIFEST ANALYSIS
     * ─────────────────────────────
     */

    analyzeManifest(
        manifest,
        result
    ) {

        const attributes =
            manifest.attributes ||
            {};


        result.identity.packageName =
            this.getAttribute(
                attributes,
                "package"
            );


        result.identity.versionName =
            this.getAttribute(
                attributes,
                "versionName"
            );


        result.identity.versionCode =
            this.getAttribute(
                attributes,
                "versionCode"
            );


        result.identity.minSdk =
            this.getAttribute(
                attributes,
                "minSdkVersion"
            );


        result.identity.targetSdk =
            this.getAttribute(
                attributes,
                "targetSdkVersion"
            );


        result.identity.compileSdk =
            this.getAttribute(
                attributes,
                "compileSdkVersion"
            );


        const application =
            this.findChild(
                manifest.root,
                "application"
            );


        if (application) {

            result.application.label =
                this.getAttribute(
                    application.attributes,
                    "label"
                );


            result.application.debuggable =
                this.parseBooleanAttribute(
                    application.attributes,
                    "debuggable"
                );


            result.application.allowBackup =
                this.parseBooleanAttribute(
                    application.attributes,
                    "allowBackup"
                );


            result.application.usesCleartextTraffic =
                this.parseBooleanAttribute(
                    application.attributes,
                    "usesCleartextTraffic"
                );


            this.extractComponents(
                application,
                result
            );
        }


        const permissionNodes =
            this.findChildren(
                manifest.root,
                [
                    "uses-permission",
                    "uses-permission-sdk-23",
                    "uses-permission-sdk-m"
                ]
            );


        for (
            const node
            of permissionNodes
        ) {

            const name =
                this.getAttribute(
                    node.attributes,
                    "name"
                );


            if (
                name &&
                !result.permissions.includes(
                    name
                )
            ) {

                result.permissions.push(
                    name
                );
            }
        }


        result.permissions.sort();
    },


    extractComponents(
        application,
        result
    ) {

        const componentTypes = [

            {
                tag:
                    "activity",
                target:
                    "activities"
            },

            {
                tag:
                    "activity-alias",
                target:
                    "activities"
            },

            {
                tag:
                    "service",
           
