"use strict";

const FileGuardAPKAnalyzer = {
    VERSION: "2.1.0",

    MAX_TEXT_SCAN_SIZE:
        8 * 1024 * 1024,

    MAX_STRING_LENGTH:
        200,

    MAX_STRINGS:
        500,

    MAX_TEXT_FILES:
        50,

    APK_MAGIC:
        0x04034B50,

    ZIP_LOCAL_FILE_HEADER:
        0x04034B50,

    COMPRESSION_STORE:
        0,

    COMPRESSION_DEFLATE:
        8,

    async analyze(
        file,
        options = {}
    ) {
        this.validateFile(file);

        const context =
            options.context || null;

        const startedAt =
            performance.now();

        this.checkpoint(
            context,
            "apk-start"
        );

        const result = {
            analyzer: "apk",
            analyzerVersion:
                this.VERSION,

            status: "unknown",

            identity: {
                packageName: null,
                versionName: null,
                versionCode: null,
                minSdk: null,
                targetSdk: null,
                compileSdk: null
            },

            application: {
                label: null,
                debuggable: null,
                allowBackup: null,
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
                manifest: false,
                dex: 0,
                nativeLibraries: 0,
                signatureFiles: 0
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
                entries: 0,
                files: 0,
                directories: 0,
                totalUncompressedBytes: 0
            },

            durationMs: null
        };

        const archive =
            options.archive ||
            options.context?.archive ||
            null;

        if (
            archive &&
            Array.isArray(
                archive.entries
            )
        ) {
            result.statistics.entries =
                archive.entries.length;

            result.statistics.files =
                Number.isFinite(
                    archive.statistics?.files
                )
                    ? archive.statistics.files
                    : archive.entries.filter(
                        entry =>
                            !entry.directory
                    ).length;

            result.statistics.directories =
                Number.isFinite(
                    archive.statistics?.directories
                )
                    ? archive.statistics.directories
                    : archive.entries.filter(
                        entry =>
                            entry.directory
                    ).length;

            result.statistics.totalUncompressedBytes =
                Number.isFinite(
                    archive.statistics
                        ?.uncompressedBytes
                )
                    ? archive.statistics
                        .uncompressedBytes
                    : 0;
        }

        const maxFileSize =
            this.getLimit(
                context,
                "MAX_FILE_SIZE_BYTES"
            );

        if (
            Number.isFinite(
                maxFileSize
            ) &&
            file.size > maxFileSize
        ) {
            throw this.createLimitError(
                "FILE_TOO_LARGE",
                file.size,
                maxFileSize
            );
        }

        this.checkpoint(
            context,
            "apk-before-buffer"
        );

        const buffer =
            await file.arrayBuffer();

        const bytes =
            new Uint8Array(
                buffer
            );

        this.checkpoint(
            context,
            "apk-buffer-read"
        );

        if (
            bytes.length < 4 ||
            this.readUInt32LE(
                bytes,
                0
            ) !== this.APK_MAGIC
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
                    "Verify the container structure before relying on APK-specific results."
                )
            );

            return this.finish(
                result,
                startedAt
            );
        }

        const entries =
            archive &&
            Array.isArray(
                archive.entries
            )
                ? archive.entries
                : [];

        if (
            entries.length === 0
        ) {
            result.status =
                "partial";

            result.limitations.push(
                "APK analysis requires the completed ZIP entry index."
            );

            result.findings.push(
                this.finding(
                    "apk-archive-index-missing",
                    "MEDIUM",
                    "HIGH",
                    "APK ZIP entry index is unavailable.",
                    "The APK bytes are valid enough to enter APK analysis, but no archive entry index was supplied by the core pipeline.",
                    null,
                    "Run the archive analyzer before relying on APK-specific structural results."
                )
            );

            return this.finish(
                result,
                startedAt
            );
        }

        const manifestEntry =
            this.findEntry(
                entries,
                "AndroidManifest.xml"
            );

        if (
            manifestEntry
        ) {
            result.files.manifest =
                true;

            this.checkpoint(
                context,
                "apk-before-manifest"
            );

            const manifestBytes =
                await this.extractEntry(
                    bytes,
                    manifestEntry,
                    context
                );

            this.checkpoint(
                context,
                "apk-after-manifest"
            );

            if (
                manifestBytes
            ) {
                const manifest =
                    this.parseBinaryXML(
                        manifestBytes
                    );

                if (
                    manifest
                ) {
                    this.analyzeManifest(
                        manifest,
                        result
                    );
                } else {
                    result.status =
                        "partial";

                    result.limitations.push(
                        "AndroidManifest.xml was found but binary AXML parsing was not completed."
                    );

                    result.findings.push(
                        this.finding(
                            "manifest-parse-unavailable",
                            "INFO",
                            "MEDIUM",
                            "AndroidManifest.xml was found but could not be fully parsed.",
                            "The manifest exists, but the local binary XML parser could not reconstruct its XML structure.",
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
                result.status =
                    "partial";

                result.limitations.push(
                    "AndroidManifest.xml could not be extracted."
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
                                "AndroidManifest.xml"
                        },
                        "Validate the APK with another ZIP parser before relying on manifest-dependent findings."
                    )
                );
            }
        } else {
            result.status =
                "partial";

            result.findings.push(
                this.finding(
                    "apk-manifest-missing",
                    "HIGH",
                    "HIGH",
                    "AndroidManifest.xml is missing.",
                    "A structurally valid Android application package normally contains AndroidManifest.xml.",
                    {
                        expected:
                            "AndroidManifest.xml"
                    },
                    "Treat the package as structurally invalid or incomplete until verified."
                )
            );
        }

        this.checkpoint(
            context,
            "apk-manifest-complete"
        );

        const dexEntries =
            entries.filter(
                entry =>
                    entry &&
                    !entry.directory &&
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

                    compressionMethod:
                        entry.compressionMethod
                })
            );

        result.files.dex =
            dexEntries.length;

        if (
            dexEntries.length === 0
        ) {
            result.findings.push(
                this.finding(
                    "apk-no-dex",
                    "MEDIUM",
                    "HIGH",
                    "No DEX file was found.",
                    "The APK does not contain a standard classes*.dex entry.",
                    {
                        expected:
                            "classes.dex"
                    },
                    "Verify the package structure and determine whether the file is a valid Android package."
                )
            );
        } else {
            this.checkpoint(
                context,
                "apk-before-dex"
            );

            const firstDex =
                await this.extractEntry(
                    bytes,
                    dexEntries[0],
                    context
                );

            this.checkpoint(
                context,
                "apk-after-dex"
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
                            "The first DEX entry was extracted but its header does not match the standard DEX signature.",
                            {
                                file:
                                    dexEntries[0]
                                        .name,
                                magic
                            },
                            "Inspect the DEX file with a DEX-aware parser."
                        )
                    );
                }
            }
        }

        const nativeEntries =
            entries.filter(
                entry =>
                    entry &&
                    !entry.directory &&
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

        this.checkpoint(
            context,
            "apk-native-libraries"
        );

        const signatureEntries =
            entries.filter(
                entry =>
                    entry &&
                    !entry.directory &&
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
                    "The APK does not contain recognizable legacy META-INF signing metadata.",
                    {
                        directory:
                            "META-INF/"
                    },
                    "Inspect APK signing information with a dedicated Android signing parser."
                )
            );
        }

        this.checkpoint(
            context,
            "apk-structure-complete"
        );

        return await this.continueAnalysis(
            file,
            bytes,
            entries,
            result,
            context,
            startedAt
        );
    },

    async continueAnalysis(
        file,
        bytes,
        entries,
        result,
        context,
        startedAt
    ) {
        await this.extractTextIndicators(
            bytes,
            entries,
            result,
            context
        );

        this.checkpoint(
            context,
            "apk-text-analysis-complete"
        );

        this.generateSecurityFindings(
            result
        );

        this.checkpoint(
            context,
            "apk-findings-complete"
        );

        if (
            result.status ===
            "unknown"
        ) {
            result.status =
                "completed";
        }

        return this.finish(
            result,
            startedAt
        );
    },

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

        if (
            application
        ) {
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
            const node of
            permissionNodes
        ) {
            const name =
                this.getAttribute(
                    node.attributes,
                    "name"
                );

            if (name
            ) {
                components.push({
                    type,
                    name,
                    exported:
                        this.parseBooleanAttribute(
                            node.attributes,
                            "exported"
                        ),
                    permission:
                        this.getAttribute(
                            node.attributes,
                            "permission"
                        ),
                    intentFilters:
                        node.children.filter(
                            child =>
                                child.name ===
                                "intent-filter"
                        ).length
                });
            }
        }

        return components;
    },

    getAttribute(attributes, name) {
        if (!Array.isArray(attributes)) {
            return null;
        }

        const attribute =
            attributes.find(
                item =>
                    item &&
                    (
                        item.name === name ||
                        item.name ===
                            `android:${name}`
                    )
            );

        return attribute
            ? attribute.value
            : null;
    },

    parseBooleanAttribute(
        attributes,
        name
    ) {
        const value =
            this.getAttribute(
                attributes,
                name
            );

        if (
            value === true ||
            value === "true" ||
            value === "1"
        ) {
            return true;
        }

        if (
            value === false ||
            value === "false" ||
            value === "0"
        ) {
            return false;
        }

        return null;
    },

    async extractTextIndicators(
        archive,
        context
    ) {
        const urls = new Set();
        const domains = new Set();
        const ips = new Set();
        const strings = new Set();

        if (!archive) {
            return {
                urls: [],
                domains: [],
                ips: [],
                strings: []
            };
        }

        const entries =
            Array.isArray(archive.entries)
                ? archive.entries
                : [];

        let scanned = 0;

        for (const entry of entries) {
            if (scanned >= this.MAX_TEXT_FILES) {
                break;
            }

            if (
                !entry ||
                entry.directory ||
                !this.isTextEntry(entry.name)
            ) {
                continue;
            }

            if (
                Number.isFinite(
                    entry.uncompressedSize
                ) &&
                entry.uncompressedSize >
                    this.MAX_TEXT_SCAN_SIZE
            ) {
                continue;
            }

            if (context) {
                this.checkpoint(
                    context,
                    `apk-text-${scanned}`
                );
            }

            try {
                const buffer =
                    await this.extractEntry(
                        archive,
                        entry,
                        context,
                        this.MAX_TEXT_SCAN_SIZE
                    );

                const text =
                    new TextDecoder(
                        "utf-8",
                        {
                            fatal: false
                        }
                    ).decode(buffer);

                this.collectTextIndicators(
                    text,
                    urls,
                    domains,
                    ips,
                    strings
                );

                scanned += 1;
            } catch {
                scanned += 1;
            }
        }

        return {
            urls: Array.from(urls).slice(0, 100),
            domains: Array.from(domains).slice(0, 100),
            ips: Array.from(ips).slice(0, 100),
            strings: Array.from(strings).slice(
                0,
                this.MAX_STRINGS
            )
        };
    },

    isTextEntry(name) {
        if (typeof name !== "string") {
            return false;
        }

        const lower =
            name.toLowerCase();

        return (
            lower.endsWith(".xml") ||
            lower.endsWith(".json") ||
            lower.endsWith(".txt") ||
            lower.endsWith(".html") ||
            lower.endsWith(".htm") ||
            lower.endsWith(".js") ||
            lower.endsWith(".smali") ||
            lower.endsWith(".properties") ||
            lower.startsWith("assets/") ||
            lower.startsWith("res/raw/") ||
            lower.startsWith("res/xml/")
        );
    },

    collectTextIndicators(
        text,
        urls,
        domains,
        ips,
        strings
    ) {
        if (!text) {
            return;
        }

        const urlMatches =
            text.match(
                /https?:\/\/[^\s"'<>\\]+/gi
            ) || [];

        for (const value of urlMatches) {
            const clean =
                value
                    .replace(
                        /[),.;]+$/,
                        ""
                    )
                    .slice(0, 500);

            if (clean) {
                urls.add(clean);

                try {
                    const host =
                        new URL(clean).hostname;

                    if (host) {
                        domains.add(
                            host.toLowerCase()
                        );
                    }
                } catch {}
            }
        }

        const domainMatches =
            text.match(
                /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi
            ) || [];

        for (const value of domainMatches) {
            domains.add(
                value.toLowerCase()
            );
        }

        const ipMatches =
            text.match(
                /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
            ) || [];

        for (const value of ipMatches) {
            const parts =
                value.split(".")
                    .map(Number);

            if (
                parts.length === 4 &&
                parts.every(
                    part =>
                        Number.isInteger(part) &&
                        part >= 0 &&
                        part <= 255
                )
            ) {
                ips.add(value);
            }
        }

        const interestingPattern =
            /\b(?:dex|dalvik|runtime|reflection|classloader|loadlibrary|system\.load|exec|runtime\.exec|socket|webview|javascript|base64|encrypt|decrypt|keystore|accessibility|overlay|install[_ -]?package)\b/gi;

        const interesting =
            text.match(
                interestingPattern
            ) || [];

        for (const value of interesting) {
            strings.add(
                value.toLowerCase()
            );
        }
    },

    generateSecurityFindings(
        manifest,
        textIndicators,
        dex,
        nativeLibraries,
        signature
    ) {
        const findings = [];

        const application =
            manifest &&
            manifest.application
                ? manifest.application
                : null;

        if (
            application &&
            application.debuggable === true
        ) {
            findings.push(
                this.finding(
                    "apk-debuggable",
                    "MEDIUM",
                    "HIGH",
                    "Application is debuggable",
                    "The APK manifest explicitly enables the Android debuggable flag.",
                    {
                        field: "android:debuggable",
                        value: true
                    },
                    "Disable debuggable builds for production releases."
                )
            );
        }

        if (
            application &&
            application.allowBackup === true
        ) {
            findings.push(
                this.finding(
                    "apk-backup-enabled",
                    "LOW",
                    "HIGH",
                    "Application backup is enabled",
                    "The manifest permits Android backup behavior. Actual exposure depends on Android version and backup configuration.",
                    {
                        field: "android:allowBackup",
                        value: true
                    },
                    "Review backup requirements and platform-specific backup rules before release."
                )
            );
        }

        if (
            application &&
            application.usesCleartextTraffic === true
        ) {
            findings.push(
                this.finding(
                    "apk-cleartext-traffic",
                    "MEDIUM",
                    "HIGH",
                    "Cleartext network traffic is permitted",
                    "The manifest explicitly permits cleartext network traffic.",
                    {
                        field: "android:usesCleartextTraffic",
                        value: true
                    },
                    "Prefer HTTPS and restrict cleartext traffic unless it is explicitly required."
                )
            );
        }

        for (
            const component
            of manifest.components || []
        ) {
            if (
                component.exported === true &&
                !component.permission
            ) {
                findings.push(
                    this.finding(
                        `apk-exported-${component.type}-${component.name}`,
                        "MEDIUM",
                        "MEDIUM",
                        "Exported component has no declared permission",
                        "The component is explicitly exported without a component-level permission.",
                        {
                            component:
                                component.name,
                            type:
                                component.type,
                            exported:
                                true
                        },
                        "Review whether the component must be externally accessible and restrict it when appropriate."
                    )
                );
            }
        }

        const dangerousPermissions =
            new Set([
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_PHONE_STATE",
                "android.permission.READ_PHONE_NUMBERS",
                "android.permission.QUERY_ALL_PACKAGES",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ]);

        for (
            const permission
            of manifest.permissions || []
        ) {
            if (
                dangerousPermissions.has(
                    permission
                )
            ) {
                findings.push(
                    this.finding(
                        `apk-permission-${permission}`,
                        "LOW",
                        "HIGH",
                        "Sensitive Android permission requested",
                        "The manifest requests a permission that can provide access to sensitive device capabilities or data.",
                        {
                            permission
                        },
                        "Confirm that this permission is required for the application's documented functionality."
                    )
                );
            }
        }

        if (
            textIndicators.urls.length > 0 ||
            textIndicators.domains.length > 0 ||
            textIndicators.ips.length > 0
        ) {
            findings.push(
                this.finding(
                    "apk-network-indicators",
                    "INFO",
                    "MEDIUM",
                    "Network indicators found",
                    "Static text scanning identified URLs, domains, or IP addresses inside APK text resources.",
                    {
                        urls:
                            textIndicators.urls,
                        domains:
                            textIndicators.domains,
                        ips:
                            textIndicators.ips
                    },
                    "Review the indicators and determine whether they correspond to expected application services."
                )
            );
        }

        if (
            textIndicators.strings.length > 0
        ) {
            findings.push(
                this.finding(
                    "apk-interesting-strings",
                    "INFO",
                    "LOW",
                    "Security-relevant strings found",
                    "Static text scanning identified strings associated with runtime loading, reflection, networking, encoding, or privileged Android behavior.",
                    {
                        strings:
                            textIndicators.strings
                    },
                    "Treat these strings as investigation leads rather than proof of malicious behavior."
                )
            );
        }

        if (
            Array.isArray(nativeLibraries) &&
            nativeLibraries.length > 0
        ) {
            findings.push(
                this.finding(
                    "apk-native-code",
                    "INFO",
                    "HIGH",
                    "Native libraries detected",
                    "The APK contains native shared libraries.",
                    {
                        libraries:
                            nativeLibraries
                    },
                    "Review native libraries separately when deeper reverse engineering is required."
                )
            );
        }

        if (
            dex &&
            dex.count > 0
        ) {
            findings.push(
                this.finding(
                    "apk-dex-code",
                    "INFO",
                    "HIGH",
                    "DEX bytecode detected",
                    "The APK contains Android DEX bytecode. FileGuard inventories the bytecode but does not perform full reverse engineering.",
                    {
                        files:
                            dex.files,
                        count:
                            dex.count
                    },
                    "Use a dedicated Android reverse-engineering tool for deeper bytecode analysis."
                )
            );
        }

        if (
            signature &&
            signature.present === false
        ) {
            findings.push(
                this.finding(
                    "apk-signature-missing",
                    "HIGH",
                    "HIGH",
                    "APK signing information was not found",
                    "The expected APK signing artifacts were not detected in the archive.",
                    {
                        files:
                            signature.files || []
                    },
                    "Verify the APK signing structure and analyze the package with a dedicated Android signing tool."
                )
            );
        }

        return findings;
    },

        async extractEntry(
        archive,
        entry,
        context,
        maxOutputBytes
    ) {
        if (!archive || !entry) {
            throw new Error(
                "APK archive entry is unavailable."
            );
        }

        if (context) {
            this.checkpoint(
                context,
                "apk-entry-extract-start"
            );
        }

        const limit =
            Number.isFinite(maxOutputBytes)
                ? maxOutputBytes
                : this.MAX_TEXT_SCAN_SIZE;

        const declaredSize =
            Number.isFinite(
                entry.uncompressedSize
            )
                ? entry.uncompressedSize
                : null;

        if (
            declaredSize !== null &&
            declaredSize > limit
        ) {
            throw this.createLimitError(
                "APK entry exceeds extraction limit.",
                "ENTRY_TOO_LARGE",
                declaredSize,
                limit
            );
        }

        const buffer =
            archive.buffer;

        if (!(buffer instanceof ArrayBuffer)) {
            throw new Error(
                "APK archive buffer is unavailable."
            );
        }

        const view =
            new DataView(buffer);

        const offset =
            Number.isSafeInteger(
                entry.localHeaderOffset
            )
                ? entry.localHeaderOffset
                : null;

        if (
            offset === null ||
            offset < 0 ||
            offset + 30 > buffer.byteLength
        ) {
            throw new Error(
                "Invalid APK local file header offset."
            );
        }

        const signature =
            view.getUint32(
                offset,
                true
            );

        if (
            signature !==
            this.ZIP_LOCAL_FILE_HEADER
        ) {
            throw new Error(
                "Invalid APK local file header."
            );
        }

        const fileNameLength =
            view.getUint16(
                offset + 26,
                true
            );

        const extraLength =
            view.getUint16(
                offset + 28,
                true
            );

        const dataOffset =
            offset +
            30 +
            fileNameLength +
            extraLength;

        if (
            dataOffset < 0 ||
            dataOffset > buffer.byteLength
        ) {
            throw new Error(
                "Invalid APK entry data offset."
            );
        }

        const compressedSize =
            Number.isSafeInteger(
                entry.compressedSize
            )
                ? entry.compressedSize
                : null;

        if (
            compressedSize === null ||
            compressedSize < 0 ||
            dataOffset +
                compressedSize >
                buffer.byteLength
        ) {
            throw new Error(
                "Invalid APK compressed entry size."
            );
        }

        const compressed =
            buffer.slice(
                dataOffset,
                dataOffset +
                    compressedSize
            );

        const method =
            Number.isInteger(
                entry.compressionMethod
            )
                ? entry.compressionMethod
                : this.COMPRESSION_STORE;

        if (
            method ===
            this.COMPRESSION_STORE
        ) {
            if (
                compressed.byteLength >
                limit
            ) {
                throw this.createLimitError(
                    "Stored APK entry exceeds extraction limit.",
                    "ENTRY_TOO_LARGE",
                    compressed.byteLength,
                    limit
                );
            }

            return compressed;
        }

        if (
            method !==
            this.COMPRESSION_DEFLATE
        ) {
            throw new Error(
                `Unsupported APK compression method: ${method}`
            );
        }

        if (
            typeof DecompressionStream !==
            "function"
        ) {
            throw new Error(
                "Browser does not support raw DEFLATE decompression."
            );
        }

        const stream =
            new Blob([
                compressed
            ])
                .stream()
                .pipeThrough(
                    new DecompressionStream(
                        "deflate-raw"
                    )
                );

        const reader =
            stream.getReader();

        const chunks = [];

        let total = 0;

        try {
            while (true) {
                if (context) {
                    this.checkpoint(
                        context,
                        "apk-entry-decompress"
                    );
                }

                const result =
                    await reader.read();

                if (result.done) {
                    break;
                }

                const chunk =
                    result.value;

                if (
                    !(chunk instanceof Uint8Array)
                ) {
                    continue;
                }

                total +=
                    chunk.byteLength;

                if (total > limit) {
                    try {
                        await reader.cancel();
                    } catch {}

                    throw this.createLimitError(
                        "Decompressed APK entry exceeds extraction limit.",
                        "ENTRY_OUTPUT_TOO_LARGE",
                        total,
                        limit
                    );
                }

                chunks.push(chunk);
            }
        } finally {
            try {
                reader.releaseLock();
            } catch {}
        }

        const output =
            new Uint8Array(total);

        let position = 0;

        for (const chunk of chunks) {
            output.set(
                chunk,
                position
            );

            position +=
                chunk.byteLength;
        }

        return output.buffer;
    },

    findEntry(
        archive,
        name
    ) {
        if (
            !archive ||
            !Array.isArray(
                archive.entries
            )
        ) {
            return null;
        }

        return (
            archive.entries.find(
                entry =>
                    entry &&
                    entry.name === name
            ) || null
        );
    },

    getSignatureFileType(
        entryName
    ) {
        if (
            typeof entryName !==
            "string"
        ) {
            return "UNKNOWN";
        }

        const upper =
            entryName.toUpperCase();

        if (
            upper.endsWith(
                ".RSA"
            )
        ) {
            return "RSA";
        }

        if (
            upper.endsWith(
                ".DSA"
            )
        ) {
            return "DSA";
        }

        if (
            upper.endsWith(
                ".EC"
            )
        ) {
            return "EC";
        }

        return "UNKNOWN";
    },

    readUInt16(
        view,
        offset
    ) {
        if (
            offset < 0 ||
            offset + 2 >
                view.byteLength
        ) {
            return null;
        }

        return view.getUint16(
            offset,
            true
        );
    },

    readUInt32(
        view,
        offset
    ) {
        if (
            offset < 0 ||
            offset + 4 >
                view.byteLength
        ) {
            return null;
        }

        return view.getUint32(
            offset,
            true
        );
    },

    readInt32(
        view,
        offset
    ) {
        if (
            offset < 0 ||
            offset + 4 >
                view.byteLength
        ) {
            return null;
        }

        return view.getInt32(
            offset,
            true
        );
    },

    readBytes(
        buffer,
        offset,
        length
    ) {
        if (
            !(buffer instanceof ArrayBuffer) ||
            !Number.isSafeInteger(offset) ||
            !Number.isSafeInteger(length) ||
            offset < 0 ||
            length < 0 ||
            offset + length >
                buffer.byteLength
        ) {
            return null;
        }

        return new Uint8Array(
            buffer,
            offset,
            length
        );
    },

    decodeAscii(
        bytes
    ) {
        if (
            !(bytes instanceof Uint8Array)
        ) {
            return "";
        }

        let result = "";

        const length =
            Math.min(
                bytes.length,
                this.MAX_STRING_LENGTH
            );

        for (
            let index = 0;
            index < length;
            index += 1
        ) {
            const value =
                bytes[index];

            if (
                value >= 32 &&
                value <= 126
            ) {
                result +=
                    String.fromCharCode(
                        value
                    );
            } else {
                result += " ";
            }
        }

        return result.trim();
    },

    finding(
        id,
        severity,
        confidence,
        title,
        description,
        evidence,
        recommendation
    ) {
        return {
            id,
            severity,
            confidence,
            title,
            description,
            evidence:
                evidence || null,
            recommendation:
                recommendation || null,
            source: "apk",
            category: "android",
            status: "observed"
        };
    },

    checkpoint(
        context,
        stage
    ) {
        if (
            context &&
            typeof context.checkpoint ===
                "function"
        ) {
            context.checkpoint(stage);
        }
    },

    getLimit(
        context,
        name,
        fallback
    ) {
        if (
            context &&
            typeof context.getLimit ===
                "function"
        ) {
            const value =
                context.getLimit(name);

            if (
                Number.isFinite(value)
            ) {
                return value;
            }
        }

        return fallback;
    },

    createLimitError(
        message,
        code,
        actual,
        limit
    ) {
        const error =
            new Error(message);

        error.name =
            "ResourceLimitError";

        error.code =
            code;

        error.actual =
            actual;

        error.limit =
            limit;

        return error;
    },

    validateFile(
        file
    ) {
        if (!(file instanceof File)) {
            throw new TypeError(
                "APK analyzer requires a File object."
            );
        }

        if (
            file.size < 4
        ) {
            throw new Error(
                "APK file is too small."
            );
        }

        if (
            typeof file.name !==
            "string"
        ) {
            throw new Error(
                "APK file name is invalid."
            );
        }
    }
};

window.FileGuardAPKAnalyzer =
    FileGuardAPKAnalyzer;

                        
 
