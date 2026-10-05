"use strict";

const FileGuardArchiveAnalyzer = {
    VERSION: "2.1.0",

    MAX_ENTRIES: 100000,
    SUSPICIOUS_UNCOMPRESSED_SIZE: 100 * 1024 * 1024,
    SUSPICIOUS_COMPRESSION_RATIO: 100,

    ZIP_CENTRAL_DIRECTORY_HEADER: 0x02014B50,
    ZIP_END_OF_CENTRAL_DIRECTORY: 0x06054B50,
    ZIP64_END_OF_CENTRAL_DIRECTORY: 0x06064B50,
    ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR: 0x07064B50,

    async analyze(file, options = {}) {
        this.validateFile(file);

        const context = options.context || null;

        this.checkpoint(context, "archive-start");

        const startedAt = performance.now();

        const result = {
            analyzer: "archive",
            analyzerVersion: this.VERSION,
            status: "unknown",
            format: "ZIP",
            containerType: "ZIP",
            entryCount: 0,

            entries: [],

            statistics: {
                compressedBytes: 0,
                uncompressedBytes: 0,
                compressionRatio: null,
                encryptedEntries: 0,
                directories: 0,
                files: 0
            },

            features: {
                zip64: false,
                encrypted: false,
                duplicateNames: false,
                pathTraversal: false,
                absolutePaths: false,
                suspiciousCompression: false,
                nestedArchives: false
            },

            findings: [],

            evidence: {
                signatures: [],
                containerMarkers: [],
                centralDirectory: null
            }
        };

        const limit =
            context &&
            typeof context.getLimit === "function"
                ? context.getLimit("MAX_FILE_SIZE_BYTES")
                : null;

        if (
            Number.isFinite(limit) &&
            file.size > limit
        ) {
            throw this.createLimitError(
                file.size,
                limit
            );
        }

        const buffer =
            await file.arrayBuffer();

        const bytes =
            new Uint8Array(buffer);

        this.checkpoint(
            context,
            "archive-buffer-read"
        );

        const signature =
            bytes.length >= 4
                ? this.readUInt32LE(bytes, 0)
                : null;

        if (signature !== null) {
            result.evidence.signatures.push(
                "0x" +
                signature
                    .toString(16)
                    .padStart(8, "0")
            );
        }

        const endRecord =
            this.findEndOfCentralDirectory(bytes);

        if (!endRecord) {
            result.status = "invalid";

            result.findings.push({
                id: "invalid-zip-structure",
                severity: "MEDIUM",
                confidence: "HIGH",
                title:
                    "ZIP end-of-central-directory record was not found.",
                description:
                    "The file has ZIP-like characteristics but its central directory could not be located.",
                evidence: null,
                recommendation:
                    "Treat the container as structurally invalid until further inspection."
            });

            result.durationMs =
                Math.round(
                    performance.now() -
                    startedAt
                );

            return result;
        }

        const zip64 =
            this.resolveZip64(
                bytes,
                endRecord
            );

        result.features.zip64 =
            zip64.detected;

        if (zip64.detected) {
            result.findings.push({
                id: "zip64-container",
                severity: "INFO",
                confidence: "HIGH",
                title:
                    "ZIP64 structures detected.",
                description:
                    "The archive uses ZIP64 metadata and was parsed using ZIP64-aware offsets and sizes.",
                evidence:
                    zip64.evidence,
                recommendation:
                    "Continue processing only with ZIP64-aware tooling and enforce resource limits before extraction."
            });
        }

        if (zip64.error) {
            result.status = "partial";

            result.evidence.centralDirectory = {
                offset: endRecord.offset,
                entries: endRecord.entries,
                centralDirectoryOffset:
                    endRecord.centralDirectoryOffset,
                centralDirectorySize:
                    endRecord.centralDirectorySize
            };

            result.findings.push({
                id: "zip64-parse-limited",
                severity: "MEDIUM",
                confidence: "HIGH",
                title:
                    "ZIP64 metadata could not be resolved completely.",
                description:
                    zip64.error,
                evidence:
                    zip64.evidence,
                recommendation:
                    "Do not treat the archive as fully validated. Use a ZIP64-aware parser for complete verification."
            });

            result.durationMs =
                Math.round(
                    performance.now() -
                    startedAt
                );

            return result;
        }

        const directoryInfo =
            zip64.resolved || {
                entries:
                    endRecord.entries,

                centralDirectoryOffset:
                    endRecord.centralDirectoryOffset,

                centralDirectorySize:
                    endRecord.centralDirectorySize
            };

        result.evidence.centralDirectory = {
            offset: endRecord.offset,
            entries:
                directoryInfo.entries,

            centralDirectoryOffset:
                directoryInfo.centralDirectoryOffset,

            centralDirectorySize:
                directoryInfo.centralDirectorySize
        };

        if (
            directoryInfo.entries >
            this.MAX_ENTRIES
        ) {
            result.status = "partial";

            result.entryCount =
                directoryInfo.entries;

            result.findings.push({
                id: "entry-count-limit",
                severity: "MEDIUM",
                confidence: "HIGH",
                title:
                    "Archive entry count exceeds the analysis limit.",
                description:
                    "The archive declares " +
                    Number(
                        directoryInfo.entries
                    ).toLocaleString() +
                    " entries.",

                evidence: {
                    entryCount:
                        directoryInfo.entries,

                    limit:
                        this.MAX_ENTRIES
                },

                recommendation:
                    "Do not blindly extract the archive. Full entry enumeration was intentionally stopped by FileGuard's resource limit."
            });

            result.durationMs =
                Math.round(
                    performance.now() -
                    startedAt
                );

            return result;
        }

        const parsed =
            this.parseCentralDirectory(
                bytes,
                directoryInfo,
                context
            );

        if (parsed.error) {
            result.status = "invalid";

            result.entries =
                parsed.entries;

            result.entryCount =
                parsed.entries.length;

            result.findings.push({
                id:
                    "central-directory-parse-failed",

                severity:
                    "MEDIUM",

                confidence:
                    "HIGH",

                title:
                    "ZIP central directory could not be parsed completely.",

                description:
                    parsed.error,

                evidence: {
                    centralDirectoryOffset:
                        directoryInfo.centralDirectoryOffset,

                    centralDirectorySize:
                        directoryInfo.centralDirectorySize,

                    parsedEntries:
                        parsed.entries.length
                },

                recommendation:
                    "Treat the archive as structurally suspicious until it can be validated by another ZIP parser."
            });

            result.durationMs =
                Math.round(
                    performance.now() -
                    startedAt
                );

            return result;
        }

        result.entries =
            parsed.entries;

        result.entryCount =
            parsed.entries.length;

        this.checkpoint(
            context,
            "archive-directory-parsed"
        );

        this.analyzeEntries(result);

        const container =
            this.identifyContainer(
                result.entries
            );

        result.containerType =
            container.type;

        result.format =
            container.format;

        result.evidence.containerMarkers =
            container.markers;

        if (container.type !== "ZIP") {
            result.findings.push({
                id:
                    "container-" +
                    container.type.toLowerCase(),

                severity:
                    "INFO",

                confidence:
                    "HIGH",

                title:
                    container.type +
                    " container identified.",

                description:
                    container.description,

                evidence: {
                    markers:
                        container.markers
                },

                recommendation:
                    "Route the container to its specialized analyzer when available."
            });
        }

        const nested =
            this.detectNestedArchives(
                result.entries
            );

        if (nested.length) {
            result.features.nestedArchives =
                true;

            result.findings.push({
                id:
                    "nested-archives",

                severity:
                    "LOW",

                confidence:
                    "HIGH",

                title:
                    "Nested archive files detected.",

                description:
                    "The container contains one or more archive-like files.",

                evidence: {
                    entries:
                        nested
                },

                recommendation:
                    "Inspect nested archives separately if their contents are relevant to the investigation."
            });
        }

        this.checkpoint(
            context,
            "archive-complete"
        );

        result.status =
            "completed";

        result.durationMs =
            Math.round(
                performance.now() -
                startedAt
            );

        return result;
    },

    findEndOfCentralDirectory(bytes) {
        const minimumOffset =
            Math.max(
                0,
                bytes.length -
                0xFFFF -
                22
            );

        for (
            let offset =
                bytes.length - 22;

            offset >= minimumOffset;

            offset--
        ) {
            if (
                this.readUInt32LE(
                    bytes,
                    offset
                ) !==
                this.ZIP_END_OF_CENTRAL_DIRECTORY
            ) {
                continue;
            }

            if (
                offset + 22 >
                bytes.length
            ) {
                continue;
            }

            const commentLength =
                this.readUInt16LE(
                    bytes,
                    offset + 20
                );

            if (
                offset +
                22 +
                commentLength >
                bytes.length
            ) {
                continue;
            }

            return {
                offset,

                diskNumber:
                    this.readUInt16LE(
                        bytes,
                        offset + 4
                    ),

                centralDirectoryDisk:
                    this.readUInt16LE(
                        bytes,
                        offset + 6
                    ),

                entriesOnDisk:
                    this.readUInt16LE(
                        bytes,
                        offset + 8
                    ),

                entries:
                    this.readUInt16LE(
                        bytes,
                        offset + 10
                    ),

                centralDirectorySize:
                    this.readUInt32LE(
                        bytes,
                        offset + 12
                    ),

                centralDirectoryOffset:
                    this.readUInt32LE(
                        bytes,
                        offset + 16
                    )
            };
        }

        return null;
    },

    resolveZip64(bytes, endRecord) {
        const marker =
            endRecord.entries === 0xFFFF ||
            endRecord.centralDirectorySize ===
                0xFFFFFFFF ||
            endRecord.centralDirectoryOffset ===
                0xFFFFFFFF;

        const evidence = [];

        let locatorOffset = -1;

        const searchStart =
            Math.max(
                0,
                endRecord.offset -
                1024
            );

        for (
            let offset =
                endRecord.offset - 20;

            offset >= searchStart;

            offset--
        ) {
            if (
                this.readUInt32LE(
                    bytes,
                    offset
                ) ===
                this
                    .ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR
            ) {
                locatorOffset =
                    offset;

                break;
            }
        }

        if (locatorOffset >= 0) {
            evidence.push(
                "ZIP64 EOCD locator detected."
            );
        }

        if (
            !marker &&
            locatorOffset < 0
        ) {
            return {
                detected: false,
                resolved: null,
                evidence
            };
        }

        if (locatorOffset < 0) {
            return {
                detected: true,
                resolved: null,
                error:
                    "ZIP64 marker values were present but the ZIP64 EOCD locator was not found.",
                evidence
            };
        }

        if (
            locatorOffset + 20 >
            bytes.length
        ) {
            return {
                detected: true,
                resolved: null,
                error:
                    "ZIP64 EOCD locator extends beyond the file.",
                evidence
            };
        }

        const recordOffset =
            this.readUInt64LE(
                bytes,
                locatorOffset + 8
            );

        if (
            !Number.isSafeInteger(
                recordOffset
            ) ||
            recordOffset < 0 ||
            recordOffset + 56 >
                bytes.length
        ) {
            return {
                detected: true,
                resolved: null,
                error:
                    "ZIP64 EOCD record offset is invalid or outside the file.",
                evidence
            };
        }

        if (
            this.readUInt32LE(
                bytes,
                recordOffset
            ) !==
            this.ZIP64_END_OF_CENTRAL_DIRECTORY
        ) {
            return {
                detected: true,
                resolved: null,
                error:
                    "ZIP64 EOCD record signature was not found at the locator target.",
                evidence
            };
        }

        evidence.push(
            "ZIP64 EOCD record detected."
        );

        const recordSize =
            this.readUInt64LE(
                bytes,
                recordOffset + 4
            );

        if (
            !Number.isSafeInteger(
                recordSize
            ) ||
            recordOffset +
                12 +
                recordSize >
                bytes.length
        ) {
            return {
                detected: true,
                resolved: null,
                error:
                    "ZIP64 EOCD record size is invalid.",
                evidence
            };
        }

        const entries =
            this.readUInt64LE(
                bytes,
                recordOffset + 32
            );

        const centralDirectorySize =
            this.readUInt64LE(
                bytes,
                recordOffset + 40
            );

        const centralDirectoryOffset =
            this.readUInt64LE(
                bytes,
                recordOffset + 48
            );

        if (
            !Number.isSafeInteger(
                entries
            ) ||
            !Number.isSafeInteger(
                centralDirectorySize
            ) ||
            !Number.isSafeInteger(
                centralDirectoryOffset
            )
        ) {
            return {
                detected: true,
                resolved: null,
                error:
                    "ZIP64 values exceed JavaScript's safe integer range.",
                evidence
            };
        }

        return {
            detected: true,

            resolved: {
                entries,
                centralDirectorySize,
                centralDirectoryOffset
            },

            evidence
        };
    },

        parseCentralDirectory(bytes, directoryInfo, context) {
        const entries = [];

        const start =
            directoryInfo.centralDirectoryOffset;

        const end =
            start +
            directoryInfo.centralDirectorySize;

        if (
            start < 0 ||
            end < start ||
            end > bytes.length
        ) {
            return {
                entries,
                error:
                    "Central directory range is outside the file."
            };
        }

        let offset = start;

        while (
            offset < end &&
            entries.length <
                this.MAX_ENTRIES
        ) {
            this.checkpoint(
                context,
                "archive-central-directory"
            );

            if (
                offset + 46 >
                bytes.length
            ) {
                return {
                    entries,
                    error:
                        "ZIP central directory entry is truncated."
                };
            }

            const signature =
                this.readUInt32LE(
                    bytes,
                    offset
                );

            if (
                signature !==
                this.ZIP_CENTRAL_DIRECTORY_HEADER
            ) {
                return {
                    entries,
                    error:
                        "Invalid central directory entry signature at offset " +
                        offset +
                        "."
                };
            }

            const flags =
                this.readUInt16LE(
                    bytes,
                    offset + 8
                );

            const compressionMethod =
                this.readUInt16LE(
                    bytes,
                    offset + 10
                );

            const compressedSize32 =
                this.readUInt32LE(
                    bytes,
                    offset + 20
                );

            const uncompressedSize32 =
                this.readUInt32LE(
                    bytes,
                    offset + 24
                );

            const fileNameLength =
                this.readUInt16LE(
                    bytes,
                    offset + 28
                );

            const extraLength =
                this.readUInt16LE(
                    bytes,
                    offset + 30
                );

            const commentLength =
                this.readUInt16LE(
                    bytes,
                    offset + 32
                );

            const diskStart =
                this.readUInt16LE(
                    bytes,
                    offset + 34
                );

            const externalAttributes =
                this.readUInt32LE(
                    bytes,
                    offset + 38
                );

            const localHeaderOffset32 =
                this.readUInt32LE(
                    bytes,
                    offset + 42
                );

            const recordLength =
                46 +
                fileNameLength +
                extraLength +
                commentLength;

            if (
                offset +
                recordLength >
                bytes.length
            ) {
                return {
                    entries,
                    error:
                        "ZIP central directory entry extends beyond the file."
                };
            }

            const fileNameBytes =
                bytes.slice(
                    offset + 46,
                    offset +
                        46 +
                        fileNameLength
                );

            const extraBytes =
                bytes.slice(
                    offset +
                        46 +
                        fileNameLength,
                    offset +
                        46 +
                        fileNameLength +
                        extraLength
                );

            const commentBytes =
                bytes.slice(
                    offset +
                        46 +
                        fileNameLength +
                        extraLength,
                    offset +
                        recordLength
                );

            const fileName =
                this.decodeText(
                    fileNameBytes,
                    flags
                );

            const comment =
                this.decodeText(
                    commentBytes,
                    flags
                );

            const zip64Values =
                this.parseZip64Extra(
                    extraBytes,
                    compressedSize32 ===
                        0xFFFFFFFF,
                    uncompressedSize32 ===
                        0xFFFFFFFF,
                    localHeaderOffset32 ===
                        0xFFFFFFFF,
                    diskStart ===
                        0xFFFF
                );

            if (
                zip64Values.error
            ) {
                return {
                    entries,
                    error:
                        "Invalid ZIP64 extra field for entry '" +
                        fileName +
                        "': " +
                        zip64Values.error
                };
            }

            const compressedSize =
                compressedSize32 ===
                0xFFFFFFFF
                    ? zip64Values.compressedSize
                    : compressedSize32;

            const uncompressedSize =
                uncompressedSize32 ===
                0xFFFFFFFF
                    ? zip64Values.uncompressedSize
                    : uncompressedSize32;

            const localHeaderOffset =
                localHeaderOffset32 ===
                0xFFFFFFFF
                    ? zip64Values.localHeaderOffset
                    : localHeaderOffset32;

            const resolvedDiskStart =
                diskStart === 0xFFFF
                    ? zip64Values.diskStart
                    : diskStart;

            if (
                !Number.isSafeInteger(
                    compressedSize
                ) ||
                !Number.isSafeInteger(
                    uncompressedSize
                ) ||
                !Number.isSafeInteger(
                    localHeaderOffset
                )
            ) {
                return {
                    entries,
                    error:
                        "ZIP64 entry values exceed JavaScript's safe integer range."
                };
            }

            const isDirectory =
                fileName.endsWith("/") ||
                (
                    externalAttributes &
                    0x10
                ) !== 0;

            const encrypted =
                (
                    flags &
                    0x0001
                ) !== 0;

            const compressionRatio =
                compressedSize > 0
                    ? uncompressedSize /
                      compressedSize
                    : uncompressedSize > 0
                        ? Infinity
                        : 1;

            const entry = {
                index:
                    entries.length,

                name:
                    fileName,

                comment,

                directory:
                    isDirectory,

                encrypted,

                compressionMethod,

                compressedSize,

                uncompressedSize,

                compressionRatio,

                localHeaderOffset,

                diskStart:
                    resolvedDiskStart,

                flags,

                externalAttributes,

                zip64:
                    compressedSize32 ===
                        0xFFFFFFFF ||
                    uncompressedSize32 ===
                        0xFFFFFFFF ||
                    localHeaderOffset32 ===
                        0xFFFFFFFF ||
                    diskStart ===
                        0xFFFF,

                suspicious:
                    false,

                issues: []
            };

            this.inspectEntryPath(
                entry
            );

            if (
                entry.uncompressedSize >
                this.SUSPICIOUS_UNCOMPRESSED_SIZE
            ) {
                entry.suspicious =
                    true;

                entry.issues.push(
                    "large-uncompressed-size"
                );
            }

            if (
                entry.compressionRatio >=
                this.SUSPICIOUS_COMPRESSION_RATIO
            ) {
                entry.suspicious =
                    true;

                entry.issues.push(
                    "high-compression-ratio"
                );
            }

            if (
                entry.encrypted
            ) {
                entry.suspicious =
                    true;

                entry.issues.push(
                    "encrypted"
                );
            }

            entries.push(
                entry
            );

            offset +=
                recordLength;
        }

        if (
            entries.length >
            this.MAX_ENTRIES
        ) {
            return {
                entries:
                    entries.slice(
                        0,
                        this.MAX_ENTRIES
                    ),

                error:
                    "Archive entry count exceeds the analysis limit."
            };
        }

        if (
            entries.length !==
            directoryInfo.entries
        ) {
            return {
                entries,

                error:
                    "Parsed entry count does not match the ZIP central directory."
            };
        }

        return {
            entries,
            error: null
        };
    },

    parseZip64Extra(
        extraBytes,
        needUncompressedSize,
        needCompressedSize,
        needOffset,
        needDiskStart
    ) {
        let offset = 0;

        while (
            offset + 4 <=
            extraBytes.length
        ) {
            const headerId =
                this.readUInt16LE(
                    extraBytes,
                    offset
                );

            const dataSize =
                this.readUInt16LE(
                    extraBytes,
                    offset + 2
                );

            offset += 4;

            if (
                offset +
                dataSize >
                extraBytes.length
            ) {
                return {
                    error:
                        "Extra field extends beyond the available entry data."
                };
            }

            if (
                headerId !== 0x0001
            ) {
                offset +=
                    dataSize;

                continue;
            }

            let cursor = offset;

            const result = {
                uncompressedSize: null,
                compressedSize: null,
                localHeaderOffset: null,
                diskStart: null
            };

            if (
                needUncompressedSize
            ) {
                if (
                    cursor + 8 >
                    offset + dataSize
                ) {
                    return {
                        error:
                            "ZIP64 uncompressed size is missing."
                    };
                }

                result.uncompressedSize =
                    this.readUInt64LE(
                        extraBytes,
                        cursor
                    );

                cursor += 8;
            }

            if (
                needCompressedSize
            ) {
                if (
                    cursor + 8 >
                    offset + dataSize
                ) {
                    return {
                        error:
                            "ZIP64 compressed size is missing."
                    };
                }

                result.compressedSize =
                    this.readUInt64LE(
                        extraBytes,
                        cursor
                    );

                cursor += 8;
            }

            if (
                needOffset
            ) {
                if (
                    cursor + 8 >
                    offset + dataSize
                ) {
                    return {
                        error:
                            "ZIP64 local header offset is missing."
                    };
                }

                result.localHeaderOffset =
                    this.readUInt64LE(
                        extraBytes,
                        cursor
                    );

                cursor += 8;
            }

            if (
                needDiskStart
            ) {
                if (
                    cursor + 4 >
                    offset + dataSize
                ) {
                    return {
                        error:
                            "ZIP64 disk-start value is missing."
                    };
                }

                result.diskStart =
                    this.readUInt32LE(
                        extraBytes,
                        cursor
                    );

                cursor += 4;
            }

            return result;
        }

        if (
            needUncompressedSize ||
            needCompressedSize ||
            needOffset ||
            needDiskStart
        ) {
            return {
                error:
                    "ZIP64 extra field was required but not found."
            };
        }

        return {
            uncompressedSize: null,
            compressedSize: null,
            localHeaderOffset: null,
            diskStart: null,
            error: null
        };
    },

    analyzeEntries(result) {
        const entries =
            result.entries;

        const names =
            new Map();

        let compressedBytes = 0;
        let uncompressedBytes = 0;
        let encryptedEntries = 0;
        let directories = 0;
        let files = 0;

        let suspiciousCompression = false;

        for (
            const entry of entries
        ) {
            if (
                entry.directory
            ) {
                directories++;
            } else {
                files++;
            }

            if (
                entry.encrypted
            ) {
                encryptedEntries++;
            }

            compressedBytes +=
                entry.compressedSize;

            uncompressedBytes +=
                entry.uncompressedSize;

            const normalizedName =
                entry.name
                    .replace(
                        /\\/g,
                        "/"
                    )
                    .toLowerCase();

            if (
                names.has(
                    normalizedName
                )
            ) {
                entry.suspicious =
                    true;

                entry.issues.push(
                    "duplicate-name"
                );

                result.features.duplicateNames =
                    true;
            } else {
                names.set(
                    normalizedName,
                    entry.index
                );
            }

            if (
                entry.issues.includes(
                    "high-compression-ratio"
                )
            ) {
                suspiciousCompression =
                    true;
            }

            if (
                entry.issues.length
            ) {
                result.findings.push(
                    this.createEntryFinding(
                        entry
                    )
                );
            }
        }

        result.statistics = {
            compressedBytes,
            uncompressedBytes,

            compressionRatio:
                compressedBytes > 0
                    ? uncompressedBytes /
                      compressedBytes
                    : null,

            encryptedEntries,

            directories,

            files
        };

        result.features.encrypted =
            encryptedEntries > 0;

        result.features.suspiciousCompression =
            suspiciousCompression;

        if (
            encryptedEntries > 0
        ) {
            result.findings.push({
                id:
                    "encrypted-entries",

                severity:
                    "LOW",

                confidence:
                    "HIGH",

                title:
                    "Encrypted ZIP entries detected.",

                description:
                    encryptedEntries +
                    " archive entr" +
                    (
                        encryptedEntries === 1
                            ? "y is"
                            : "ies are"
                    ) +
                    " encrypted and cannot be fully inspected by the current browser parser.",

                evidence: {
                    count:
                        encryptedEntries
                },

                recommendation:
                    "Do not assume encrypted content is safe. Inspect it separately if the password is trusted and available."
            });
        }

        if (
            result.features.duplicateNames
        ) {
            result.findings.push({
                id:
                    "duplicate-entry-names",

                severity:
                    "MEDIUM",

                confidence:
                    "HIGH",

                title:
                    "Duplicate archive entry names detected.",

                description:
                    "Multiple entries resolve to the same normalized path.",

                evidence: {
                    count:
                        entries.filter(
                            entry =>
                                entry.issues.includes(
                                    "duplicate-name"
                                )
                        ).length
                },

                recommendation:
                    "Inspect duplicate paths because extraction behavior can differ between archive implementations."
            });
        }

        if (
            result.statistics.compressionRatio !==
                null &&
            result.statistics.compressionRatio >=
                this.SUSPICIOUS_COMPRESSION_RATIO
        ) {
            result.findings.push({
                id:
                    "archive-compression-ratio",

                severity:
                    "MEDIUM",

                confidence:
                    "HIGH",

                title:
                    "Archive compression ratio is unusually high.",

                description:
                    "The declared uncompressed size is substantially larger than the compressed representation.",

                evidence: {
                    compressedBytes:
                        compressedBytes,

                    uncompressedBytes:
                        uncompressedBytes,

                    compressionRatio:
                        result.statistics.compressionRatio
                },

                recommendation:
                    "Do not extract without resource limits. Validate the declared sizes before processing."
            });
        }
    },

        createEntryFinding(entry) {
        let severity =
            "LOW";

        if (
            entry.issues.includes(
                "path-traversal"
            ) ||
            entry.issues.includes(
                "absolute-path"
            )
        ) {
            severity =
                "HIGH";
        } else if (
            entry.issues.includes(
                "high-compression-ratio"
            ) ||
            entry.issues.includes(
                "duplicate-name"
            )
        ) {
            severity =
                "MEDIUM";
        }

        const issueLabels = {
            "path-traversal":
                "path traversal",

            "absolute-path":
                "absolute path",

            "large-uncompressed-size":
                "large declared uncompressed size",

            "high-compression-ratio":
                "high compression ratio",

            encrypted:
                "encryption",

            "duplicate-name":
                "duplicate entry name"
        };

        const readableIssues =
            entry.issues.map(
                issue =>
                    issueLabels[issue] ||
                    issue
            );

        return {
            id:
                "archive-entry-" +
                entry.index,

            severity,

            confidence:
                "HIGH",

            title:
                "Suspicious archive entry: " +
                entry.name,

            description:
                "The entry has the following structural characteristics: " +
                readableIssues.join(
                    ", "
                ) +
                ".",

            evidence: {
                entry:
                    entry.name,

                compressedSize:
                    entry.compressedSize,

                uncompressedSize:
                    entry.uncompressedSize,

                compressionRatio:
                    entry.compressionRatio,

                issues:
                    entry.issues
            },

            recommendation:
                "Inspect this entry before extraction or execution."
        };
    },

    inspectEntryPath(entry) {
        const normalized =
            entry.name
                .replace(
                    /\\/g,
                    "/"
                );

        const segments =
            normalized.split(
                "/"
            );

        const hasTraversal =
            segments.some(
                segment =>
                    segment === ".."
            );

        const hasAbsolutePath =
            normalized.startsWith("/") ||
            /^[A-Za-z]:\//.test(
                normalized
            ) ||
            normalized.startsWith(
                "\\\\"
            );

        if (
            hasTraversal
        ) {
            entry.suspicious =
                true;

            entry.issues.push(
                "path-traversal"
            );
        }

        if (
            hasAbsolutePath
        ) {
            entry.suspicious =
                true;

            entry.issues.push(
                "absolute-path"
            );
        }
    },

    identifyContainer(entries) {
        const markers = [];

        let hasJava =
            false;

        let hasAndroid =
            false;

        let hasArchive =
            false;

        for (
            const entry of entries
        ) {
            const name =
                entry.name
                    .replace(
                        /\\/g,
                        "/"
                    )
                    .toLowerCase();

            if (
                name ===
                "meta-inf/manifest.mf"
            ) {
                hasJava = true;

                markers.push(
                    "META-INF/MANIFEST.MF"
                );
            }

            if (
                name ===
                "androidmanifest.xml"
            ) {
                hasAndroid = true;

                markers.push(
                    "AndroidManifest.xml"
                );
            }

            if (
                /\.(zip|jar|apk|aar|war|ear)$/i.test(
                    name
                )
            ) {
                hasArchive = true;
            }
        }

        if (
            hasAndroid
        ) {
            return {
                type:
                    "APK",

                format:
                    "APK",

                markers,

                description:
                    "Android application package structure detected inside the ZIP container."
            };
        }

        if (
            hasJava
        ) {
            return {
                type:
                    "JAR",

                format:
                    "JAR",

                markers,

                description:
                    "Java archive structure detected inside the ZIP container."
            };
        }

        if (
            hasArchive
        ) {
            markers.push(
                "nested-archive-extension"
            );
        }

        return {
            type:
                "ZIP",

            format:
                "ZIP",

            markers,

            description:
                "Standard ZIP container detected."
        };
    },

    detectNestedArchives(entries) {
        const nested = [];

        for (
            const entry of entries
        ) {
            if (
                entry.directory
            ) {
                continue;
            }

            const name =
                entry.name
                    .toLowerCase();

            if (
                /\.(zip|jar|apk|aar|war|ear|7z|rar|tar|gz|bz2)$/i.test(
                    name
                )
            ) {
                nested.push(
                    entry.name
                );
            }
        }

        return nested;
    },

    readUInt16LE(bytes, offset) {
        if (
            offset < 0 ||
            offset + 2 >
                bytes.length
        ) {
            throw new RangeError(
                "Unable to read UInt16LE outside the buffer."
            );
        }

        return (
            bytes[offset] |
            (
                bytes[offset + 1] <<
                8
            )
        ) >>> 0;
    },

    readUInt32LE(bytes, offset) {
        if (
            offset < 0 ||
            offset + 4 >
                bytes.length
        ) {
            throw new RangeError(
                "Unable to read UInt32LE outside the buffer."
            );
        }

        return (
            bytes[offset] |
            (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) |
            (bytes[offset + 3] << 24)
        ) >>> 0;
    },

    readUInt64LE(bytes, offset) {
        if (
            offset < 0 ||
            offset + 8 >
                bytes.length
        ) {
            throw new RangeError(
                "Unable to read UInt64LE outside the buffer."
            );
        }

        const low =
            this.readUInt32LE(
                bytes,
                offset
            );

        const high =
            this.readUInt32LE(
                bytes,
                offset + 4
            );

        const value =
            high * 4294967296 +
            low;

        if (
            !Number.isSafeInteger(
                value
            )
        ) {
            return Number.MAX_SAFE_INTEGER;
        }

        return value;
    },

    decodeText(bytes, flags) {
        if (
            !bytes.length
        ) {
            return "";
        }

        if (
            flags & 0x0800
        ) {
            try {
                return new TextDecoder(
                    "utf-8",
                    {
                        fatal: false
                    }
                ).decode(bytes);
            } catch {
                return this.decodeLatin1(
                    bytes
                );
            }
        }

        return this.decodeLatin1(
            bytes
        );
    },

    decodeLatin1(bytes) {
        let output = "";

        for (
            let index = 0;
            index < bytes.length;
            index++
        ) {
            output += String.fromCharCode(
                bytes[index]
            );
        }

        return output;
    },

    checkpoint(context, label) {
        if (
            context &&
            typeof context.checkpoint ===
                "function"
        ) {
            context.checkpoint(
                label
            );
        }
    },

    validateFile(file) {
        if (
            !(file instanceof File)
        ) {
            throw new TypeError(
                "Archive analyzer requires a File object."
            );
        }
    },

    createLimitError(
        actual,
        limit
    ) {
        const error =
            new Error(
                "Archive input exceeds the configured file-size limit."
            );

        error.name =
            "ResourceLimitError";

        error.code =
            "FILE_TOO_LARGE";

        error.actual =
            actual;

        error.limit =
            limit;

        return error;
    }
};

window.FileGuardArchiveAnalyzer =
    FileGuardArchiveAnalyzer;
