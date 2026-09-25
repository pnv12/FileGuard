"use strict";

/*
 * FILEGUARD
 * Archive Analyzer
 *
 * V1.0
 *
 * Purpose:
 * - inspect ZIP-based containers locally
 * - parse the ZIP central directory
 * - enumerate files
 * - detect encrypted entries
 * - detect ZIP64
 * - detect path traversal / absolute paths
 * - detect duplicate entry names
 * - detect suspicious compression ratios
 * - identify known container types:
 *   - APK
 *   - JAR
 *   - DOCX
 *   - XLSX
 *   - PPTX
 *   - ZIP
 *
 * No external libraries required.
 */


const FileGuardArchiveAnalyzer = {

    VERSION: "1.0.0",

    MAX_ENTRIES: 100000,

    ZIP_LOCAL_FILE_HEADER: 0x04034B50,

    ZIP_CENTRAL_DIRECTORY_HEADER: 0x02014B50,

    ZIP_END_OF_CENTRAL_DIRECTORY: 0x06054B50,

    ZIP64_END_OF_CENTRAL_DIRECTORY: 0x06064B50,

    ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR: 0x07064B50,


    async analyze(file) {

        this.validateFile(file);


        const startedAt =
            performance.now();


        const basicResult = {

            analyzer:
                "archive",

            analyzerVersion:
                this.VERSION,

            status:
                "unknown",

            format:
                "ZIP",

            containerType:
                "ZIP",

            entryCount:
                0,

            entries:
                [],

            statistics: {

                compressedBytes:
                    0,

                uncompressedBytes:
                    0,

                compressionRatio:
                    null,

                encryptedEntries:
                    0,

                directories:
                    0,

                files:
                    0

            },

            features: {

                zip64:
                    false,

                encrypted:
                    false,

                duplicateNames:
                    false,

                pathTraversal:
                    false,

                absolutePaths:
                    false,

                suspiciousCompression:
                    false,

                nestedArchives:
                    false

            },

            findings: [],

            evidence: {

                signatures: [],

                containerMarkers: [],

                centralDirectory:
                    null

            }

        };


        /*
         * Read the complete file.
         *
         * This is intentional for V1 because the
         * archive analyzer needs random access to
         * ZIP structures.
         */

        const buffer =
            await file.arrayBuffer();


        const bytes =
            new Uint8Array(buffer);


        /*
         * Validate ZIP structure.
         */

        const endRecord =
            this.findEndOfCentralDirectory(
                bytes
            );


        if (!endRecord) {

            return {

                ...basicResult,

                status:
                    "invalid",

                findings: [

                    {

                        id:
                            "invalid-zip-structure",

                        severity:
                            "MEDIUM",

                        confidence:
                            "HIGH",

                        title:
                            "ZIP end-of-central-directory record was not found.",

                        description:
                            "The file has ZIP-like characteristics but its central directory could not be located.",

                        evidence:
                            null,

                        recommendation:
                            "Treat the container as structurally invalid until further inspection."

                    }

                ],

                durationMs:
                    Math.round(
                        performance.now() -
                        startedAt
                    )

            };
        }


        basicResult.evidence.centralDirectory = {

            offset:
                endRecord.offset,

            entries:
                endRecord.entries,

            centralDirectoryOffset:
                endRecord.centralDirectoryOffset,

            centralDirectorySize:
                endRecord.centralDirectorySize

        };


        /*
         * Detect ZIP64.
         */

        const zip64 =
            this.detectZip64(
                bytes,
                endRecord
            );


        basicResult.features.zip64 =
            zip64.detected;


        if (zip64.detected) {

            basicResult.findings.push({

                id:
                    "zip64-container",

                severity:
                    "INFO",

                confidence:
                    "HIGH",

                title:
                    "ZIP64 structures detected.",

                description:
                    "The archive uses ZIP64 extensions for large archive metadata.",

                evidence:
                    zip64.evidence,

                recommendation:
                    "Use ZIP64-aware parsers when processing this container."

            });
        }


        /*
         * Parse central directory.
         */

        const entries =
            this.parseCentralDirectory(
                bytes,
                endRecord
            );


        if (
            entries.error
        ) {

            basicResult.status =
                "invalid";

            basicResult.findings.push({

                id:
                    "central-directory-parse-failed",

                severity:
                    "MEDIUM",

                confidence:
                    "HIGH",

                title:
                    "ZIP central directory could not be parsed completely.",

                description:
                    entries.error,

                evidence: {

                    centralDirectoryOffset:
                        endRecord.centralDirectoryOffset,

                    centralDirectorySize:
                        endRecord.centralDirectorySize

                },

                recommendation:
                    "Treat the archive as structurally suspicious until it can be validated by another ZIP parser."

            });


            return {

                ...basicResult,

                durationMs:
                    Math.round(
                        performance.now() -
                        startedAt
                    )

            };
        }


        basicResult.entries =
            entries.entries;


        basicResult.entryCount =
            entries.entries.length;


        /*
         * Entry limit protection.
         */

        if (
            entries.entries.length >
            this.MAX_ENTRIES
        ) {

            basicResult.findings.push({

                id:
                    "entry-count-limit",

                severity:
                    "MEDIUM",

                confidence:
                    "HIGH",

                title:
                    "Archive contains an unusually large number of entries.",

                description:
                    `The archive contains ${entries.entries.length.toLocaleString()} entries.`,

                evidence: {

                    entryCount:
                        entries.entries.length,

                    limit:
                        this.MAX_ENTRIES

                },

                recommendation:
                    "Avoid blindly extracting the archive. Inspect the entry list before processing it."

            });
        }


        /*
         * Analyze entry metadata.
         */

        this.analyzeEntries(
            basicResult
        );


        /*
         * Identify the container.
         */

        const container =
            this.identifyContainer(
                basicResult.entries
            );


        basicResult.containerType =
            container.type;

        basicResult.format =
            container.format;


        basicResult.evidence.containerMarkers =
            container.markers;


        /*
         * Add container finding.
         */

        if (
            container.type !== "ZIP"
        ) {

            basicResult.findings.push({

                id:
                    `container-${container.type.toLowerCase()}`,

                severity:
                    "INFO",

                confidence:
                    "HIGH",

                title:
                    `${container.type} container identified.`,

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


        /*
         * Nested archive detection.
         */

        const nestedArchives =
            this.detectNestedArchives(
                basicResult.entries
            );


        if (
            nestedArchives.length > 0
        ) {

            basicResult.features.nestedArchives =
                true;


            basicResult.findings.push({

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
                        nestedArchives

                },

                recommendation:
                    "Inspect nested archives separately if their contents are relevant to the investigation."

            });
        }


        /*
         * Final status.
         */

        basicResult.status =
            "completed";


        basicResult.durationMs =
            Math.round(
                performance.now() -
                startedAt
            );


        return basicResult;
    },


    findEndOfCentralDirectory(bytes) {

        /*
         * EOCD can appear within the final
         * 65,535 bytes plus its fixed structure.
         */

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


            const diskNumber =
                this.readUInt16LE(
                    bytes,
                    offset + 4
                );


            const centralDirectoryDisk =
                this.readUInt16LE(
                    bytes,
                    offset + 6
                );


            const entriesOnDisk =
                this.readUInt16LE(
                    bytes,
                    offset + 8
                );


            const totalEntries =
                this.readUInt16LE(
                    bytes,
                    offset + 10
                );


            const centralDirectorySize =
                this.readUInt32LE(
                    bytes,
                    offset + 12
                );


            const centralDirectoryOffset =
                this.readUInt32LE(
                    bytes,
                    offset + 16
                );


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

                diskNumber,

                centralDirectoryDisk,

                entriesOnDisk,

                entries:
                    totalEntries,

                centralDirectorySize,

                centralDirectoryOffset

            };
        }


        return null;
    },


    detectZip64(
        bytes,
        endRecord
    ) {

        const evidence = [];


        /*
         * Standard ZIP64 trigger:
         * EOCD fields contain maximum
         * 16/32-bit values.
         */

        if (
            endRecord.entries === 0xFFFF ||
            endRecord.centralDirectorySize ===
                0xFFFFFFFF ||
            endRecord.centralDirectoryOffset ===
                0xFFFFFFFF
        ) {

            evidence.push(
                "ZIP64 marker values present in EOCD."
            );
        }


        /*
         * Search for ZIP64 EOCD locator
         * immediately before EOCD.
         */

        const searchStart =
            Math.max(
                0,
                endRecord.offset - 64
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
                this.ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR
            ) {

                evidence.push(
                    "ZIP64 EOCD locator detected."
                );

                break;
            }
        }


        /*
         * Search nearby for ZIP64 EOCD.
         */

        const zip64SearchStart =
            Math.max(
                0,
                endRecord.offset - 256
            );


        for (
            let offset =
                endRecord.offset - 56;

            offset >= zip64SearchStart;

            offset--
        ) {

            if (
                this.readUInt32LE(
                    bytes,
                    offset
                ) ===
                this.ZIP64_END_OF_CENTRAL_DIRECTORY
            ) {

                evidence.push(
                    "ZIP64 EOCD record detected."
                );

                break;
            }
        }


        return {

            detected:
                evidence.length > 0,

            evidence

        };
    },


    parseCentralDirectory(
        bytes,
        endRecord
    ) {

        const entries = [];


        let offset =
            endRecord.centralDirectoryOffset;


        const endOffset =
            Math.min(
                bytes.length,
                endRecord.centralDirectoryOffset +
                endRecord.centralDirectorySize
            );


        while (
            offset + 46 <=
            endOffset
        ) {

            const signature =
                this.readUInt32LE(
                    bytes,
                    offset
                );


            if (
                signature !==
                this.ZIP_CENTRAL_DIRECTORY_HEADER
            ) {

                break;
            }


            const versionMadeBy =
                this.readUInt16LE(
                    bytes,
                    offset + 4
                );


            const versionNeeded =
                this.readUInt16LE(
                    bytes,
                    offset + 6
                );


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


            const modifiedTime =
                this.readUInt16LE(
                    bytes,
                    offset + 12
                );


            const modifiedDate =
                this.readUInt16LE(
                    bytes,
                    offset + 14
                );


            const crc32 =
                this.readUInt32LE(
                    bytes,
                    offset + 16
                );


            const compressedSize =
                this.readUInt32LE(
                    bytes,
                    offset + 20
                );


            const uncompressedSize =
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


            const internalAttributes =
                this.readUInt16LE(
                    bytes,
                    offset + 36
                );


            const externalAttributes =
                this.readUInt32LE(
                    bytes,
                    offset + 38
                );


            const localHeaderOffset =
                this.readUInt32LE(
                    bytes,
                    offset + 42
                );


            const totalHeaderSize =
                46 +
                fileNameLength +
                extraLength +
                commentLength;


            if (
                offset +
                totalHeaderSize >
                endOffset
            ) {

                return {

                    error:
                        "A central directory entry extends beyond the declared central directory bounds.",

                    entries

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
                    totalHeaderSize
                );


            const fileName =
                this.decodeFileName(
                    fileNameBytes,
                    flags
                );


            const comment =
                this.decodeText(
                    commentBytes
                );


            const extraFields =
                this.parseExtraFields(
                    extraBytes
                );


            const directory =
                fileName.endsWith("/");


            const encrypted =
                Boolean(
                    flags & 0x0001
                );


            const entry = {

                name:
                    fileName,

                type:
                    directory
                        ? "directory"
                        : "file",

                compressedSize,

                uncompressedSize,

                compressionMethod,

 
