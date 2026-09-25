"use strict";

/*
 * FILEGUARD
 * File Detector
 *
 * V1.0
 *
 * Purpose:
 * - inspect real file bytes
 * - identify known file signatures
 * - compare detected format with filename extension
 * - compare detected format with browser MIME type
 * - detect container formats
 * - calculate detection confidence
 * - provide normalized detection data to the router
 *
 * IMPORTANT:
 * File extension and browser MIME type are treated as hints.
 * The byte signature is the primary source when available.
 */


const FileGuardDetector = {

    VERSION: "1.0.0",

    DEFAULT_HEADER_SIZE: 512,

    MAX_SIGNATURE_OFFSET: 256,


    SIGNATURES: [

        {
            id: "png",
            format: "PNG",
            category: "image",
            mimeTypes: [
                "image/png"
            ],
            extensions: [
                "png"
            ],
            signature: [
                0x89, 0x50, 0x4E, 0x47,
                0x0D, 0x0A, 0x1A, 0x0A
            ]
        },


        {
            id: "jpeg",
            format: "JPEG",
            category: "image",
            mimeTypes: [
                "image/jpeg"
            ],
            extensions: [
                "jpg",
                "jpeg",
                "jpe"
            ],
            signature: [
                0xFF, 0xD8, 0xFF
            ]
        },


        {
            id: "gif",
            format: "GIF",
            category: "image",
            mimeTypes: [
                "image/gif"
            ],
            extensions: [
                "gif"
            ],
            signatures: [
                [
                    0x47, 0x49, 0x46, 0x38,
                    0x37, 0x61
                ],
                [
                    0x47, 0x49, 0x46, 0x38,
                    0x39, 0x61
                ]
            ]
        },


        {
            id: "webp",
            format: "WEBP",
            category: "image",
            mimeTypes: [
                "image/webp"
            ],
            extensions: [
                "webp"
            ],
            customDetector:
                "riff-webp"
        },


        {
            id: "pdf",
            format: "PDF",
            category: "document",
            mimeTypes: [
                "application/pdf"
            ],
            extensions: [
                "pdf"
            ],
            signature: [
                0x25, 0x50, 0x44, 0x46,
                0x2D
            ]
        },


        {
            id: "zip",
            format: "ZIP",
            category: "archive",
            mimeTypes: [
                "application/zip",
                "application/x-zip-compressed"
            ],
            extensions: [
                "zip"
            ],
            signatures: [
                [
                    0x50, 0x4B, 0x03, 0x04
                ],
                [
                    0x50, 0x4B, 0x05, 0x06
                ],
                [
                    0x50, 0x4B, 0x07, 0x08
                ]
            ]
        },


        {
            id: "gzip",
            format: "GZIP",
            category: "archive",
            mimeTypes: [
                "application/gzip",
                "application/x-gzip"
            ],
            extensions: [
                "gz",
                "gzip"
            ],
            signature: [
                0x1F, 0x8B
            ]
        },


        {
            id: "bzip2",
            format: "BZIP2",
            category: "archive",
            mimeTypes: [
                "application/x-bzip2"
            ],
            extensions: [
                "bz2"
            ],
            signature: [
                0x42, 0x5A, 0x68
            ]
        },


        {
            id: "rar",
            format: "RAR",
            category: "archive",
            mimeTypes: [
                "application/vnd.rar"
            ],
            extensions: [
                "rar"
            ],
            signatures: [
                [
                    0x52, 0x61, 0x72, 0x21,
                    0x1A, 0x07, 0x00
                ],
                [
                    0x52, 0x61, 0x72, 0x21,
                    0x1A, 0x07, 0x01,
                    0x00
                ]
            ]
        },


        {
            id: "7z",
            format: "7-Zip",
            category: "archive",
            mimeTypes: [
                "application/x-7z-compressed"
            ],
            extensions: [
                "7z"
            ],
            signature: [
                0x37, 0x7A, 0xBC, 0xAF,
                0x27, 0x1C
            ]
        },


        {
            id: "elf",
            format: "ELF",
            category: "executable",
            mimeTypes: [
                "application/x-executable",
                "application/x-elf"
            ],
            extensions: [
                "elf",
                "so"
            ],
            signature: [
                0x7F, 0x45, 0x4C, 0x46
            ]
        },


        {
            id: "pe",
            format: "PE",
            category: "executable",
            mimeTypes: [
                "application/vnd.microsoft.portable-executable",
                "application/x-msdownload"
            ],
            extensions: [
                "exe",
                "dll",
                "sys",
                "scr"
            ],
            signature: [
                0x4D, 0x5A
            ]
        },


        {
            id: "wasm",
            format: "WebAssembly",
            category: "executable",
            mimeTypes: [
                "application/wasm"
            ],
            extensions: [
                "wasm"
            ],
            signature: [
                0x00, 0x61, 0x73, 0x6D
            ]
        },


        {
            id: "mp3",
            format: "MP3",
            category: "audio",
            mimeTypes: [
                "audio/mpeg"
            ],
            extensions: [
                "mp3"
            ],
            customDetector:
                "mp3"
        },


        {
            id: "wav",
            format: "WAV",
            category: "audio",
            mimeTypes: [
                "audio/wav",
                "audio/x-wav"
            ],
            extensions: [
                "wav"
            ],
            customDetector:
                "riff-wav"
        },


        {
            id: "ogg",
            format: "OGG",
            category: "audio",
            mimeTypes: [
                "audio/ogg"
            ],
            extensions: [
                "ogg",
                "oga",
                "ogv"
            ],
            signature: [
                0x4F, 0x67, 0x67, 0x53
            ]
        },


        {
            id: "flac",
            format: "FLAC",
            category: "audio",
            mimeTypes: [
                "audio/flac"
            ],
            extensions: [
                "flac"
            ],
            signature: [
                0x66, 0x4C, 0x61, 0x43
            ]
        },


        {
            id: "mp4",
            format: "MP4",
            category: "video",
            mimeTypes: [
                "video/mp4"
            ],
            extensions: [
                "mp4"
            ],
            customDetector:
                "mp4"
        },


        {
            id: "webm",
            format: "WebM",
            category: "video",
            mimeTypes: [
                "video/webm"
            ],
            extensions: [
                "webm"
            ],
            signature: [
                0x1A, 0x45, 0xDF, 0xA3
            ]
        },


        {
            id: "avi",
            format: "AVI",
            category: "video",
            mimeTypes: [
                "video/x-msvideo"
            ],
            extensions: [
                "avi"
            ],
            customDetector:
                "riff-avi"
        },


        {
            id: "docx",
            format: "DOCX",
            category: "document",
            mimeTypes: [
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ],
            extensions: [
                "docx"
            ],
            signatures: [
                [
                    0x50, 0x4B, 0x03, 0x04
                ],
                [
                    0x50, 0x4B, 0x05, 0x06
                ],
                [
                    0x50, 0x4B, 0x07, 0x08
                ]
            ],
            containerType: "zip"
        },


        {
            id: "xlsx",
            format: "XLSX",
            category: "document",
            mimeTypes: [
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ],
            extensions: [
                "xlsx"
            ],
            signatures: [
                [
                    0x50, 0x4B, 0x03, 0x04
                ],
                [
                    0x50, 0x4B, 0x05, 0x06
                ],
                [
                    0x50, 0x4B, 0x07, 0x08
                ]
            ],
            containerType: "zip"
        },


        {
            id: "pptx",
            format: "PPTX",
            category: "document",
            mimeTypes: [
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            ],
            extensions: [
                "pptx"
            ],
            signatures: [
                [
                    0x50, 0x4B, 0x03, 0x04
                ],
                [
                    0x50, 0x4B, 0x05, 0x06
                ],
                [
                    0x50, 0x4B, 0x07, 0x08
                ]
            ],
            containerType: "zip"
        },


        {
            id: "jar",
            format: "JAR",
            category: "archive",
            mimeTypes: [
                "application/java-archive"
            ],
            extensions: [
                "jar"
            ],
            signatures: [
                [
                    0x50, 0x4B, 0x03, 0x04
                ],
                [
                    0x50, 0x4B, 0x05, 0x06
                ],
                [
                    0x50, 0x4B, 0x07, 0x08
                ]
            ],
            containerType: "zip"
        }


    ],


    async detect(file) {

        this.validateFile(file);


        const header =
            await this.readHeader(
                file,
                this.DEFAULT_HEADER_SIZE
            );


        const extension =
            this.getExtension(
                file.name
            );


        const browserMime =
            file.type || "unknown";


        const byteMatches =
            this.detectBySignature(
                header
            );


        const customMatches =
            this.detectCustomFormats(
                header
            );


        const allMatches =
            [
                ...byteMatches,
                ...customMatches
            ];


        const uniqueMatches =
            this.deduplicateMatches(
                allMatches
            );


        const primary =
            this.selectPrimaryMatch(
                uniqueMatches,
                extension,
                browserMime
            );


        const extensionMatch =
            this.matchExtension(
                primary,
                extension
            );


        const mimeMatch =
            this.matchMimeType(
                primary,
                browserMime
            );


        const confidence =
            this.calculateConfidence(
                primary,
                extensionMatch,
                mimeMatch
            );


        const anomalies =
            this.buildAnomalies(
                primary,
                extension,
                browserMime,
                extensionMatch,
                mimeMatch,
                uniqueMatches
            );


        return {

            detector: "signature",

            detectorVersion:
                this.VERSION,

            status:
                primary
                    ? "detected"
                    : "unknown",

            format:
                primary
                    ? primary.format
                    : "Unknown",

            formatId:
                primary
                    ? primary.id
                    : "unknown",

            category:
                primary
                    ? primary.category
                    : "unknown",

            confidence,

            confidenceScore:
                confidence.score,

            confidenceLevel:
                confidence.level,

            extension,

            browserMime,

            detectedMimeTypes:
                primary
                    ? primary.mimeTypes || []
                    : [],

            expectedExtensions:
                primary
                    ? primary.extensions || []
                    : [],

            signatureMatched:
                Boolean(primary),

            container:
                primary
                    ? primary.containerType || null
                    : null,

            matches:
                uniqueMatches.map(
                    (match) => ({
                        id: match.id,
                        format: match.format,
                        category: match.category,
                        containerType:
                            match.containerType || null
                    })
                ),

            anomalies,

            evidence: {

                headerBytes:
                    this.bytesToHex(
                        header.slice(
                            0,
                            Math.min(
                                header.length,
                                32
                            )
                        )
                    ),

                signature:
                    primary
                        ? this.getMatchedSignature(
                            primary,
                            header
                        )
                        : null

            }

        };
    },


    async readHeader(file, size) {

        const safeSize =
            Math.min(
                size,
                file.size
            );


        const buffer =
            await file.slice(
                0,
                safeSize
            ).arrayBuffer();


        return new Uint8Array(
            buffer
        );
    },


    detectBySignature(bytes) {

        const matches = [];


        for (
            const definition
            of this.SIGNATURES
        ) {

            if (!definition.signature &&
                !definition.signatures) {

                continue;
            }


            const signatures =
                definition.signatures ||
                [
                    definition.signature
                ];


            for (
                const signature
                of signatures
            ) {

                if (
                    this.matchesSignature(
                        bytes,
                        signature
                    )
                ) {

                    matches.push({
                        ...definition,
                        matchedSignature:
                            signature
                    });

                    break;
                }
            }
        }


        return matches;
    },


    detectCustomFormats(bytes) {

        const matches = [];


        for (
            const definition
            of this.SIGNATURES
        ) {

            if (
                !definition.customDetector
            ) {
                continue;
            }


            const matched =
                this.runCustomDetector(
                    definition.customDetector,
                    bytes
                );


            if (matched) {

                matches.push({
                    ...definition,
                    matchedSignature:
                        matched
                });
            }
        }


        return matches;
    },


    runCustomDetector(type, bytes) {

        switch (type) {

            case "riff-webp":

                if (
                    this.matchesAscii(
                        bytes,
                        "RIFF",
                        0
                    ) &&
                    this.matchesAscii(
                        bytes,
                        "WEBP",
                        8
                    )
                ) {

                    return this.sliceBytes(
                        bytes,
                        0,
                        12
                    );
                }

                return null;


            case "riff-wav":

                if (
                    this.matchesAscii(
                        bytes,
                        "RIFF",
                        0
                    ) &&
                    this.matchesAscii(
                        bytes,
                        "WAVE",
                        8
                    )
                ) {

                    return this.sliceBytes(
                        bytes,
                        0,
                        12
                    );
                }

                return null;


            case "riff-avi":

                if (
                    this.matchesAscii(
                        bytes,
                        "RIFF",
                        0
                    ) &&
                    this.matchesAscii(
                        bytes,
                        "AVI ",
                        8
                    )
                ) {

                    return this.sliceBytes(
                        bytes,
                        0,
                        12
                    );
                }

                return null;


            case "mp4":

                return this.detectMp4(
                    bytes
                );


            case "mp3":

                return this.detectMp3(
                    bytes
                );


            default:

                return null;
        }
    },


    detectMp4(bytes) {

        /*
         * ISO Base Media File Format:
         * first box starts with 4-byte size
         * followed by 4-byte type.
         *
         * Common MP4 brands:
         * isom, iso2, mp41, mp42, avc1,
         * M4V, M4A, MSNV, etc.
         */

        if (bytes.length < 12) {
            return null;
        }


        const boxType =
            this.ascii(
                bytes,
                4,
                4
            );


        if (
            boxType !== "ftyp"
        ) {
            return null;
        }


        return this.sliceBytes(
            bytes,
            4,
            8
        );
    },


    detectMp3(bytes) {

        if (bytes.length >= 3) {

            if (
                this.matchesAscii(
                    bytes,
                    "ID3",
                    0
                )
            ) {

                return this.sliceBytes(
                    bytes,
                    0,
                    3
                );
            }
        }


        /*
         * MPEG audio frame sync.
         *
         * This is deliberately treated as a
         * secondary detection because random
         * binary data can produce similar bytes.
         */

        if (bytes.length >= 2) {

            const first =
                bytes[0];

            const second =
                bytes[1];


            const frameSync =
                first === 0xFF &&
                (second & 0xE0) === 0xE0;


            if (frameSync) {

                return this.sliceBytes(
   
