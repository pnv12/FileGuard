"use strict";

const FileGuardDetector = {
    VERSION: "2.0.0",

    signatures: [
        ["png","PNG","image","image/png",["png"],[89,80,78,71,13,10,26,10]],
        ["jpeg","JPEG","image","image/jpeg",["jpg","jpeg","jpe"],[255,216,255]],
        ["gif","GIF","image","image/gif",["gif"],[71,73,70,56]],
        ["webp","WEBP","image","image/webp",["webp"],null],
        ["pdf","PDF","document","application/pdf",["pdf"],[37,80,68,70,45]],
        ["zip","ZIP","archive","application/zip",["zip"],[80,75,3,4]],
        ["gzip","GZIP","archive","application/gzip",["gz","gzip"],[31,139]],
        ["bz2","BZIP2","archive","application/x-bzip2",["bz2"],[66,90,104]],
        ["rar","RAR","archive","application/vnd.rar",["rar"],[82,97,114,33,26,7]],
        ["7z","7-Zip","archive","application/x-7z-compressed",["7z"],[55,122,188,175,39,28]],
        ["elf","ELF","executable","application/x-elf",["elf","so"],[127,69,76,70]],
        ["pe","PE","executable","application/x-msdownload",["exe","dll","sys","scr"],[77,90]],
        ["wasm","WebAssembly","executable","application/wasm",["wasm"],[0,97,115,109]],
        ["ogg","OGG","audio","audio/ogg",["ogg","oga","ogv"],[79,103,103,83]],
        ["flac","FLAC","audio","audio/flac",["flac"],[102,76,97,67]],
        ["webm","WebM","video","video/webm",["webm"],[26,69,223,163]],
        ["docx","DOCX","document","application/vnd.openxmlformats-officedocument.wordprocessingml.document",["docx"],[80,75,3,4]],
        ["xlsx","XLSX","document","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",["xlsx"],[80,75,3,4]],
        ["pptx","PPTX","document","application/vnd.openxmlformats-officedocument.presentationml.presentation",["pptx"],[80,75,3,4]],
        ["jar","JAR","archive","application/java-archive",["jar"],[80,75,3,4]]
    ],

    async detect(file) {
        if (!(file instanceof File)) {
            throw new TypeError("Invalid File object.");
        }

        const bytes = new Uint8Array(
            await file.slice(0, 512).arrayBuffer()
        );

        const extension = this.extension(file.name);
        const mime = file.type || "unknown";

        let matches = this.signatures
            .filter(x => x[5] && this.match(bytes, x[5]))
            .map(x => this.def(x));

        matches.push(
            ...this.custom(bytes)
        );

        matches = this.unique(matches);

        const primary =
            this.primary(matches, extension, mime);

        const extMatch = primary
            ? primary.extensions.includes(extension)
            : false;

        const mimeMatch = primary
            ? primary.mimeTypes.includes(mime)
            : false;

        const confidence =
            this.confidence(primary, extMatch, mimeMatch);

        const anomalies = [];

        if (!primary) {
            anomalies.push({
                id: "unknown-format",
                severity: "INFO",
                confidence: "MEDIUM",
                title: "Unknown file format",
                description:
                    "No known file signature was detected.",
                evidence: {
                    extension,
                    mimeType: mime
                }
            });
        }

        if (
            primary &&
            extension &&
            !extMatch
        ) {
            anomalies.push({
                id: "extension-mismatch",
                severity: "LOW",
                confidence: "HIGH",
                title: "Extension mismatch",
                description:
                    "The filename extension does not match the detected format.",
                evidence: {
                    extension,
                    detectedFormat: primary.format
                }
            });
        }

        if (
            primary &&
            mime !== "unknown" &&
            !mimeMatch
        ) {
            anomalies.push({
                id: "mime-mismatch",
                severity: "LOW",
                confidence: "MEDIUM",
                title: "MIME type mismatch",
                description:
                    "The browser-provided MIME type differs from the detected format.",
                evidence: {
                    browserMime: mime,
                    detectedFormat: primary.format
                }
            });
        }

        if (matches.length > 1) {
            anomalies.push({
                id: "multiple-signatures",
                severity: "LOW",
                confidence: "MEDIUM",
                title: "Multiple format signatures detected",
                description:
                    "More than one known format matched the file header.",
                evidence: {
                    formats: matches.map(
                        x => x.format
                    )
                }
            });
        }

        return {
            detector: "signature",
            detectorVersion: this.VERSION,

            status: primary
                ? "detected"
                : "unknown",

            format: primary
                ? primary.format
                : "Unknown",

            formatId: primary
                ? primary.id
                : "unknown",

            category: primary
                ? primary.category
                : "unknown",

            confidence,
            confidenceScore: confidence.score,
            confidenceLevel: confidence.level,

            extension,
            browserMime: mime,

            detectedMimeTypes:
                primary
                    ? primary.mimeTypes
                    : [],

            expectedExtensions:
                primary
                    ? primary.extensions
                    : [],

            signatureMatched: !!primary,

            container:
                primary
                    ? primary.containerType || null
                    : null,

            extensionMatches: extMatch,
            mimeMatches: mimeMatch,

            matches: matches.map(x => ({
                id: x.id,
                format: x.format,
                category: x.category,
                containerType:
                    x.containerType || null
            })),

            anomalies,

            evidence: {
                headerBytes:
                    this.hex(
                        bytes.slice(
                            0,
                            Math.min(32, bytes.length)
                        )
                    ),

                signature:
                    primary
                        ? this.hex(
                            primary.matchedSignature
                        )
                        : null
            }
        };
    },

    def(x) {
        return {
            id: x[0],
            format: x[1],
            category: x[2],
            mimeTypes: [x[3]],
            extensions: x[4],
            signature: x[5],
            matchedSignature: x[5]
        };
    },

    custom(bytes) {
        const out = [];

        if (
            this.ascii(bytes,0,4) === "RIFF" &&
            this.ascii(bytes,8,4) === "WEBP"
        ) {
            out.push({
                id: "webp",
                format: "WEBP",
                category: "image",
                mimeTypes: ["image/webp"],
                extensions: ["webp"],
                matchedSignature:
                    Array.from(bytes.slice(0,12))
            });
        }

        if (
            this.ascii(bytes,0,4) === "RIFF" &&
            this.ascii(bytes,8,4) === "WAVE"
        ) {
            out.push({
                id: "wav",
                format: "WAV",
                category: "audio",
                mimeTypes: [
                    "audio/wav",
                    "audio/x-wav"
                ],
                extensions: ["wav"],
                matchedSignature:
                    Array.from(bytes.slice(0,12))
            });
        }

        if (
            this.ascii(bytes,0,4) === "RIFF" &&
            this.ascii(bytes,8,4) === "AVI "
        ) {
            out.push({
                id: "avi",
                format: "AVI",
                category: "video",
                mimeTypes: ["video/x-msvideo"],
                extensions: ["avi"],
                matchedSignature:
                    Array.from(bytes.slice(0,12))
            });
        }

        if (
            this.ascii(bytes,4,4) === "ftyp"
        ) {
            out.push({
                id: "mp4",
                format: "MP4",
                category: "video",
                mimeTypes: ["video/mp4"],
                extensions: ["mp4"],
                matchedSignature:
                    Array.from(bytes.slice(4,12))
            });
        }

        if (
            this.ascii(bytes,0,3) === "ID3" ||
            (
                bytes.length >= 2 &&
                bytes[0] === 255 &&
                (bytes[1] & 224) === 224
            )
        ) {
            out.push({
                id: "mp3",
                format: "MP3",
                category: "audio",
                mimeTypes: ["audio/mpeg"],
                extensions: ["mp3"],
                matchedSignature:
                    Array.from(bytes.slice(0,3))
            });
        }

        return out;
    },

    primary(matches, ext, mime) {
        if (!matches.length) {
            return null;
        }

        return (
            matches.find(
                x => x.extensions.includes(ext)
            ) ||

            matches.find(
                x => x.mimeTypes.includes(mime)
            ) ||

            matches[0]
        );
    },

    confidence(primary, ext, mime) {
        if (!primary) {
            return {
                score: 0,
                level: "LOW"
            };
        }

        let score = 60;

        if (ext) {
            score += 20;
        }

        if (mime) {
            score += 20;
        }

        if (
            primary.extensions.includes(ext)
        ) {
            score += 10;
        }

        if (
            primary.mimeTypes.includes(mime)
        ) {
            score += 10;
        }

        score = Math.min(100, score);

        return {
            score,
            level:
                score >= 90
                    ? "HIGH"
                    : score >= 70
                        ? "MEDIUM"
                        : "LOW"
        };
    },

    match(bytes, sig) {
        if (bytes.length < sig.length) {
            return false;
        }

        for (
            let i = 0;
            i < sig.length;
            i++
        ) {
            if (bytes[i] !== sig[i]) {
                return false;
            }
        }

        return true;
    },

    unique(matches) {
        const map = new Map();

        for (const item of matches) {
            if (!map.has(item.id)) {
                map.set(item.id, item);
            }
        }

        return [...map.values()];
    },

    extension(name) {
        const clean =
            String(name || "")
                .split("/")
                .pop()
                .split("\\")
                .pop();

        const dot =
            clean.lastIndexOf(".");

        return dot > 0
            ? clean
                .slice(dot + 1)
                .toLowerCase()
            : "";
    },

    ascii(bytes, start, length) {
        let out = "";

        for (
            let i = start;
            i < start + length &&
            i < bytes.length;
            i++
        ) {
            out += String.fromCharCode(
                bytes[i]
            );
        }

        return out;
    },

    hex(bytes) {
        return Array.from(bytes)
            .map(
                x =>
                    x
                        .toString(16)
                        .padStart(2, "0")
            )
            .join(" ");
    }
};

window.FileGuardDetector =
    FileGuardDetector;
