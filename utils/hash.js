"use strict";

const FileGuardHash = {
    VERSION: "2.0.0",

    async calculateAll(file, options = {}) {
        this.validateFile(file);

        const context = options.context || null;

        this.checkpoint(context, "hash-read");

        const buffer = await this.readFileBuffer(
            file,
            context
        );

        this.checkpoint(context, "hash-digest");

        const sha256 = await this.calculateDigest(
            buffer,
            "SHA-256",
            context
        );

        const sha384 = await this.calculateDigest(
            buffer,
            "SHA-384",
            context
        );

        const sha512 = await this.calculateDigest(
            buffer,
            "SHA-512",
            context
        );

        this.checkpoint(context, "hash-complete");

        return {
            sha256,
            sha384,
            sha512
        };
    },

    async calculateDigest(
        buffer,
        algorithm,
        context = null
    ) {
        if (!buffer) {
            throw new Error(
                "Hash calculation requires file data."
            );
        }

        this.checkpoint(context, `digest-${algorithm}`);

        const digest =
            await crypto.subtle.digest(
                algorithm,
                buffer
            );

        this.checkpoint(
            context,
            `digest-${algorithm}-complete`
        );

        return this.bufferToHex(digest);
    },

    async readFileBuffer(file, context = null) {
        this.validateFile(file);

        this.checkpoint(context, "file-read");

        const limit =
            context &&
            typeof context.getLimit === "function"
                ? context.getLimit(
                    "MAX_FILE_SIZE_BYTES"
                )
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

        this.checkpoint(
            context,
            "file-read-complete"
        );

        return buffer;
    },

    bufferToHex(buffer) {
        const bytes =
            new Uint8Array(buffer);

        let result = "";

        for (const byte of bytes) {
            result += byte
                .toString(16)
                .padStart(2, "0");
        }

        return result;
    },

    checkpoint(context, label) {
        if (
            context &&
            typeof context.checkpoint === "function"
        ) {
            context.checkpoint(label);
        }
    },

    createLimitError(size, limit) {
        const error = new Error(
            "File exceeds the configured hash analysis limit."
        );

        error.name = "ResourceLimitError";
        error.code = "FILE_TOO_LARGE";
        error.resourceDetails = {
            resource: "MAX_FILE_SIZE_BYTES",
            value: size,
            limit
        };

        return error;
    },

    validateFile(file) {
        if (
            typeof File === "undefined" ||
            !(file instanceof File)
        ) {
            throw new TypeError(
                "Expected a File object."
            );
        }
    }
};

window.FileGuardHash =
    FileGuardHash;
