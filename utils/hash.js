"use strict";

/*
 * FILEGUARD
 * Hash Utility
 *
 * V1.0
 *
 * Calculates cryptographic hashes locally
 * using the browser Web Crypto API.
 *
 * Supported:
 * - SHA-256
 * - SHA-384
 * - SHA-512
 */


const FileGuardHash = {

    /*
     * ─────────────────────────────
     * PUBLIC API
     * ─────────────────────────────
     */

    async calculateAll(file) {

        this.validateFile(file);

        const buffer =
            await this.readFileBuffer(file);


        const [
            sha256,
            sha384,
            sha512
        ] = await Promise.all([

            this.calculateDigest(
                buffer,
                "SHA-256"
            ),

            this.calculateDigest(
                buffer,
                "SHA-384"
            ),

            this.calculateDigest(
                buffer,
                "SHA-512"
            )

        ]);


        return {
            sha256,
            sha384,
            sha512
        };
    },


    /*
     * ─────────────────────────────
     * SINGLE DIGEST
     * ─────────────────────────────
     */

    async calculateDigest(buffer, algorithm) {

        if (!buffer) {
            throw new Error(
                "Hash calculation requires file data."
            );
        }


        const digest =
            await crypto.subtle.digest(
                algorithm,
                buffer
            );


        return this.bufferToHex(digest);
    },


    /*
     * ─────────────────────────────
     * FILE READING
     * ─────────────────────────────
     */

    async readFileBuffer(file) {

        this.validateFile(file);

        return await file.arrayBuffer();
    },


    /*
     * ─────────────────────────────
     * BUFFER → HEX
     * ─────────────────────────────
     */

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


    /*
     * ─────────────────────────────
     * VALIDATION
     * ─────────────────────────────
     */

    validateFile(file) {

        if (!(file instanceof File)) {

            throw new TypeError(
                "Expected a File object."
            );
        }
    }
};


/*
 * Expose utility globally for the
 * current browser-based architecture.
 */

window.FileGuardHash = FileGuardHash;
