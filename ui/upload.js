"use strict";

/*
 * FILEGUARD
 * Generic Analyzer
 *
 * V1.0
 *
 * Performs general-purpose analysis for files
 * that do not have a specialized analyzer yet.
 */


const FileGuardGenericAnalyzer = {

    async analyze(file) {

        if (!(file instanceof File)) {
            throw new TypeError(
                "Generic analyzer requires a File object."
            );
        }


        const result = {
            analyzer: "generic",

            identity: {
                name: file.name,
                extension: this.getExtension(file.name),
                mimeType: file.type || "unknown",
                size: file.size,
                lastModified: file.lastModified || null
            },

            structure: {
                available: true,
                status: "pending"
            },

            metadata: {
                available: false,
                status: "pending"
            },

            findings: []
        };


        return result;
    },


    getExtension(fileName) {

        if (
            typeof fileName !== "string" ||
            fileName.length === 0
        ) {
            return "";
        }


        const lastDot =
            fileName.lastIndexOf(".");


        if (
            lastDot <= 0 ||
            lastDot === fileName.length - 1
        ) {
            return "";
        }


        return fileName
            .slice(lastDot + 1)
            .toLowerCase();
    }
};


window.FileGuardGenericAnalyzer =
    FileGuardGenericAnalyzer;
