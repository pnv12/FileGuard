"use strict";

/*
 * FILEGUARD
 * Resource Guard
 *
 * V1.0.0
 *
 * Central resource-safety layer for local file analysis.
 *
 * Responsibilities:
 * - global file-size limit;
 * - analysis timeout;
 * - AbortController / cancellation;
 * - cooperative checkpoints;
 * - per-operation limits;
 * - ZIP/archive safety budgets;
 * - text scanning limits;
 * - consistent resource-limit errors.
 *
 * IMPORTANT:
 * Resource Guard does not analyze files.
 * It only controls the resources available to analyzers.
 */


const FileGuardResourceGuard = {

    VERSION: "1.0.0",

    LIMITS: {

        /*
         * Maximum input file size.
         *
         * 100 MiB is intentionally used instead
         * of an arbitrary decimal MB value.
         */
        MAX_FILE_SIZE_BYTES:
            100 * 1024 * 1024,

        /*
         * Maximum total analysis time.
         */
        MAX_ANALYSIS_TIME_MS:
            45 * 1000,

        /*
         * Maximum number of ZIP/archive entries.
         */
        MAX_ARCHIVE_ENTRIES:
            100000,

        /*
         * Maximum declared uncompressed archive size
         * that the analysis engine is allowed to process.
         */
        MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            500 * 1024 * 1024,

        /*
         * Maximum amount of data allowed for
         * textual indicator scanning.
         */
        MAX_TEXT_SCAN_BYTES:
            8 * 1024 * 1024,

        /*
         * Maximum number of textual indicators
         * retained by a single analyzer.
         */
        MAX_TEXT_INDICATORS:
            500,

        /*
         * Maximum number of generic findings
         * retained by the core pipeline.
         */
        MAX_FINDINGS:
            1000,

        /*
         * Maximum number of evidence records
         * retained by the core pipeline.
         */
        MAX_EVIDENCE:
            2000
    },


    /*
     * ─────────────────────────────────────────
     * CONTEXT CREATION
     * ─────────────────────────────────────────
     */

    createContext(file, options = {}) {

        this.validateFile(file);

        const limits =
            this.mergeLimits(
                this.LIMITS,
                options.limits || {}
            );

        this.validateFileSize(
            file,
            limits
        );

        const controller =
            new AbortController();

        const startedAt =
            performance.now();

        const timeoutMs =
            this.normalizePositiveInteger(
                options.timeoutMs,
                limits.MAX_ANALYSIS_TIME_MS
            );

        const deadline =
            startedAt + timeoutMs;

        let timeoutId =
            null;

        let aborted =
            false;

        let abortReason =
            null;


        const abort =
            (reason = "Analysis cancelled.") => {

                if (aborted) {
                    return;
                }

                aborted = true;
                abortReason = reason;

                try {
                    controller.abort(
                        reason
                    );
                } catch (error) {

                    /*
                     * Older browser implementations
                     * may not support AbortController.abort(reason).
                     */
                    try {
                        controller.abort();
                    } catch (ignored) {
                        /*
                         * Nothing else is required here.
                         */
                    }
                }
            };


        timeoutId =
            window.setTimeout(
                () => {

                    abort(
                        "Analysis time limit exceeded."
                    );

                },
                timeoutMs
            );


        const cleanup =
            () => {

                if (
                    timeoutId !== null
                ) {

                    window.clearTimeout(
                        timeoutId
                    );

                    timeoutId = null;
                }
            };


        const context = {

            version:
                this.VERSION,

            signal:
                controller.signal,

            controller,

            startedAt,

            deadline,

            timeoutMs,

            limits,

            file: {

                name:
                    file.name || "",

                size:
                    file.size,

                type:
                    file.type || "unknown"
            },


            abort,


            cleanup,


            isAborted:
                () => {

                    return (
                        aborted ||
                        controller.signal.aborted
                    );
                },


            getAbortReason:
                () => {

                    if (
                        abortReason
                    ) {
                        return abortReason;
                    }

                    if (
                        controller.signal &&
                        controller.signal.reason
                    ) {
                        return (
                            controller.signal.reason
                        );
                    }

                    return null;
                },


            elapsedMs:
                () => {

                    return Math.max(
                        0,
                        performance.now() -
                            startedAt
                    );
                },


            remainingMs:
                () => {

                    return Math.max(
                        0,
                        deadline -
                            performance.now()
                    );
                },


            checkpoint:
                (label = "analysis") => {

                    if (
                        context.isAborted()
                    ) {

                        throw this.createAbortError(
                            context.getAbortReason(),
                            label
                        );
                    }

                    if (
                        performance.now() >=
                        deadline
                    ) {

                        abort(
                            "Analysis time limit exceeded."
                        );

                        throw this.createAbortError(
                            "Analysis time limit exceeded.",
                            label
                        );
                    }

                    return true;
                },


            assertWithin:
                (
                    resource,
                    value,
                    label = resource
                ) => {

                    const limit =
                        context.getLimit(
                            resource
                        );

                    if (
                        limit === null
                    ) {
                        return true;
                    }

                    if (
                        !Number.isFinite(
                            value
                        )
                    ) {

                        throw this.createResourceError(
                            "INVALID_RESOURCE_VALUE",
                            `${label} value is invalid.`
                        );
                    }

                    if (
                        value > limit
                    ) {

                        throw this.createResourceError(
                            "RESOURCE_LIMIT_EXCEEDED",
                            `${label} exceeds the configured resource limit.`,
                            {
                                resource,
                                value,
                                limit
                            }
                        );
                    }

                    return true;
                },


            getLimit:
                (name) => {

                    if (
                        !name ||
                        typeof name !==
                            "string"
                    ) {
                        return null;
                    }

                    return Object.prototype.hasOwnProperty.call(
                        limits,
                        name
                    )
                        ? limits[name]
                        : null;
                },


            run:
                async (
                    label,
                    operation
                ) => {

                    context.checkpoint(
                        label
                    );

                    if (
                        typeof operation !==
                            "function"
                    ) {

                        throw new TypeError(
                            `Resource Guard operation "${label}" must be a function.`
                        );
                    }

                    const remaining =
                        context.remainingMs();

                    if (
                        remaining <= 0
                    ) {

                        abort(
                            "Analysis time limit exceeded."
                        );

                        throw this.createAbortError(
                            "Analysis time limit exceeded.",
                            label
                        );
                    }

                    /*
                     * The operation receives the same
                     * analysis context.
                     *
                     * IMPORTANT:
                     * AbortController cannot forcibly
                     * terminate arbitrary JavaScript.
                     * Therefore operations must cooperate
                     * by checking context.signal/checkpoint.
                     */
                    const operationPromise =
                        Promise.resolve().then(
                            () =>
                                operation(
                                    context
                                )
                        );

                    const timeoutPromise =
                        new Promise(
                            (_, reject) => {

                                const timer =
                                    window.setTimeout(
                                        () => {

                                            abort(
                                                `Analysis stage "${label}" exceeded the remaining time budget.`
                                            );

                                            reject(
                                                this.createAbortError(
                                                    context.getAbortReason(),
                                                    label
                                                )
                                            );

                                        },
                                        remaining
                                    );

                                operationPromise
                                    .finally(
                                        () => {
                                            window.clearTimeout(
                                                timer
                                            );
                                        }
                                    )
                                    .catch(
                                        () => {
                                            /*
                                             * The original operation
                                             * promise is handled by
                                             * Promise.race().
                                             */
                                        }
                                    );
                            }
                        );


                    try {

                        return await Promise.race(
                            [
                                operationPromise,
                                timeoutPromise
                            ]
                        );

                    } finally {

                        context.checkpoint(
                            label
                        );
                    }
                }
        };


        return context;
    },


    /*
     * ─────────────────────────────────────────
     * FILE VALIDATION
     * ─────────────────────────────────────────
     */

    validateFile(file) {

        if (
            typeof File ===
            "undefined"
        ) {

            throw new Error(
                "Browser File API is unavailable."
            );
        }

        if (
            !(file instanceof File)
        ) {

            throw new TypeError(
                "Resource Guard requires a File object."
            );
        }

        if (
            !Number.isFinite(
                file.size
            ) ||
            file.size < 0
        ) {

            throw this.createResourceError(
                "INVALID_FILE_SIZE",
                "File size is invalid."
            );
        }
    },


    validateFileSize(
        file,
        limits = this.LIMITS
    ) {

        const maximum =
            limits.MAX_FILE_SIZE_BYTES;


        if (
            !Number.isFinite(
                maximum
            ) ||
            maximum <= 0
        ) {

            throw new Error(
                "MAX_FILE_SIZE_BYTES must be a positive number."
            );
        }


        if (
            file.size >
            maximum
        ) {

            throw this.createResourceError(
                "FILE_TOO_LARGE",
                "The selected file exceeds FileGuard's maximum analysis size.",
                {
                    fileSize:
                        file.size,

                    maxFileSize:
                        maximum
                }
            );
        }


        return true;
    },


    /*
     * ─────────────────────────────────────────
     * LIMIT MANAGEMENT
     * ─────────────────────────────────────────
     */

    mergeLimits(
        base,
        overrides
    ) {

        const result = {
            ...base
        };


        if (
            overrides &&
            typeof overrides ===
                "object"
        ) {

            for (
                const key
                of Object.keys(
                    overrides
                )
            ) {

                const value =
                    overrides[key];


                if (
                    Number.isFinite(
                        value
                    ) &&
                    value > 0
                ) {

                    result[key] =
                        value;
                }
            }
        }


        return result;
    },


    normalizePositiveInteger(
        value,
        fallback
    ) {

        if (
            Number.isFinite(
                value
            ) &&
            value > 0
        ) {

            return Math.floor(
                value
            );
        }


        return Math.floor(
            fallback
        );
    },


    /*
     * ─────────────────────────────────────────
     * ERROR FACTORIES
     * ─────────────────────────────────────────
     */

    createAbortError(
        reason,
        label = "analysis"
    ) {

        const error =
            new Error(
                reason ||
                `Analysis "${label}" was cancelled.`
            );

        error.name =
            "AbortError";

        error.code =
            "ANALYSIS_ABORTED";

        error.stage =
            label;

        return error;
    },


    createResourceError(
        code,
        message,
        details = null
    ) {

        const error =
            new Error(
                message
            );

        error.name =
            "ResourceLimitError";

        error.code =
            code;

        error.resourceDetails =
            details;

        return error;
    }
};


/*
 * Public global export.
 *
 * The current FileGuard architecture uses
 * browser globals intentionally. This module
 * therefore follows the existing architecture
 * instead of introducing ES modules mid-refactor.
 */

window.FileGuardResourceGuard =
    FileGuardResourceGuard;
