"use strict";

const FileGuardController = {

    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.initialized = true;

        this.bindEvents();

        if (
            !window.FileGuardWorkspace &&
            window.FileGuardWorkspaceUI
        ) {
            window.FileGuardWorkspace =
                window.FileGuardWorkspaceUI;
        }

        if (
            window.FileGuardUpload &&
            typeof window.FileGuardUpload.init ===
                "function"
        ) {
            window.FileGuardUpload.init();
        }

        if (
            window.FileGuardUploadUI &&
            typeof window.FileGuardUploadUI.init ===
                "function"
        ) {
            window.FileGuardUploadUI.init();
        }

        if (
            window.FileGuardAnalysisUI &&
            typeof window.FileGuardAnalysisUI.init ===
                "function"
        ) {
            window.FileGuardAnalysisUI.init();
        }

        if (
            window.FileGuardWorkspace &&
            typeof window.FileGuardWorkspace.init ===
                "function"
        ) {
            window.FileGuardWorkspace.init();
        }

        if (
            window.FileGuardRouter &&
            typeof window.FileGuardRouter.init ===
                "function"
        ) {
            window.FileGuardRouter.init();
        }
    },

    bindEvents() {
        document.addEventListener(
            "fileguard:file-selected",
            (event) => {
                this.handleFileSelected(event);
            }
        );

        document.addEventListener(
            "fileguard:workspace-tab-selected",
            (event) => {
                this.handleWorkspaceTabSelected(event);
            }
        );
    },

    async handleFileSelected(event) {
        const file =
            event && event.detail
                ? event.detail.file
                : null;

        if (!(file instanceof File)) {
            this.handleError(
                new Error(
                    "FileGuard received an invalid file."
                )
            );

            return;
        }

        const state =
            window.FileGuardAppState;

        if (!state) {
            this.handleError(
                new Error(
                    "FileGuard application state is unavailable."
                )
            );

            return;
        }

        if (state.analysisRunning) {
            return;
        }

        state.resetForAnalysis(file);

        this.navigateToAnalysis();

        this.showAnalysis(file);

        try {
            if (
                !window.FileGuardAnalyzer ||
                typeof window.FileGuardAnalyzer.analyze !==
                    "function"
            ) {
                throw new Error(
                    "FileGuard analysis engine is unavailable."
                );
            }

            const result =
                await window.FileGuardAnalyzer.analyze(
                    file,
                    (progress) => {
                        this.handleProgress(
                            progress
                        );
                    }
                );

            state.setResult(result);

            this.showAnalysisComplete(
                file,
                result
            );

            this.navigateToResults();

            this.showResult(result);

            if (
                window.FileGuardUploadUI &&
                typeof window.FileGuardUploadUI.setComplete ===
                    "function"
            ) {
                window.FileGuardUploadUI.setComplete(
                    file
                );
            }

        } catch (error) {

            state.setError(error);

            if (
                window.FileGuardUploadUI &&
                typeof window.FileGuardUploadUI.setError ===
                    "function"
            ) {
                window.FileGuardUploadUI.setError(
                    "ANALYSIS ERROR"
                );
            }

            this.handleError(error);
        }
    },

    handleProgress(progress) {
        if (
            window.FileGuardAnalysisUI &&
            typeof window.FileGuardAnalysisUI.updateProgress ===
                "function"
        ) {
            window.FileGuardAnalysisUI.updateProgress(
                progress
            );
        }
    },

    handleWorkspaceTabSelected(event) {
        const detail =
            event && event.detail
                ? event.detail
                : null;

        const panel =
            detail &&
            typeof detail.panel === "string"
                ? detail.panel
                : null;

        if (!panel) {
            return;
        }

        const state =
            window.FileGuardAppState;

        if (state) {
            state.setActivePanel(
                panel
            );
        }

        if (
            window.FileGuardWorkspace &&
            typeof window.FileGuardWorkspace.showPanel ===
                "function"
        ) {
            window.FileGuardWorkspace.showPanel(
                panel
            );
        }
    },

    navigateToAnalysis() {
        if (
            window.FileGuardRouter &&
            typeof window.FileGuardRouter.navigate ===
                "function"
        ) {
            window.FileGuardRouter.navigate(
                "analysis"
            );
        }
    },

    navigateToResults() {
        if (
            window.FileGuardRouter &&
            typeof window.FileGuardRouter.navigate ===
                "function"
        ) {
            window.FileGuardRouter.navigate(
                "results"
            );
        }
    },

    navigateToError() {
        if (
            window.FileGuardRouter &&
            typeof window.FileGuardRouter.navigate ===
                "function"
        ) {
            window.FileGuardRouter.navigate(
                "error"
            );
        }
    },

    navigateToHome() {
        if (
            window.FileGuardRouter &&
            typeof window.FileGuardRouter.navigate ===
                "function"
        ) {
            window.FileGuardRouter.navigate(
                "home"
            );
        }
    },

    showAnalysis(file) {
        if (
            window.FileGuardAnalysisUI &&
            typeof window.FileGuardAnalysisUI.start ===
                "function"
        ) {
            window.FileGuardAnalysisUI.start(
                file
            );
        }
    },

    showAnalysisComplete(
        file,
        result
    ) {
        if (
            window.FileGuardAnalysisUI &&
            typeof window.FileGuardAnalysisUI.complete ===
                "function"
        ) {
            window.FileGuardAnalysisUI.complete(
                file,
                result
            );
        }
    },

    showResult(result) {
        if (
            window.FileGuardResultUI &&
            typeof window.FileGuardResultUI.render ===
                "function"
        ) {
            window.FileGuardResultUI.render(
                result
            );
        }

        if (
            window.FileGuardWorkspace &&
            typeof window.FileGuardWorkspace.render ===
                "function"
        ) {
            window.FileGuardWorkspace.render(
                result
            );
        }
    },

    handleError(error) {
        console.error(
            "FileGuardController error:",
            error
        );

        const state =
            window.FileGuardAppState;

        if (
            state &&
            state.error !== error
        ) {
            state.setError(
                error
            );
        }

        if (
            window.FileGuardErrors &&
            typeof window.FileGuardErrors.show ===
                "function"
        ) {
            window.FileGuardErrors.show(
                error
            );

            return;
        }

        if (
            window.FileGuardErrorsUI &&
            typeof window.FileGuardErrorsUI.show ===
                "function"
        ) {
            window.FileGuardErrorsUI.show(
                error
            );

            return;
        }

        this.navigateToError();
    }

};

window.FileGuardController =
    FileGuardController;
