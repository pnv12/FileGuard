"use strict";

const FileGuardController = {
    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.initialized = true;

        this.bindEvents();

        if (window.FileGuardWorkspaceUI) {
            window.FileGuardWorkspaceUI.init();
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
        const file = event.detail?.file;

        if (!(file instanceof File)) {
            this.handleError(
                new TypeError("FileGuard received an invalid file.")
            );
            return;
        }

        if (FileGuardAppState.analysisRunning) {
            return;
        }

        FileGuardAppState.resetForAnalysis(file);

        this.showAnalysis(file);

        try {
            const result = await FileGuardAnalyzer.analyze(
                file,
                (progress) => {
                    this.handleProgress(progress);
                }
            );

            FileGuardAppState.setResult(result);

            this.showResult(result);
        } catch (error) {
            FileGuardAppState.setError(error);

            this.handleError(error);
        }
    },

    handleProgress(progress) {
        if (window.FileGuardAnalysisUI) {
            window.FileGuardAnalysisUI.update(progress);
        }
    },

    handleWorkspaceTabSelected(event) {
        const panelName = event.detail?.panel;

        if (!panelName) {
            return;
        }

        FileGuardAppState.setActivePanel(panelName);

        if (window.FileGuardWorkspaceUI) {
            window.FileGuardWorkspaceUI.showPanel(panelName);
        }
    },

    showAnalysis(file) {
        if (window.FileGuardAnalysisUI) {
            window.FileGuardAnalysisUI.show(file);
        }
    },

    showResult(result) {
        if (window.FileGuardResultUI) {
            window.FileGuardResultUI.render(result);
        }

        if (window.FileGuardWorkspaceUI) {
            window.FileGuardWorkspaceUI.render(result);
        }
    },

    handleError(error) {
        console.error("FileGuard analysis error:", error);

        if (window.FileGuardErrorsUI) {
            window.FileGuardErrorsUI.show(error);
        }
    }
};

window.FileGuardController = FileGuardController;
