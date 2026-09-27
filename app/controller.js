"use strict";

const FileGuardController = {

    initialized: false,


    init() {

        if (this.initialized) {
            return;
        }


        this.bindEvents();


        /*
         * Initialize upload system.
         *
         * Without this call the native input
         * has no "change" listener.
         */

        if (
            window.FileGuardUploadUI &&
            typeof window.FileGuardUploadUI.init ===
                "function"
        ) {

            window.FileGuardUploadUI.init();

        } else {

            console.error(
                "FileGuardUploadUI is not available."
            );

        }


        if (window.FileGuardAnalysisUI) {

            window.FileGuardAnalysisUI.init();

        }


        if (window.FileGuardWorkspaceUI) {

            window.FileGuardWorkspaceUI.init();

        }


        this.initialized = true;


        console.log(
            "FileGuardController: initialized."
        );

    },


    bindEvents() {

        /*
         * File selection.
         */

        document.addEventListener(
            "fileguard:file-selected",
            (event) => {

                this.handleFileSelected(
                    event
                );

            }
        );


        /*
         * Workspace navigation.
         */

        document.addEventListener(
            "fileguard:workspace-tab-selected",
            (event) => {

                this.handleWorkspaceTabSelected(
                    event
                );

            }
        );

    },


    async handleFileSelected(event) {

        const file =
            event.detail?.file;


        console.log(
            "FileGuardController: file-selected event received.",
            file
        );


        if (!(file instanceof File)) {

            this.handleError(
                new TypeError(
                    "FileGuard received an invalid file."
                )
            );

            return;
        }


        if (
            FileGuardAppState.analysisRunning
        ) {

            console.warn(
                "FileGuardController: analysis already running."
            );

            return;
        }


        /*
         * Set global application state.
         */

        FileGuardAppState.resetForAnalysis(
            file
        );


        /*
         * Immediately show analysis state.
         */

        this.showAnalysis(
            file
        );


        /*
         * Start actual analysis.
         */

        try {

            console.log(
                "FileGuardController: starting analysis."
            );


            const result =
                await FileGuardAnalyzer.analyze(
                    file,
                    (progress) => {

                        this.handleProgress(
                            progress
                        );

                    }
                );


            /*
             * Analysis succeeded.
             */

            FileGuardAppState.setResult(
                result
            );


            if (
                window.FileGuardUploadUI &&
                typeof window.FileGuardUploadUI.setComplete ===
                    "function"
            ) {

                window.FileGuardUploadUI.setComplete(
                    file
                );

            }


            this.showResult(
                result
            );


            console.log(
                "FileGuardController: analysis completed.",
                result
            );

        } catch (error) {

            /*
             * Analysis failed.
             */

            FileGuardAppState.setError(
                error
            );


            if (
                window.FileGuardUploadUI &&
                typeof window.FileGuardUploadUI.setError ===
                    "function"
            ) {

                window.FileGuardUploadUI.setError(
                    "ERROR"
                );

            }


            this.handleError(
                error
            );

        }

    },


    handleProgress(progress) {

        if (
            !progress ||
            typeof progress !== "object"
        ) {
            return;
        }


        console.log(
            "FileGuard progress:",
            progress
        );


        if (
            window.FileGuardAnalysisUI
        ) {

            window.FileGuardAnalysisUI.update(
                progress
            );

        }

    },


    handleWorkspaceTabSelected(event) {

        const panelName =
            event.detail?.panel;


        if (!panelName) {
            return;
        }


        FileGuardAppState.setActivePanel(
            panelName
        );


        if (
            window.FileGuardWorkspaceUI
        ) {

            window.FileGuardWorkspaceUI.showPanel(
                panelName
            );

        }

    },


    showAnalysis(file) {

        if (
            window.FileGuardAnalysisUI
        ) {

            window.FileGuardAnalysisUI.show(
                file
            );

        }

    },


    showResult(result) {

        if (
            window.FileGuardResultUI
        ) {

            window.FileGuardResultUI.render(
                result
            );

        }


        if (
            window.FileGuardWorkspaceUI
        ) {

            window.FileGuardWorkspaceUI.render(
                result
            );

        }

    },


    handleError(error) {

        console.error(
            "FileGuard analysis error:",
            error
        );


        if (
            window.FileGuardAnalysisUI
        ) {

            window.FileGuardAnalysisUI.showError(
                error
            );

        }


        if (
            window.FileGuardErrorsUI
        ) {

            window.FileGuardErrorsUI.show(
                error
            );

        }

    }

};


window.FileGuardController =
    FileGuardController;
