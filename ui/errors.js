"use strict";

const FileGuardErrorsUI = {
    elements: {
        section: null,
        message: null
    },

    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.section =
            document.getElementById(
                "error-section"
            );

        this.elements.message =
            document.getElementById(
                "error-message"
            );

        this.initialized = true;
    },

    show(error) {
        this.init();

        const message =
            this.getMessage(error);

        console.error(
            "FileGuard UI error:",
            error
        );

        if (this.elements.message) {
            this.elements.message.textContent =
                message;
        }

        if (this.elements.section) {
            this.elements.section.hidden =
                false;
        }

        const analysisSection =
            document.getElementById(
                "analysis-section"
            );

        if (analysisSection) {
            analysisSection.hidden = true;
        }

        const resultSection =
            document.getElementById(
                "result-section"
            );

        if (resultSection) {
            resultSection.hidden = true;
        }
    },

    getMessage(error) {
        if (
            error instanceof Error &&
            error.message
        ) {
            return error.message;
        }

        if (
            error &&
            typeof error.message === "string" &&
            error.message.length > 0
        ) {
            return error.message;
        }

        if (
            typeof error === "string" &&
            error.length > 0
        ) {
            return error;
        }

        return (
            "An unexpected error occurred during file analysis."
        );
    },

    hide() {
        this.init();

        if (this.elements.section) {
            this.elements.section.hidden =
                true;
        }
    },

    clear() {
        this.init();

        if (this.elements.message) {
            this.elements.message.textContent =
                "";
        }

        this.hide();
    }
};

window.FileGuardErrorsUI =
    FileGuardErrorsUI;
