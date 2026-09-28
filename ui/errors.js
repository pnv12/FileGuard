"use strict";

const FileGuardErrorsUI = {

    elements: {
        screen: null,
        message: null
    },

    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.screen =
            document.getElementById(
                "screen-error"
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

        if (
            this.elements.screen &&
            window.FileGuardRouter &&
            typeof window.FileGuardRouter.navigate ===
                "function"
        ) {
            window.FileGuardRouter.navigate(
                "error"
            );

            return;
        }

        if (this.elements.screen) {
            this.elements.screen.hidden =
                false;

            this.elements.screen.setAttribute(
                "aria-hidden",
                "false"
            );
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

        if (this.elements.screen) {
            this.elements.screen.hidden =
                true;

            this.elements.screen.setAttribute(
                "aria-hidden",
                "true"
            );
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

window.FileGuardErrors =
    FileGuardErrorsUI;
