"use strict";

const FileGuardUploadUI = {

    elements: {
        input: null,
        button: null,
        dropZone: null,
        localStatus: null,
        localStatusText: null
    },

    initialized: false,

    state: "ready",

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.input =
            document.getElementById(
                "file-input"
            );

        this.elements.button =
            document.getElementById(
                "select-file-button"
            );

        this.elements.dropZone =
            document.getElementById(
                "drop-zone"
            );

        this.elements.localStatus =
            document.querySelector(
                ".local-status"
            );

        this.elements.localStatusText =
            this.elements.localStatus
                ? this.elements.localStatus.querySelector(
                    "span:last-child"
                )
                : null;

        if (!this.elements.input) {
            console.error(
                "FileGuardUploadUI: file input not found."
            );

            return;
        }

        if (!this.elements.button) {
            console.error(
                "FileGuardUploadUI: select button not found."
            );

            return;
        }

        if (!this.elements.dropZone) {
            console.error(
                "FileGuardUploadUI: drop zone not found."
            );

            return;
        }

        this.bindEvents();

        this.initialized = true;

        this.setReady();

        console.log(
            "FileGuardUploadUI: initialized."
        );
    },

    bindEvents() {

        this.elements.input.addEventListener(
            "change",
            (event) => {

                const files =
                    event.target.files;

                if (
                    !files ||
                    files.length === 0
                ) {
                    return;
                }

                this.handleFile(
                    files[0]
                );

            }
        );

        this.elements.button.addEventListener(
            "click",
            () => {

                if (
                    this.state === "analyzing"
                ) {
                    return;
                }

                this.elements.input.click();

            }
        );

        this.elements.dropZone.addEventListener(
            "click",
            (event) => {

                if (
                    event.target.closest(
                        "#select-file-button"
                    )
                ) {
                    return;
                }

                if (
                    this.state === "analyzing"
                ) {
                    return;
                }

                this.elements.input.click();

            }
        );

        this.elements.dropZone.addEventListener(
            "keydown",
            (event) => {

                if (
                    event.key !== "Enter" &&
                    event.key !== " "
                ) {
                    return;
                }

                event.preventDefault();

                if (
                    this.state === "analyzing"
                ) {
                    return;
                }

                this.elements.input.click();

            }
        );

        this.elements.dropZone.addEventListener(
            "dragover",
            (event) => {

                event.preventDefault();

                if (
                    this.state === "analyzing"
                ) {
                    return;
                }

                this.elements.dropZone.classList.add(
                    "drag-over"
                );

            }
        );

        this.elements.dropZone.addEventListener(
            "dragleave",
            () => {

                this.elements.dropZone.classList.remove(
                    "drag-over"
                );

            }
        );

        this.elements.dropZone.addEventListener(
            "drop",
            (event) => {

                event.preventDefault();

                this.elements.dropZone.classList.remove(
                    "drag-over"
                );

                if (
                    this.state === "analyzing"
                ) {
                    return;
                }

                const files =
                    event.dataTransfer &&
                    event.dataTransfer.files;

                if (
                    !files ||
                    files.length === 0
                ) {
                    return;
                }

                this.handleFile(
                    files[0]
                );

            }
        );
    },

    handleFile(file) {

        if (!(file instanceof File)) {
            console.error(
                "FileGuardUploadUI: invalid File object."
            );

            this.setError(
                "INVALID FILE"
            );

            return;
        }

        console.log(
            "FileGuardUploadUI: selected file:",
            file.name
        );

        this.setAnalyzing(
            file
        );

        document.dispatchEvent(
            new CustomEvent(
                "fileguard:file-selected",
                {
                    detail: {
                        file
                    }
                }
            )
        );

        /*
         * Clear the native input after dispatching.
         * The File object is already passed to the application,
         * so this allows selecting the exact same file again later.
         */
        if (this.elements.input) {
            this.elements.input.value =
                "";
        }
    },

    setAnalyzing(file) {

        this.state =
            "analyzing";

        if (this.elements.dropZone) {
            this.elements.dropZone.classList.add(
                "is-analyzing"
            );

            this.elements.dropZone.setAttribute(
                "aria-disabled",
                "true"
            );
        }

        if (this.elements.button) {
            this.elements.button.classList.add(
                "is-disabled"
            );

            this.elements.button.setAttribute(
                "aria-disabled",
                "true"
            );
        }

        if (this.elements.localStatus) {
            this.elements.localStatus.classList.add(
                "is-analyzing"
            );

            this.elements.localStatus.classList.remove(
                "is-complete",
                "is-error"
            );
        }

        if (this.elements.localStatusText) {
            this.elements.localStatusText.textContent =
                file && file.name
                    ? `ANALYZING — ${file.name}`
                    : "ANALYZING FILE";
        }
    },

    setReady() {

        this.state =
            "ready";

        if (this.elements.dropZone) {
            this.elements.dropZone.classList.remove(
                "is-analyzing"
            );

            this.elements.dropZone.removeAttribute(
                "aria-disabled"
            );
        }

        if (this.elements.button) {
            this.elements.button.classList.remove(
                "is-disabled"
            );

            this.elements.button.removeAttribute(
                "aria-disabled"
            );
        }

        if (this.elements.localStatus) {
            this.elements.localStatus.classList.remove(
                "is-analyzing",
                "is-complete",
                "is-error"
            );
        }

        if (this.elements.localStatusText) {
            this.elements.localStatusText.textContent =
                "LOCAL ENGINE — READY";
        }
    },

    setComplete(file) {

        this.state =
            "complete";

        if (this.elements.dropZone) {
            this.elements.dropZone.classList.remove(
                "is-analyzing"
            );

            this.elements.dropZone.removeAttribute(
                "aria-disabled"
            );
        }

        if (this.elements.button) {
            this.elements.button.classList.remove(
                "is-disabled"
            );

            this.elements.button.removeAttribute(
                "aria-disabled"
            );
        }

        if (this.elements.localStatus) {
            this.elements.localStatus.classList.remove(
                "is-analyzing",
                "is-error"
            );

            this.elements.localStatus.classList.add(
                "is-complete"
            );
        }

        if (this.elements.localStatusText) {
            this.elements.localStatusText.textContent =
                file && file.name
                    ? `ANALYSIS COMPLETE — ${file.name}`
                    : "LOCAL ENGINE — COMPLETE";
        }
    },

    setError(message) {

        this.state =
            "error";

        if (this.elements.dropZone) {
            this.elements.dropZone.classList.remove(
                "is-analyzing"
            );

            this.elements.dropZone.removeAttribute(
                "aria-disabled"
            );
        }

        if (this.elements.button) {
            this.elements.button.classList.remove(
                "is-disabled"
            );

            this.elements.button.removeAttribute(
                "aria-disabled"
            );
        }

        if (this.elements.localStatus) {
            this.elements.localStatus.classList.remove(
                "is-analyzing",
                "is-complete"
            );

            this.elements.localStatus.classList.add(
                "is-error"
            );
        }

        if (this.elements.localStatusText) {
            this.elements.localStatusText.textContent =
                message
                    ? `LOCAL ENGINE — ${message}`
                    : "LOCAL ENGINE — ERROR";
        }
    }

};

window.FileGuardUploadUI =
    FileGuardUploadUI;
