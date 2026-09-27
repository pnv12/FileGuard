"use strict";

/*
 * FILEGUARD
 * Upload UI
 *
 * V1.3
 *
 * Handles:
 * - native file picker
 * - file selection
 * - drag and drop
 * - file selection events
 * - upload/loading state
 * - selected file feedback
 */

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

        /*
         * Native file picker.
         */

        this.elements.input.addEventListener(
            "change",
            (event) => {

                const files =
                    event.target.files;


                console.log(
                    "FileGuardUploadUI: file input changed.",
                    files
                );


                if (
                    !files ||
                    files.length === 0
                ) {

                    console.warn(
                        "FileGuardUploadUI: no file selected."
                    );

                    return;
                }


                const file =
                    files[0];


                this.handleFile(
                    file
                );

            }
        );


        /*
         * Drag over.
         */

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


        /*
         * Drag leave.
         */

        this.elements.dropZone.addEventListener(
            "dragleave",
            () => {

                this.elements.dropZone.classList.remove(
                    "drag-over"
                );

            }
        );


        /*
         * Drop.
         */

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


        /*
         * IMPORTANT:
         *
         * controller.js listens on document.
         * Therefore the event must also be
         * dispatched on document.
         */

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

    },


    setAnalyzing(file) {

        this.state = "analyzing";


        if (this.elements.dropZone) {

            this.elements.dropZone.classList.add(
                "is-analyzing"
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

        }


        if (this.elements.localStatusText) {

            this.elements.localStatusText.textContent =
                file && file.name
                    ? `ANALYZING — ${file.name}`
                    : "ANALYZING FILE";

        }

    },


    setReady() {

        this.state = "ready";


        if (this.elements.dropZone) {

            this.elements.dropZone.classList.remove(
                "is-analyzing"
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

        this.state = "complete";


        if (this.elements.dropZone) {

            this.elements.dropZone.classList.remove(
                "is-analyzing"
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

        this.state = "error";


        if (this.elements.dropZone) {

            this.elements.dropZone.classList.remove(
                "is-analyzing"
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
