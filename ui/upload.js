"use strict";

/*
 * FILEGUARD
 * Upload UI
 *
 * V1.2
 *
 * Handles:
 * - native file picker
 * - file selection
 * - drag and drop
 * - file selection events
 */


const FileGuardUploadUI = {

    elements: {
        input: null,
        button: null,
        dropZone: null
    },


    initialized: false,


    init() {

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


        if (this.initialized) {
            return;
        }


        this.bindEvents();

        this.initialized = true;


        console.log(
            "FileGuardUploadUI: initialized."
        );
    },


    bindEvents() {

        /*
         * Native file picker.
         *
         * The label in index.html is connected to
         * this input through:
         *
         * for="file-input"
         *
         * We do NOT trigger input.click() here.
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


                this.emitFile(file);

            }
        );


        /*
         * Drag over.
         */

        this.elements.dropZone.addEventListener(
            "dragover",
            (event) => {

                event.preventDefault();

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


                const files =
                    event.dataTransfer &&
                    event.dataTransfer.files;


                if (
                    !files ||
                    files.length === 0
                ) {

                    return;
                }


                this.emitFile(
                    files[0]
                );

            }
        );

    },


    emitFile(file) {

        if (!(file instanceof File)) {

            console.error(
                "FileGuardUploadUI: invalid File object."
            );

            return;
        }


        console.log(
            "FileGuardUploadUI: selected file:",
            file.name
        );


        window.dispatchEvent(
            new CustomEvent(
                "fileguard:file-selected",
                {
                    detail: {
                        file
                    }
                }
            )
        );

    }

};


window.FileGuardUploadUI =
    FileGuardUploadUI;
