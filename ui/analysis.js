"use strict";

const FileGuardAnalysisUI = {

    elements: {

        section: null,

        fileName: null,

        steps: null,

        status: null,

        statusText: null,

        spinner: null

    },


    initialized: false,


    spinnerTimer: null,

    spinnerIndex: 0,


    spinnerFrames: [
        "◐",
        "◓",
        "◑",
        "◒"
    ],


    init() {

        if (this.initialized) {
            return;
        }


        this.elements.section =
            document.getElementById(
                "analysis-section"
            );


        this.elements.fileName =
            document.getElementById(
                "analysis-file"
            );


        this.elements.steps =
            document.getElementById(
                "analysis-steps"
            );


        this.createStatusElement();


        this.initialized = true;

    },


    createStatusElement() {

        if (!this.elements.section) {
            return;
        }


        const header =
            this.elements.section.querySelector(
                ".section-header"
            );


        if (!header) {
            return;
        }


        let status =
            header.querySelector(
                ".analysis-live-status"
            );


        if (!status) {

            status =
                document.createElement(
                    "div"
                );

            status.className =
                "analysis-live-status";


            status.innerHTML = `
                <span
                    class="analysis-spinner"
                    aria-hidden="true"
                >◐</span>

                <span
                    class="analysis-live-text"
                >
                    WAITING
                </span>
            `;


            header.insertBefore(
                status,
                header.querySelector(
                    ".analysis-file-name"
                )
            );

        }


        this.elements.status =
            status;


        this.elements.statusText =
            status.querySelector(
                ".analysis-live-text"
            );


        this.elements.spinner =
            status.querySelector(
                ".analysis-spinner"
            );

    },


    show(file) {

        this.init();


        if (!this.elements.section) {
            return;
        }


        this.stopSpinner();


        this.resetSteps();


        if (this.elements.fileName) {

            this.elements.fileName.textContent =
                file?.name ||
                "UNKNOWN FILE";

        }


        this.elements.section.hidden =
            false;


        const resultSection =
            document.getElementById(
                "result-section"
            );


        if (resultSection) {

            resultSection.hidden =
                true;

        }


        const errorSection =
            document.getElementById(
                "error-section"
            );


        if (errorSection) {

            errorSection.hidden =
                true;

        }


        this.setLoadingState();


        /*
         * Force the browser to paint the
         * loading state before heavy analysis.
         */

        requestAnimationFrame(
            () => {

                requestAnimationFrame(
                    () => {

                        this.startSpinner();

                    }
                );

            }
        );

    },


    update(progress) {

        this.init();


        if (
            !progress ||
            typeof progress !== "object"
        ) {
            return;
        }


        const step =
            typeof progress.step === "string"
                ? progress.step
                : null;


        const status =
            typeof progress.status === "string"
                ? progress.status
                : null;


        if (step) {

            this.updateStep(
                step,
                status
            );

        }


        if (
            status === "running"
        ) {

            this.setLoadingState(
                step
            );

        }


        if (
            status === "completed" &&
            step === "complete"
        ) {

            this.setCompleteState();

        }

    },


    updateStep(
        stepName,
        status
    ) {

        if (!this.elements.steps) {
            return;
        }


        const step =
            this.elements.steps.querySelector(
                `[data-step="${stepName}"]`
            );


        if (!step) {

            console.warn(
                "FileGuardAnalysisUI: unknown analysis step:",
                stepName
            );

            return;
        }


        const statusElement =
            step.querySelector(
                ".step-status"
            );


        if (
            statusElement &&
            status
        ) {

            statusElement.textContent =
                this.formatStatus(
                    status
                );

        }


        step.classList.remove(
            "active",
            "complete",
            "error"
        );


        if (
            status === "complete" ||
            status === "completed" ||
            status === "done"
        ) {

            step.classList.add(
                "complete"
            );

            return;
        }


        if (
            status === "error" ||
            status === "failed"
        ) {

            step.classList.add(
                "error"
            );

            return;
        }


        step.classList.add(
            "active"
        );

    },


    setLoadingState(stepName) {

        this.init();


        if (
            this.elements.status
        ) {

            this.elements.status.classList.remove(
                "is-complete",
                "is-error"
            );

            this.elements.status.classList.add(
                "is-loading"
            );

        }


        if (
            this.elements.statusText
        ) {

            const stepLabel =
                stepName
                    ? this.formatStatus(
                        stepName
                    )
                    : "ANALYZING";


            this.elements.statusText.textContent =
                stepLabel;

        }


        this.startSpinner();

    },


    setCompleteState() {

        this.stopSpinner();


        if (
            this.elements.status
        ) {

            this.elements.status.classList.remove(
                "is-loading",
                "is-error"
            );

            this.elements.status.classList.add(
                "is-complete"
            );

        }


        if (
            this.elements.statusText
        ) {

            this.elements.statusText.textContent =
                "COMPLETE";

        }


        if (
            this.elements.spinner
        ) {

            this.elements.spinner.textContent =
                "✓";

        }

    },


    showError(error) {

        this.stopSpinner();


        if (
            this.elements.status
        ) {

            this.elements.status.classList.remove(
                "is-loading",
                "is-complete"
            );

            this.elements.status.classList.add(
                "is-error"
            );

        }


        if (
            this.elements.statusText
        ) {

            this.elements.statusText.textContent =
                "ERROR";

        }


        if (
            this.elements.spinner
        ) {

            this.elements.spinner.textContent =
                "!";

        }

    },


    startSpinner() {

        if (this.spinnerTimer) {
            return;
        }


        this.spinnerIndex = 0;


        if (
            this.elements.spinner
        ) {

            this.elements.spinner.textContent =
                this.spinnerFrames[
                    this.spinnerIndex
                ];

        }


        this.spinnerTimer =
            window.setInterval(
                () => {

                    this.spinnerIndex =
                        (
                            this.spinnerIndex +
                            1
                        ) %
                        this.spinnerFrames.length;


                    if (
                        this.elements.spinner
                    ) {

                        this.elements.spinner.textContent =
                            this.spinnerFrames[
                                this.spinnerIndex
                            ];

                    }

                },
                140
            );

    },


    stopSpinner() {

        if (
            this.spinnerTimer
        ) {

            window.clearInterval(
                this.spinnerTimer
            );

            this.spinnerTimer =
                null;

        }

    },


    resetSteps() {

        if (!this.elements.steps) {
            return;
        }


        const steps =
            this.elements.steps.querySelectorAll(
                ".analysis-step"
            );


        steps.forEach(
            (step) => {

                step.classList.remove(
                    "active",
                    "complete",
                    "error"
                );


                const statusElement =
                    step.querySelector(
                        ".step-status"
                    );


                if (statusElement) {

                    statusElement.textContent =
                        "WAITING";

                }

            }
        );

    },


    formatStatus(status) {

        if (
            typeof status !== "string"
        ) {

            return "WAITING";

        }


        return status
            .replace(
                /[-_]+/g,
                " "
            )
            .toUpperCase();

    },


    hide() {

        this.init();


        this.stopSpinner();


        if (
            this.elements.section
        ) {

            this.elements.section.hidden =
                true;

        }

    }

};


window.FileGuardAnalysisUI =
    FileGuardAnalysisUI;
