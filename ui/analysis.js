"use strict";

const FileGuardAnalysisUI = {

    initialized: false,

    elements: {
        screen: null,
        fileName: null,
        steps: null,
        status: null,
        statusText: null,
        spinner: null,
        progressBar: null,
        progressValue: null
    },

    spinnerTimer: null,

    spinnerIndex: 0,

    currentStepIndex: -1,

    spinnerFrames: [
        "◐",
        "◓",
        "◑",
        "◒"
    ],

    stepOrder: [
        "identity",
        "hashes",
        "detection",
        "plan",
        "archive",
        "generic",
        "apk",
        "findings",
        "correlation",
        "evidence",
        "complete"
    ],

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.screen =
            document.getElementById(
                "screen-analysis"
            );

        this.elements.fileName =
            document.getElementById(
                "analysis-file"
            );

        this.elements.steps =
            document.getElementById(
                "analysis-steps"
            );

        if (this.elements.screen) {
            this.elements.status =
                this.elements.screen.querySelector(
                    ".analysis-live-status"
                );

            this.elements.statusText =
                this.elements.screen.querySelector(
                    ".analysis-live-text"
                );

            this.elements.spinner =
                this.elements.screen.querySelector(
                    ".analysis-spinner"
                );
        }

        this.elements.progressBar =
            document.getElementById(
                "analysis-progress-bar"
            );

        this.elements.progressValue =
            document.getElementById(
                "analysis-progress-value"
            );

        this.initialized = true;
    },

    start(file) {
        this.init();

        this.stopSpinner();

        this.currentStepIndex = -1;

        this.resetSteps();

        if (this.elements.fileName) {
            this.elements.fileName.textContent =
                file && file.name
                    ? file.name
                    : "UNKNOWN FILE";
        }

        this.setProgress(0);

        this.setLoadingState(
            "INITIALIZING"
        );

        this.startSpinner();
    },

    updateProgress(progress) {
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

        if (!step) {
            return;
        }

        this.updateStep(
            step,
            status
        );

        if (status === "running") {
            this.setLoadingState(step);
        }

        if (
            (
                status === "completed" ||
                status === "complete" ||
                status === "done"
            ) &&
            step === "complete"
        ) {
            this.setCompleteState();
        }
    },

    update(progress) {
        this.updateProgress(progress);
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

        const stepIndex =
            this.stepOrder.indexOf(
                stepName
            );

        const statusElement =
            step.querySelector(
                ".step-status"
            );

        step.classList.remove(
            "active",
            "complete",
            "error"
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

        if (
            status === "error" ||
            status === "failed"
        ) {
            step.classList.add(
                "error"
            );

            return;
        }

        if (
            status === "completed" ||
            status === "complete" ||
            status === "done"
        ) {
            step.classList.add(
                "complete"
            );

            if (
                stepIndex >= 0 &&
                stepIndex > this.currentStepIndex
            ) {
                this.currentStepIndex =
                    stepIndex;
            }

            this.updateProgressValue(
                stepName,
                status
            );

            return;
        }

        if (status === "running") {
            step.classList.add(
                "active"
            );

            if (
                stepIndex >= 0
            ) {
                this.currentStepIndex =
                    Math.max(
                        this.currentStepIndex,
                        stepIndex
                    );
            }

            this.updateProgressValue(
                stepName,
                status
            );
        }
    },

    updateProgressValue(
        stepName,
        status
    ) {
        const index =
            this.stepOrder.indexOf(
                stepName
            );

        if (index < 0) {
            return;
        }

        let completedIndex =
            index;

        if (status === "running") {
            completedIndex =
                Math.max(
                    0,
                    index - 0.35
                );
        }

        const total =
            this.stepOrder.length - 1;

        const percentage =
            total > 0
                ? Math.round(
                    (
                        completedIndex /
                        total
                    ) * 100
                )
                : 0;

        this.setProgress(
            percentage
        );
    },

    setProgress(
        percentage
    ) {
        const normalized =
            Math.max(
                0,
                Math.min(
                    100,
                    Number(
                        percentage
                    ) || 0
                )
            );

        if (
            this.elements.progressBar
        ) {
            this.elements.progressBar.style.width =
                `${normalized}%`;

            this.elements.progressBar.setAttribute(
                "aria-valuenow",
                String(normalized)
            );
        }

        if (
            this.elements.progressValue
        ) {
            this.elements.progressValue.textContent =
                `${normalized}%`;
        }
    },

    setLoadingState(
        stepName
    ) {
        this.init();

        if (this.elements.status) {
            this.elements.status.classList.remove(
                "is-complete",
                "is-error"
            );

            this.elements.status.classList.add(
                "is-loading"
            );
        }

        if (this.elements.statusText) {
            this.elements.statusText.textContent =
                stepName
                    ? this.formatStatus(
                        stepName
                    )
                    : "ANALYZING";
        }

        this.startSpinner();
    },

    setCompleteState() {
        this.init();

        this.stopSpinner();

        this.setProgress(
            100
        );

        if (this.elements.status) {
            this.elements.status.classList.remove(
                "is-loading",
                "is-error"
            );

            this.elements.status.classList.add(
                "is-complete"
            );
        }

        if (this.elements.statusText) {
            this.elements.statusText.textContent =
                "COMPLETE";
        }

        if (this.elements.spinner) {
            this.elements.spinner.textContent =
                "✓";
        }
    },

    complete(
        file,
        result
    ) {
        this.init();

        if (
            file &&
            file.name &&
            this.elements.fileName
        ) {
            this.elements.fileName.textContent =
                file.name;
        }

        if (
            result &&
            result.status === "completed"
        ) {
            this.setCompleteState();
        }
    },

    showError(
        error
    ) {
        this.init();

        this.stopSpinner();

        if (this.elements.status) {
            this.elements.status.classList.remove(
                "is-loading",
                "is-complete"
            );

            this.elements.status.classList.add(
                "is-error"
            );
        }

        if (this.elements.statusText) {
            this.elements.statusText.textContent =
                "ERROR";
        }

        if (this.elements.spinner) {
            this.elements.spinner.textContent =
                "!";
        }

        if (
            this.elements.progressValue
        ) {
            this.elements.progressValue.textContent =
                "ERROR";
        }

        console.error(
            "FileGuardAnalysisUI:",
            error
        );
    },

    startSpinner() {
        if (this.spinnerTimer) {
            return;
        }

        this.spinnerIndex = 0;

        if (this.elements.spinner) {
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
        if (!this.spinnerTimer) {
            return;
        }

        window.clearInterval(
            this.spinnerTimer
        );

        this.spinnerTimer =
            null;
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

    formatStatus(
        status
    ) {
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

        if (this.elements.screen) {
            this.elements.screen.hidden =
                true;
        }
    }
};

window.FileGuardAnalysisUI =
    FileGuardAnalysisUI;
