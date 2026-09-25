"use strict";

const FileGuardAnalysisUI = {
    elements: {
        section: null,
        fileName: null,
        steps: null
    },

    initialized: false,

    init() {
        if (this.initialized) {
            return;
        }

        this.elements.section =
            document.getElementById("analysis-section");

        this.elements.fileName =
            document.getElementById("analysis-file");

        this.elements.steps =
            document.getElementById("analysis-steps");

        this.initialized = true;
    },

    show(file) {
        this.init();

        if (!this.elements.section) {
            return;
        }

        this.resetSteps();

        if (this.elements.fileName) {
            this.elements.fileName.textContent =
                file?.name || "UNKNOWN FILE";
        }

        this.elements.section.hidden = false;

        const resultSection =
            document.getElementById("result-section");

        if (resultSection) {
            resultSection.hidden = true;
        }

        const errorSection =
            document.getElementById("error-section");

        if (errorSection) {
            errorSection.hidden = true;
        }
    },

    update(progress) {
        this.init();

        if (!progress || typeof progress !== "object") {
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
            this.updateStep(step, status);
        }
    },

    updateStep(stepName, status) {
        if (!this.elements.steps) {
            return;
        }

        const step =
            this.elements.steps.querySelector(
                `[data-step="${stepName}"]`
            );

        if (!step) {
            return;
        }

        const statusElement =
            step.querySelector(".step-status");

        if (statusElement && status) {
            statusElement.textContent =
                this.formatStatus(status);
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
            step.classList.add("complete");
            return;
        }

        if (
            status === "error" ||
            status === "failed"
        ) {
            step.classList.add("error");
            return;
        }

        step.classList.add("active");
    },

    resetSteps() {
        if (!this.elements.steps) {
            return;
        }

        const steps =
            this.elements.steps.querySelectorAll(
                ".analysis-step"
            );

        steps.forEach((step) => {
            step.classList.remove(
                "active",
                "complete",
                "error"
            );

            const statusElement =
                step.querySelector(".step-status");

            if (statusElement) {
                statusElement.textContent = "WAITING";
            }
        });
    },

    formatStatus(status) {
        if (typeof status !== "string") {
            return "WAITING";
        }

        return status
            .replace(/[-_]+/g, " ")
            .toUpperCase();
    },

    hide() {
        this.init();

        if (this.elements.section) {
            this.elements.section.hidden = true;
        }
    }
};

window.FileGuardAnalysisUI = FileGuardAnalysisUI;
