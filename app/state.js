"use strict";

const FileGuardAppState = {
    version: "1.0.0",

    currentFile: null,
    currentResult: null,

    activePanel: "overview",

    analysisRunning: false,

    error: null,

    resetForAnalysis(file) {
        this.currentFile = file;
        this.currentResult = null;
        this.analysisRunning = true;
        this.error = null;
    },

    setResult(result) {
        this.currentResult = result;
        this.analysisRunning = false;
        this.error = null;
    },

    setError(error) {
        this.analysisRunning = false;
        this.error = error;
    },

    setActivePanel(panelName) {
        if (typeof panelName !== "string" || panelName.length === 0) {
            return;
        }

        this.activePanel = panelName;
    },

    clear() {
        this.currentFile = null;
        this.currentResult = null;
        this.analysisRunning = false;
        this.activePanel = "overview";
        this.error = null;
    }
};

window.FileGuardAppState = FileGuardAppState;
