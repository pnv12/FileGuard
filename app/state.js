"use strict";

const FileGuardAppState = {

    version: "1.0.0",

    currentFile: null,

    currentResult: null,

    activePanel: "overview",

    screen: "home",

    analysisRunning: false,

    error: null,

    resetForAnalysis(file) {
        this.currentFile = file;
        this.currentResult = null;
        this.activePanel = "overview";
        this.screen = "analysis";
        this.analysisRunning = true;
        this.error = null;
    },

    setResult(result) {
        this.currentResult = result;
        this.screen = "results";
        this.analysisRunning = false;
        this.error = null;
    },

    setError(error) {
        this.screen = "error";
        this.analysisRunning = false;
        this.error = error;
    },

    setScreen(screenName) {
        if (
            typeof screenName !== "string" ||
            screenName.length === 0
        ) {
            return;
        }

        this.screen = screenName;
    },

    setActivePanel(panelName) {
        if (
            typeof panelName !== "string" ||
            panelName.length === 0
        ) {
            return;
        }

        this.activePanel = panelName;
    },

    clear() {
        this.currentFile = null;
        this.currentResult = null;
        this.activePanel = "overview";
        this.screen = "home";
        this.analysisRunning = false;
        this.error = null;
    }
};

window.FileGuardAppState = FileGuardAppState;
