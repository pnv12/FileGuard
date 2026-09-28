"use strict";

const FileGuardRouter = {

    initialized: false,

    routes: {
        home: "screen-home",
        analysis: "screen-analysis",
        results: "screen-results",
        error: "screen-error",
        diagnostics: "screen-diagnostics"
    },

    titles: {
        home: "FileGuard — File Analysis Laboratory",
        analysis: "FileGuard — Analyzing File",
        results: "FileGuard — Analysis Results",
        error: "FileGuard — Analysis Error",
        diagnostics: "FileGuard — Diagnostics"
    },

    init() {
        if (this.initialized) {
            return;
        }

        window.addEventListener(
            "hashchange",
            () => {
                this.handleHash();
            }
        );

        document.addEventListener(
            "click",
            (event) => {
                this.handleNavigationClick(event);
            }
        );

        this.initialized = true;

        this.handleHash();
    },

    handleNavigationClick(event) {
        const navigationElement =
            event.target.closest(
                "[data-navigation]"
            );

        if (!navigationElement) {
            return;
        }

        const screen =
            navigationElement.dataset.navigation;

        if (!screen) {
            return;
        }

        event.preventDefault();

        this.navigate(screen);
    },

    navigate(screen) {
        if (!this.routes[screen]) {
            console.warn(
                "FileGuardRouter: unknown screen:",
                screen
            );

            return;
        }

        if (!this.canEnter(screen)) {
            screen = "home";
        }

        const targetHash =
            this.getHashForScreen(screen);

        if (window.location.hash !== targetHash) {
            window.location.hash = targetHash;
            return;
        }

        this.render(screen);
    },

    handleHash() {
        const requestedScreen =
            this.getScreenFromHash();

        const screen =
            this.canEnter(requestedScreen)
                ? requestedScreen
                : "home";

        const targetHash =
            this.getHashForScreen(screen);

        if (
            window.location.hash !== targetHash
        ) {
            window.history.replaceState(
                null,
                "",
                targetHash
            );
        }

        this.render(screen);
    },

    getScreenFromHash() {
        const hash =
            window.location.hash || "#/";

        const normalized =
            hash
                .replace(/^#/, "")
                .replace(/^\/+/, "")
                .replace(/\/+$/, "");

        if (!normalized) {
            return "home";
        }

        const screen =
            normalized.split("/")[0];

        return this.routes[screen]
            ? screen
            : "home";
    },

    getHashForScreen(screen) {
        if (screen === "home") {
            return "#/";
        }

        return "#/" + screen;
    },

    canEnter(screen) {
        const state =
            window.FileGuardAppState;

        if (!this.routes[screen]) {
            return false;
        }

        if (!state) {
            return screen === "home";
        }

        if (screen === "analysis") {
            return Boolean(
                state.currentFile &&
                state.analysisRunning
            );
        }

        if (screen === "results") {
            return Boolean(
                state.currentResult &&
                !state.analysisRunning
            );
        }

        if (screen === "error") {
            return Boolean(
                state.error &&
                !state.analysisRunning
            );
        }

        if (screen === "diagnostics") {
            return true;
        }

        return true;
    },

    render(screen) {
        const screenIds =
            Object.values(
                this.routes
            );

        screenIds.forEach(
            (screenId) => {

                const element =
                    document.getElementById(
                        screenId
                    );

                if (!element) {
                    return;
                }

                const isActive =
                    screenId ===
                    this.routes[screen];

                if (isActive) {

                    element.hidden = false;

                    element.setAttribute(
                        "aria-hidden",
                        "false"
                    );

                    element.classList.remove(
                        "is-active"
                    );

                    requestAnimationFrame(
                        () => {
                            element.classList.add(
                                "is-active"
                            );
                        }
                    );

                } else {

                    element.classList.remove(
                        "is-active"
                    );

                    element.hidden = true;

                    element.setAttribute(
                        "aria-hidden",
                        "true"
                    );
                }
            }
        );

        if (
            window.FileGuardAppState &&
            typeof window.FileGuardAppState.setScreen ===
                "function"
        ) {
            window.FileGuardAppState.setScreen(
                screen
            );
        }

        const title =
            this.titles[screen];

        if (title) {
            document.title = title;
        }

        window.scrollTo({
            top: 0,
            behavior: "auto"
        });
    }

};

window.FileGuardRouter =
    FileGuardRouter;
