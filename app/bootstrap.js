"use strict";

document.addEventListener(
    "DOMContentLoaded",
    () => {
        if (!window.FileGuardController) {
            console.error(
                "FileGuardController is not available."
            );

            return;
        }

        window.FileGuardController.init();
    }
);
