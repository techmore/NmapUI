function setUpdateReleaseNotes(data) {
    const notesDiv = document.getElementById("update-release-notes");
    notesDiv.replaceChildren();

    const title = document.createElement("strong");
    title.textContent = "Release Notes:";
    notesDiv.appendChild(title);
    notesDiv.appendChild(document.createElement("br"));

    const lines = data.available
        ? (data.release_notes
            ? String(data.release_notes).split(/\n/)
            : [`New version ${data.latest_version} is available.`])
        : ["You are using the latest version."];

    lines.forEach((line, index) => {
        if (index > 0) {
            notesDiv.appendChild(document.createElement("br"));
        }
        notesDiv.appendChild(document.createTextNode(line));
    });
}

function appendUpdateLogLine(message, isError = false) {
    const log = document.getElementById("update-log");
    const line = document.createElement("div");
    line.className = isError ? "py-0.5 text-red-400 font-bold" : "py-0.5";

    const timestamp = document.createElement("span");
    timestamp.className = "text-zinc-500 mr-2";
    timestamp.textContent = `[${new Date().toLocaleTimeString()}]`;
    line.appendChild(timestamp);
    line.appendChild(
        document.createTextNode(isError ? ` ERROR: ${message}` : ` ${message}`)
    );
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
}

function showUpdateModal() {
    document.getElementById("update-modal").classList.remove("hidden");
}

function hideUpdateModal() {
    document.getElementById("update-modal").classList.add("hidden");
    document.getElementById("update-log").innerHTML = "";
    document.getElementById("update-current-status").textContent = "Ready to update";
    document.getElementById("update-progress-bar").style.width = "0%";
    document.getElementById("update-percentage").textContent = "0%";
}

function startAppUpdate(socket) {
    appendUpdateLogLine("Starting application update...");
    socket.emit("perform_app_update");
    document.getElementById("update-current-status").textContent = "Updating...";
}

function initializeUpdateModal(socket, deps = {}) {
    const showReportStatus =
        deps.showReportStatus || window.showReportStatus || (() => {});

    socket.on("app_update_available", (data) => {
        document.getElementById("app-update-badge").classList.remove("hidden");
        document.getElementById("update-version").textContent = data.latest_version;
        setUpdateReleaseNotes(data);
    });

    socket.on("update_status", (data) => {
        console.log("Update status:", data.message);
        const statusText = document.getElementById("update-current-status");
        const progressBar = document.getElementById("update-progress-bar");
        const percentageText = document.getElementById("update-percentage");

        statusText.textContent = data.message;
        appendUpdateLogLine(data.message);

        let progress = 0;
        if (data.message.includes("Downloading")) {
            progress = 25;
        } else if (data.message.includes("Installing")) {
            progress = 60;
        } else if (data.message.includes("Restarting")) {
            progress = 90;
        } else if (data.message.includes("complete")) {
            progress = 100;
        }

        progressBar.style.width = `${progress}%`;
        percentageText.textContent = `${progress}%`;
    });

    socket.on("update_error", (data) => {
        console.error("Update error:", data.message);
        appendUpdateLogLine(data.message, true);
        document.getElementById("update-current-status").textContent = "Update failed";
        document.getElementById("update-current-status").classList.add("text-red-500");
        document.getElementById("update-progress-bar").classList.add("bg-red-500");
    });

    socket.on("show_auto_update_banner", (data) => {
        showReportStatus(
            `Application update available: ${data.latest_version}. Auto-update countdown started.`,
            "info"
        );
    });

    socket.on("hide_auto_update_banner", () => {
        const badge = document.getElementById("app-update-badge");
        if (badge) {
            badge.classList.add("hidden");
        }
    });
}

window.setUpdateReleaseNotes = setUpdateReleaseNotes;
window.appendUpdateLogLine = appendUpdateLogLine;
window.showUpdateModal = showUpdateModal;
window.hideUpdateModal = hideUpdateModal;
window.initializeUpdateModal = initializeUpdateModal;
window.startAppUpdate = () => {
    if (window.socket) {
        startAppUpdate(window.socket);
    }
};
