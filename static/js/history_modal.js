function renderHistoryState(message, isError = false) {
    const historyList = document.getElementById("history-list");
    historyList.replaceChildren();
    const paragraph = document.createElement("p");
    paragraph.className = isError ? "text-red-600" : "text-olive-600";
    paragraph.textContent = message;
    historyList.appendChild(paragraph);
}

function renderHistoryList(scans) {
    const historyList = document.getElementById("history-list");
    historyList.replaceChildren();

    scans.forEach((scan) => {
        const card = document.createElement("div");
        card.className = "bg-olive-50 p-4 rounded-lg border border-olive-300";

        const header = document.createElement("div");
        header.className = "flex justify-between items-start mb-2";

        const details = document.createElement("div");
        details.className = "max-w-7xl mx-auto px-4 sm:px-6 lg:px-8";

        const title = document.createElement("h3");
        title.className = "font-display text-lg text-olive-900";
        title.textContent = scan.customer_name || "Unknown";
        details.appendChild(title);

        const dateText = document.createElement("p");
        dateText.className = "text-sm text-olive-600";
        dateText.textContent = new Date(scan.timestamp).toLocaleString();
        details.appendChild(dateText);

        const targetText = document.createElement("p");
        targetText.className = "text-sm text-olive-700 mt-1";
        targetText.appendChild(document.createTextNode("Target: "));
        const targetSpan = document.createElement("span");
        targetSpan.className = "font-mono";
        targetSpan.textContent = scan.target;
        targetText.appendChild(targetSpan);
        details.appendChild(targetText);
        header.appendChild(details);

        const actions = document.createElement("div");
        actions.className = "flex gap-2";

        const buildLink = (href, label, className, newTab = false) => {
            const link = document.createElement("a");
            link.href = href;
            if (newTab) {
                link.target = "_blank";
                link.rel = "noopener noreferrer";
            }
            link.className = className;
            link.textContent = label;
            actions.appendChild(link);
        };

        if (scan.has_html) {
            buildLink(
                `/api/scans/${scan.path}/html`,
                "View HTML",
                "px-3 py-1 bg-olive-600 text-white rounded text-sm hover:bg-olive-700",
                true
            );
        }
        if (scan.has_pdf) {
            buildLink(
                `/api/scans/${scan.path}/pdf`,
                "Download PDF",
                "px-3 py-1 bg-olive-700 text-white rounded text-sm hover:bg-olive-800"
            );
        }
        if (scan.has_xml) {
            buildLink(
                `/api/scans/${scan.path}/xml`,
                "Download XML",
                "px-3 py-1 bg-olive-500 text-white rounded text-sm hover:bg-olive-600"
            );
        }

        const deleteButton = document.createElement("button");
        deleteButton.className =
            "px-3 py-1 bg-red-600 text-white rounded text-sm hover:bg-red-700";
        deleteButton.textContent = "Delete";
        deleteButton.addEventListener("click", () => window.deleteScan(scan.path));
        actions.appendChild(deleteButton);

        header.appendChild(actions);
        card.appendChild(header);
        historyList.appendChild(card);
    });
}

function populateCustomerFilter(scans, defaultValue = "") {
    const filter = document.getElementById("history-customer-filter");
    const customers = [...new Set(scans.map((scan) => scan.customer_name))].sort();
    const currentValue = filter.value || defaultValue;

    filter.replaceChildren();
    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = "All Customers";
    filter.appendChild(defaultOption);

    customers.forEach((customer) => {
        const option = document.createElement("option");
        option.value = customer;
        option.textContent = customer;
        filter.appendChild(option);
    });

    if (customers.includes(currentValue)) {
        filter.value = currentValue;
    } else {
        filter.value = "";
    }
}

function displayScanHistory(scans) {
    if (scans.length === 0) {
        renderHistoryState("No scans found");
        return;
    }

    renderHistoryList(scans);
}

async function loadScanHistory(isInitialLoad = false) {
    const modal = document.getElementById("history-modal");
    const filter = document.getElementById("history-customer-filter");
    const dateFilter = document.getElementById("history-date-filter").value;

    let customerFilter = filter.value;
    if (isInitialLoad && !customerFilter && modal.dataset.defaultCustomer) {
        customerFilter = modal.dataset.defaultCustomer;
    }

    try {
        const response = await fetch("/api/scans");
        const data = await response.json();

        let scans = data.scans || [];
        populateCustomerFilter(scans, customerFilter);

        const activeFilter = filter.value;
        if (activeFilter) {
            scans = scans.filter((scan) => scan.customer_name === activeFilter);
        }
        if (dateFilter) {
            scans = scans.filter((scan) => scan.date === dateFilter);
        }

        displayScanHistory(scans);
    } catch (error) {
        console.error("Error loading scan history:", error);
        renderHistoryState("Error loading scan history", true);
    }
}

function showHistoryModal() {
    const modal = document.getElementById("history-modal");
    const customerDropdown = document.getElementById("current-customer");

    modal.classList.remove("hidden");

    let currentName = "";
    if (customerDropdown && customerDropdown.selectedOptions[0]) {
        currentName = customerDropdown.selectedOptions[0].text.split(" (")[0];
    }

    if (
        currentName &&
        currentName !== "Unassigned" &&
        currentName !== "Unknown Network" &&
        currentName !== "Auto-detect network..."
    ) {
        modal.dataset.defaultCustomer = currentName;
    } else {
        delete modal.dataset.defaultCustomer;
    }

    loadScanHistory(true);
}

function hideHistoryModal() {
    document.getElementById("history-modal").classList.add("hidden");
}

window.renderHistoryState = renderHistoryState;
window.renderHistoryList = renderHistoryList;
window.populateCustomerFilter = populateCustomerFilter;
window.displayScanHistory = displayScanHistory;
window.loadScanHistory = loadScanHistory;
window.showHistoryModal = showHistoryModal;
window.hideHistoryModal = hideHistoryModal;
