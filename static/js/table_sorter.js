class TableSorter {
    constructor(tableId) {
        this.table = document.getElementById(tableId);
        this.currentSort = {
            column: null,
            direction: "asc",
        };

        this.sortFunctions = {
            ip: (a, b) => this.sortIPAddresses(a, b),
            mac: (a, b) => this.sortMACAddresses(a, b),
            text: (a, b) => this.sortText(a, b),
            number: (a, b) => this.sortNumbers(a, b),
            ports: (a, b) => this.sortPortCount(a, b),
        };

        if (!this.table) {
            console.warn(`Table with id '${tableId}' not found`);
            return;
        }

        this.initializeSorting();
        this.loadSortState();
    }

    initializeSorting() {
        const headers = this.table.querySelectorAll(".sortable");
        headers.forEach((header) => {
            header.addEventListener("click", () => this.sortByColumn(header));
            header.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    this.sortByColumn(header);
                }
            });
            header.setAttribute("tabindex", "0");
        });
    }

    sortByColumn(header) {
        const column = header.dataset.column;
        const type = header.dataset.type;

        if (this.currentSort.column === column) {
            this.currentSort.direction =
                this.currentSort.direction === "asc" ? "desc" : "asc";
        } else {
            this.currentSort.column = column;
            this.currentSort.direction = "asc";
        }

        this.sortTable(column, type, this.currentSort.direction);
        this.updateVisualIndicators(header);
        this.saveSortState();
    }

    sortTable(column, type, direction) {
        const tbody = this.table.querySelector("tbody");
        const rows = Array.from(tbody.querySelectorAll("tr"));

        rows.sort((a, b) => {
            const aValue = this.getCellValue(a, column);
            const bValue = this.getCellValue(b, column);
            const sortFn = this.sortFunctions[type] || this.sortFunctions.text;
            const result = sortFn(aValue, bValue);
            return direction === "asc" ? result : -result;
        });

        rows.forEach((row) => tbody.appendChild(row));
    }

    sortIPAddresses(a, b) {
        const aParts = a.split(".").map(Number);
        const bParts = b.split(".").map(Number);

        for (let index = 0; index < 4; index += 1) {
            if (aParts[index] !== bParts[index]) {
                return aParts[index] - bParts[index];
            }
        }
        return 0;
    }

    sortMACAddresses(a, b) {
        const aHex = a.replace(/:/g, "");
        const bHex = b.replace(/:/g, "");
        return parseInt(aHex, 16) - parseInt(bHex, 16);
    }

    sortText(a, b) {
        return a.localeCompare(b, undefined, {
            numeric: true,
            sensitivity: "base",
        });
    }

    sortNumbers(a, b) {
        return parseFloat(a) - parseFloat(b);
    }

    sortPortCount(a, b) {
        const aCount = (a || "").split(",").length;
        const bCount = (b || "").split(",").length;
        return aCount - bCount;
    }

    getCellValue(row, column) {
        const columnIndex = this.getColumnIndex(column);
        const cell = row.cells[columnIndex];
        return cell ? cell.textContent.trim() : "";
    }

    getColumnIndex(column) {
        const columnMap = {
            status: 0,
            ip: 1,
            mac: 2,
            vendor: 3,
            hostname: 4,
            open_ports: 5,
            version: 6,
            cves: 7,
        };
        return columnMap[column] || 0;
    }

    updateVisualIndicators(activeHeader) {
        this.table.querySelectorAll(".sortable").forEach((header) => {
            header.classList.remove("sorted-asc", "sorted-desc");
        });

        const directionClass =
            this.currentSort.direction === "asc" ? "sorted-asc" : "sorted-desc";
        activeHeader.classList.add(directionClass);
    }

    saveSortState() {
        const state = {
            column: this.currentSort.column,
            direction: this.currentSort.direction,
            timestamp: Date.now(),
        };
        localStorage.setItem("tableSortState", JSON.stringify(state));
    }

    loadSortState() {
        try {
            const state = JSON.parse(localStorage.getItem("tableSortState"));
            if (state && state.column) {
                this.currentSort = state;
                const header = this.table.querySelector(
                    `[data-column="${state.column}"]`
                );
                if (header) {
                    this.sortTable(state.column, header.dataset.type, state.direction);
                    this.updateVisualIndicators(header);
                }
            }
        } catch (error) {
            console.warn("Failed to load sort state:", error);
        }
    }

    resort() {
        if (this.currentSort.column) {
            const header = this.table.querySelector(
                `[data-column="${this.currentSort.column}"]`
            );
            if (header) {
                this.sortTable(
                    this.currentSort.column,
                    header.dataset.type,
                    this.currentSort.direction
                );
            }
        }
    }
}

window.TableSorter = TableSorter;
