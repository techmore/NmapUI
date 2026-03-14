function updateDateTime() {
    const now = new Date();
    const options = {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    document.getElementById('current-date-time').textContent = now.toLocaleDateString('en-US', options);
}

function startPreciseClock() {
    updateDateTime();

    const now = new Date();
    const secondsUntilNextMinute = 60 - now.getSeconds();
    const msUntilNextMinute = secondsUntilNextMinute * 1000 - now.getMilliseconds();

    setTimeout(() => {
        updateDateTime();
        setInterval(updateDateTime, 60000);
    }, msUntilNextMinute);
}

function renderHistoryState(message, isError = false) {
    const historyList = document.getElementById('history-list');
    historyList.replaceChildren();
    const paragraph = document.createElement('p');
    paragraph.className = isError ? 'text-red-600' : 'text-olive-600';
    paragraph.textContent = message;
    historyList.appendChild(paragraph);
}

function renderHistoryList(scans) {
    const historyList = document.getElementById('history-list');
    historyList.replaceChildren();

    scans.forEach(scan => {
        const card = document.createElement('div');
        card.className = 'bg-olive-50 p-4 rounded-lg border border-olive-300';

        const header = document.createElement('div');
        header.className = 'flex justify-between items-start mb-2';
        const details = document.createElement('div');
        details.className = 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8';

        const title = document.createElement('h3');
        title.className = 'font-display text-lg text-olive-900';
        title.textContent = scan.customer_name || 'Unknown';
        details.appendChild(title);

        const dateText = document.createElement('p');
        dateText.className = 'text-sm text-olive-600';
        dateText.textContent = new Date(scan.timestamp).toLocaleString();
        details.appendChild(dateText);

        const targetText = document.createElement('p');
        targetText.className = 'text-sm text-olive-700 mt-1';
        targetText.appendChild(document.createTextNode('Target: '));
        const targetSpan = document.createElement('span');
        targetSpan.className = 'font-mono';
        targetSpan.textContent = scan.target;
        targetText.appendChild(targetSpan);
        details.appendChild(targetText);
        header.appendChild(details);

        const actions = document.createElement('div');
        actions.className = 'flex gap-2';

        const buildLink = (href, label, className, newTab = false) => {
            const link = document.createElement('a');
            link.href = href;
            if (newTab) {
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
            }
            link.className = className;
            link.textContent = label;
            actions.appendChild(link);
        };

        if (scan.has_html) {
            buildLink(`/api/scans/${scan.path}/html`, 'View HTML', 'px-3 py-1 bg-olive-600 text-white rounded text-sm hover:bg-olive-700', true);
        }
        if (scan.has_pdf) {
            buildLink(`/api/scans/${scan.path}/pdf`, 'Download PDF', 'px-3 py-1 bg-olive-700 text-white rounded text-sm hover:bg-olive-800');
        }
        if (scan.has_xml) {
            buildLink(`/api/scans/${scan.path}/xml`, 'Download XML', 'px-3 py-1 bg-olive-500 text-white rounded text-sm hover:bg-olive-600');
        }

        const deleteButton = document.createElement('button');
        deleteButton.className = 'px-3 py-1 bg-red-600 text-white rounded text-sm hover:bg-red-700';
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => deleteScan(scan.path));
        actions.appendChild(deleteButton);

        header.appendChild(actions);
        card.appendChild(header);
        historyList.appendChild(card);
    });
}

async function deleteScan(path) {
    if (!confirm('Are you sure you want to delete this scan?')) {
        return;
    }

    try {
        const response = await fetch(`/api/scans/${path}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadScanHistory();
        } else {
            alert('Error deleting scan');
        }
    } catch (error) {
        console.error('Error deleting scan:', error);
        alert('Error deleting scan');
    }
}

function initializeLayoutRuntime() {
    startPreciseClock();

    document.getElementById('view-history-btn').addEventListener('click', function() {
        showHistoryModal();
    });
}

window.renderHistoryState = renderHistoryState;
window.renderHistoryList = renderHistoryList;
window.deleteScan = deleteScan;
window.initializeLayoutRuntime = initializeLayoutRuntime;
