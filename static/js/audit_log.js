(function () {
    let logCount = 0;
    const LEVEL_STYLES = {
        log: 'text-olive-300',
        info: 'text-olive-300',
        warn: 'text-amber-400',
        error: 'text-red-400',
        scan: 'text-emerald-400',
        raw: 'text-olive-500',
    };

    function timestamp() {
        return new Date().toISOString().replace('T', ' ').slice(0, 23);
    }

    function appendLog(level, message) {
        logCount += 1;
        const container = document.getElementById('log-entries');
        if (!container) {
            return;
        }

        const div = document.createElement('div');
        div.className = `flex gap-2 leading-5 ${LEVEL_STYLES[level] || 'text-olive-300'}`;

        const timeSpan = document.createElement('span');
        timeSpan.className = 'text-olive-600 flex-shrink-0 select-none';
        timeSpan.textContent = timestamp();

        const levelSpan = document.createElement('span');
        levelSpan.className = `uppercase font-bold flex-shrink-0 w-6 select-none ${LEVEL_STYLES[level] || ''}`;
        levelSpan.textContent =
            level === 'scan' ? 'SCN' : level === 'raw' ? 'RAW' : level.slice(0, 3).toUpperCase();

        const msgSpan = document.createElement('span');
        msgSpan.className = 'break-all whitespace-pre-wrap';
        msgSpan.textContent = message;

        div.appendChild(timeSpan);
        div.appendChild(levelSpan);
        div.appendChild(msgSpan);
        container.appendChild(div);

        if (container.scrollHeight - container.scrollTop < container.clientHeight + 80) {
            container.scrollTop = container.scrollHeight;
        }

        const countEl = document.getElementById('log-entry-count');
        if (countEl) {
            countEl.textContent = `${logCount} entr${logCount === 1 ? 'y' : 'ies'}`;
        }

        const badge = document.getElementById('log-count-badge');
        if (badge) {
            badge.textContent = logCount > 999 ? '999+' : logCount;
            badge.classList.remove('hidden');
        }
    }

    function serializeArgs(args) {
        return Array.from(args)
            .map((arg) => {
                if (typeof arg === 'string') {
                    return arg;
                }
                try {
                    return JSON.stringify(arg);
                } catch {
                    return String(arg);
                }
            })
            .join(' ');
    }

    function bindConsoleInterceptors() {
        const originalLog = console.log.bind(console);
        const originalInfo = console.info.bind(console);
        const originalWarn = console.warn.bind(console);
        const originalError = console.error.bind(console);

        console.log = function (...args) {
            originalLog(...args);
            appendLog('log', serializeArgs(args));
        };
        console.info = function (...args) {
            originalInfo(...args);
            appendLog('info', serializeArgs(args));
        };
        console.warn = function (...args) {
            originalWarn(...args);
            appendLog('warn', serializeArgs(args));
        };
        console.error = function (...args) {
            originalError(...args);
            appendLog('error', serializeArgs(args));
        };
    }

    function bindWindowErrorLogger() {
        window.addEventListener('error', function (event) {
            appendLog(
                'error',
                (event.message || String(event)) +
                    (event.filename ? ` @ ${event.filename}:${event.lineno}` : '')
            );
        });
    }

    function bindSocketLogEvents() {
        if (typeof socket === 'undefined') {
            return false;
        }

        socket.on('scan_feedback', function (data) {
            appendLog('scan', `[${data.target || ''}] ${data.message || JSON.stringify(data)}`);
        });
        socket.on('scan_raw_output', function (data) {
            const lines = (data.output || '').split('\n');
            lines.forEach(function (line) {
                if (line.trim()) {
                    appendLog('raw', `[${data.target || ''}] ${line}`);
                }
            });
        });
        return true;
    }

    function initializeAuditLog() {
        bindConsoleInterceptors();
        bindWindowErrorLogger();

        if (!bindSocketLogEvents()) {
            setTimeout(function () {
                bindSocketLogEvents();
            }, 2000);
        }
    }

    window.toggleLogPanel = function () {
        const panel = document.getElementById('log-panel');
        if (!panel) return;
        const isHidden = panel.classList.contains('hidden');
        panel.classList.toggle('hidden');
        if (isHidden) {
            const container = document.getElementById('log-entries');
            if (container) {
                container.scrollTop = container.scrollHeight;
            }
            const badge = document.getElementById('log-count-badge');
            if (badge) {
                badge.classList.add('hidden');
            }
        }
    };

    window.clearLog = function () {
        const container = document.getElementById('log-entries');
        if (container) {
            container.innerHTML = '';
        }
        logCount = 0;
        const countEl = document.getElementById('log-entry-count');
        if (countEl) {
            countEl.textContent = '0 entries';
        }
    };

    window.copyLog = function (event) {
        const container = document.getElementById('log-entries');
        if (!container) return;

        const text = Array.from(container.querySelectorAll('div'))
            .map((div) => div.textContent)
            .join('\n');

        navigator.clipboard.writeText(text).then(function () {
            const button = event?.target;
            if (!button) {
                return;
            }
            const original = button.textContent;
            button.textContent = 'Copied!';
            setTimeout(function () {
                button.textContent = original;
            }, 1500);
        }).catch(function () {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        });
    };

    window._appendLog = appendLog;
    window.initializeAuditLog = initializeAuditLog;
})();
