/**
 * Shared frontend utilities.
 * Loaded first (after vendor scripts) so every other module can use them.
 */

/**
 * Escape a value for safe interpolation into innerHTML template strings.
 * Canonical XSS helper — use this instead of per-file copies.
 */
function escapeHTMLValue(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

window.escapeHTMLValue = escapeHTMLValue;
