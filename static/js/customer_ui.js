let customersTabInitialized = false;

function setCustomerTabStatus(message, isError = false) {
    const status = document.getElementById('customers-tab-status');
    if (!status) return;
    if (!message) {
        status.textContent = '';
        status.classList.add('hidden');
        return;
    }
    status.textContent = message;
    status.classList.remove('hidden');
    status.classList.toggle('bg-red-50', isError);
    status.classList.toggle('text-red-700', isError);
    status.classList.toggle('bg-olive-50', !isError);
    status.classList.toggle('text-olive-800', !isError);
}

function loadLocalCustomers() {
    try {
        return JSON.parse(localStorage.getItem('gemini-nmap-customers') || '[]');
    } catch (error) {
        return [];
    }
}

function saveLocalCustomers(customers) {
    localStorage.setItem('gemini-nmap-customers', JSON.stringify(customers));
}

function escapeCustomerHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function renderCustomerFingerprint(profile) {
    if (!profile) return;
    const prefixInput = document.getElementById('customer-profile-prefix');
    const summary = document.getElementById('customer-fingerprint-summary');
    const folder = document.getElementById('customer-fingerprint-folder');

    if (prefixInput && !prefixInput.value) prefixInput.value = profile.prefix || 'CSP';
    if (summary) {
        summary.textContent = `${profile.reportLabel || profile.baseName || 'CSP_(unknown_wan)'} | ${profile.fingerprint || 'pending'} | WAN ${profile.publicIP || 'Unknown'}`;
    }
    if (folder) {
        folder.textContent = `Reports folder: reports_archive/${profile.folderName || 'pending'}`;
    }
}

function renderCustomersTab(customers = loadLocalCustomers()) {
    const list = document.getElementById('customers-tab-list');
    if (!list) return;
    list.replaceChildren();

    if (!customers.length) {
        setCustomerTabStatus('No customers configured in this browser yet.');
        return;
    }

    setCustomerTabStatus('');
    customers.forEach(customer => {
        const card = document.createElement('div');
        card.className = 'rounded-2xl border border-olive-200 bg-white p-5 shadow-sm';
        card.innerHTML = `
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-olive-950">${escapeCustomerHTML(customer.name)}</h3>
                    <p class="mt-1 font-mono text-xs text-olive-600">${escapeCustomerHTML(customer.target || 'No target saved')}</p>
                </div>
                <button type="button" class="delete-customer-btn action-button action-button-secondary action-button-compact" data-id="${escapeCustomerHTML(customer.id)}">Delete</button>
            </div>
        `;
        list.appendChild(card);
    });
}

function loadCustomersTab() {
    renderCustomersTab();
    window.socket?.emit('get_customer_profile');
}

function showCustomerForm() {
    const name = prompt('Customer name');
    if (!name) return;
    const target = prompt('Default target or public IP', document.getElementById('scan-target')?.value || '') || '';
    const customers = loadLocalCustomers();
    customers.unshift({ id: String(Date.now()), name, target });
    saveLocalCustomers(customers);
    renderCustomersTab(customers);
}

function initializeCustomerUI() {
    if (customersTabInitialized) return;
    customersTabInitialized = true;

    document.getElementById('refresh-customers-tab-btn')?.addEventListener('click', loadCustomersTab);
    document.getElementById('add-customer-tab-btn')?.addEventListener('click', showCustomerForm);
    document.getElementById('save-customer-prefix-btn')?.addEventListener('click', () => {
        const prefix = document.getElementById('customer-profile-prefix')?.value || 'CSP';
        window.socket?.emit('set_customer_profile_prefix', { prefix });
        setCustomerTabStatus('Customer report prefix saved.');
    });
    window.socket?.on('customer_profile', renderCustomerFingerprint);
    document.getElementById('customers-tab-list')?.addEventListener('click', event => {
        const button = event.target.closest('.delete-customer-btn');
        if (!button) return;
        const customers = loadLocalCustomers().filter(customer => customer.id !== button.dataset.id);
        saveLocalCustomers(customers);
        renderCustomersTab(customers);
    });
}

window.initializeCustomerUI = initializeCustomerUI;
window.loadCustomersTab = loadCustomersTab;
window.showCustomerForm = showCustomerForm;
window.renderCustomerFingerprint = renderCustomerFingerprint;
