function showCustomerForm() {
    document.getElementById('add-customer-form').classList.remove('hidden');
}

function hideCustomerForm() {
    document.getElementById('add-customer-form').classList.add('hidden');
}

function showCustomerMessage(message, type = 'info') {
    const messagesDiv = document.getElementById('customer-messages');
    const messageSpan = document.getElementById('customer-message');

    messagesDiv.classList.remove('hidden');
    messageSpan.textContent = message;

    messagesDiv.firstElementChild.className = `p-3 border rounded-lg text-sm ${
        type === 'error' ? 'bg-red-100 border-red-300 text-red-800' :
        type === 'success' ? 'bg-green-100 border-green-300 text-green-800' :
        'bg-yellow-100 border-yellow-300 text-yellow-800'
    }`;

    setTimeout(() => {
        messagesDiv.classList.add('hidden');
    }, 5000);
}

function populateCustomerDropdown(customers) {
    console.log('Populating customer dropdowns with', customers.length, 'customers');

    const mainDropdown = document.getElementById('current-customer');
    const quickAddDropdown = document.getElementById('customer-quick-add');

    if (!quickAddDropdown) return;

    const unassignedOption = () => {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'Unassigned';
        return option;
    };

    quickAddDropdown.replaceChildren(unassignedOption());
    if (mainDropdown) {
        mainDropdown.replaceChildren(unassignedOption());
    }

    customers.forEach(customer => {
        const customerId = String(customer.id);
        const customerName = customer.name;

        if (!customerId || !customerName) return;

        if (mainDropdown) {
            const mainOption = document.createElement('option');
            mainOption.value = customerId;
            mainOption.textContent = customerName;
            if (customerId === 'unknown') mainOption.classList.add('hidden');
            mainDropdown.appendChild(mainOption);
        }

        const quickOption = document.createElement('option');
        quickOption.value = customerId;
        quickOption.textContent = customerName;
        if (customerId === 'unknown') quickOption.classList.add('hidden');
        quickAddDropdown.appendChild(quickOption);
    });

    const targetId = window.currentMatchedCustomerId || '';

    if (targetId) {
        console.log('Applying target customer selection:', targetId);
        quickAddDropdown.value = targetId;
        if (mainDropdown) mainDropdown.value = targetId;
        updateHistoryBadge(targetId);
    } else {
        updateHistoryBadge('');
    }
}

function updateDropdownSelection(customerId, customerName) {
    const idToSelect = customerId ? String(customerId) : '';
    const quickAddDropdown = document.getElementById('customer-quick-add');
    if (quickAddDropdown) {
        quickAddDropdown.value = idToSelect;
        console.log(`Dropdown updated to customer ID: ${idToSelect}, Name: ${customerName}`);
        updateHistoryBadge(customerName);
    }

    const mainDropdown = document.getElementById('current-customer');
    if (mainDropdown) {
        mainDropdown.value = idToSelect;
    }
}

function updateCustomerSelection(customer) {
    const dropdown = document.getElementById('current-customer');

    if (!dropdown) {
        console.log('current-customer dropdown not found, skipping update');
        return;
    }

    if (customer.id && customer.name) {
        const tllDiv = document.getElementById('last-scan-duration');
        if (tllDiv) {
            if (customer.metadata && customer.metadata.last_scan_duration) {
                tllDiv.textContent = 'TLL: ' + customer.metadata.last_scan_duration;
                tllDiv.classList.remove('hidden');
            } else {
                tllDiv.classList.add('hidden');
            }
        }

        let customerExists = false;
        for (let option of dropdown.options) {
            if (option.value === customer.id) {
                option.textContent = `${customer.name} (${customer.confidence.toFixed(2)} confidence)`;
                customerExists = true;
                break;
            }
        }

        if (!customerExists) {
            const option = document.createElement('option');
            option.value = customer.id;
            option.textContent = `${customer.name} (Manual Assignment)`;
            dropdown.appendChild(option);
        }

        dropdown.value = customer.id;
    } else {
        dropdown.value = '';
    }
}

function displayCustomerList(customers) {
    const customerList = customers.map(c =>
        `${c.name || c.get?.('name')} (ID: ${c.id || c.get?.('id')})`
    ).join('\n');

    showCustomerMessage(`Configured Customers:\n${customerList}`, 'info');
}

window.showCustomerForm = showCustomerForm;
window.hideCustomerForm = hideCustomerForm;
window.showCustomerMessage = showCustomerMessage;
window.populateCustomerDropdown = populateCustomerDropdown;
window.updateDropdownSelection = updateDropdownSelection;
window.updateCustomerSelection = updateCustomerSelection;
window.displayCustomerList = displayCustomerList;
