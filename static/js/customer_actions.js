function addCustomer() {
    const customerData = {
        name: document.getElementById('cust-name').value,
        id: document.getElementById('cust-id').value,
        description: document.getElementById('cust-description').value,
        location: document.getElementById('cust-location').value,
        connection_type: document.getElementById('cust-connection-type').value,
        gateway_pattern: document.getElementById('cust-gateway').value,
        exit_pattern: document.getElementById('cust-exit-pattern').value,
        hop_count: document.getElementById('cust-hop-count').value,
        private_ranges: document.getElementById('cust-private-ranges').value,
        confidence: 0.7
    };

    document.getElementById('cust-name').value = '';
    document.getElementById('cust-id').value = '';
    document.getElementById('cust-description').value = '';
    document.getElementById('cust-location').value = '';
    document.getElementById('cust-gateway').value = '';
    document.getElementById('cust-exit-pattern').value = '';
    document.getElementById('cust-hop-count').value = '';
    document.getElementById('cust-private-ranges').value = '';

    hideCustomerForm();
    window.customerSocket.emit('add_customer', customerData);
}

function assignCustomer() {
    const dropdown = document.getElementById('current-customer');
    const selectedId = dropdown.value;
    const selectedOption = dropdown.options[dropdown.selectedIndex];
    const selectedName = selectedOption?.textContent || '';

    if (!selectedId) {
        showCustomerMessage('Please select a customer to assign', 'error');
        return;
    }

    const cleanName = selectedName.split(' (')[0];

    window.customerSocket.emit('assign_customer', {
        customer_id: selectedId,
        customer_name: cleanName
    });
}

function showCustomerList() {
    window.customerSocket.emit('get_customers');
}

function initializeCustomerActions(socket) {
    window.customerSocket = socket;

    document.getElementById('customer-quick-add').addEventListener('change', function() {
        const selectedId = this.value;
        const selectedOption = this.options[this.selectedIndex];
        const selectedName = selectedOption?.textContent || '';

        updateHistoryBadge(selectedName);

        if (selectedId) {
            socket.emit('assign_customer', {
                customer_id: selectedId,
                customer_name: selectedName
            });
        }
    });

    socket.on('customers_list', data => {
        console.log('customers_list event received with data:', data);
        populateCustomerDropdown(data);
        socket.emit('get_customer_info');
    });

    socket.on('customer_info', data => {
        console.log('Customer info received:', data);
        window.currentMatchedCustomerId = data.id ? String(data.id) : '';
        updateCustomerSelection(data);
        updateDropdownSelection(window.currentMatchedCustomerId, data.name);

        if (data.id && data.id !== 'unknown') {
            socket.emit('check_resumable_scan', {
                customer_id: data.id,
                max_days: 7
            });
        }
    });

    socket.on('customer_added', data => {
        if (data.success) {
            showCustomerMessage(data.message, 'success');
            socket.emit('get_customers');
        } else {
            showCustomerMessage('Failed to add customer', 'error');
        }
    });

    socket.on('customer_assigned', data => {
        if (data.success) {
            showCustomerMessage(data.message, 'success');
            updateDropdownSelection(data.customer.id, data.customer.name);
        } else {
            showCustomerMessage('Failed to assign customer', 'error');
        }
    });

    socket.on('customer_identified', data => {
        console.log('Customer identified:', data);
        if (data.customer && data.customer.id) {
            window.currentMatchedCustomerId = String(data.customer.id);
            updateDropdownSelection(data.customer.id, data.customer.name);

            if (data.customer.confidence !== undefined) {
                console.log(`Customer detected with ${(data.customer.confidence * 100).toFixed(0)}% confidence via ${data.match_method}`);
            }

            if (data.customer.id !== 'unknown') {
                socket.emit('check_resumable_scan', {
                    customer_id: data.customer.id,
                    max_days: 7
                });
            }
        }
    });

    socket.on('customer_deleted', data => {
        if (data.success) {
            showCustomerMessage(data.message, 'success');
            socket.emit('get_customers');
        } else {
            showCustomerMessage('Failed to delete customer', 'error');
        }
    });

    socket.on('customer_error', message => {
        showCustomerMessage(message, 'error');
    });
}

window.addCustomer = addCustomer;
window.assignCustomer = assignCustomer;
window.showCustomerList = showCustomerList;
window.initializeCustomerActions = initializeCustomerActions;
