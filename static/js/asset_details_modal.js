function renderAssetServices(asset) {
    const servicesContainer = document.getElementById('asset-detail-services');
    servicesContainer.replaceChildren();

    if (asset.open_ports && asset.open_ports.trim()) {
        const ports = asset.open_ports.split(',').map(p => p.trim()).filter(p => p);
        const versions = asset.version ? asset.version.split(',').map(v => v.trim()).filter(v => v) : [];
        const versionMap = {};
        versions.forEach(v => {
            const match = v.match(/^(\d+):(.*)/);
            if (match) versionMap[match[1]] = match[2];
        });

        ports.forEach(port => {
            const portMatch = port.match(/^(\d+)\s*\(?(.*?)\)?$/);
            if (!portMatch) return;

            const portNum = portMatch[1];
            const serviceName = portMatch[2] || 'unknown';
            const version = versionMap[portNum] || '';

            const serviceDiv = document.createElement('div');
            serviceDiv.className = 'flex items-start p-3 bg-white rounded border border-olive-200';

            const infoDiv = document.createElement('div');
            infoDiv.className = 'flex-shrink-0 w-20';
            const portSpan = document.createElement('span');
            portSpan.className = 'font-mono text-sm font-bold text-olive-900';
            portSpan.textContent = portNum;
            infoDiv.appendChild(portSpan);
            const serviceSpan = document.createElement('span');
            serviceSpan.className = 'text-xs text-olive-600';
            serviceSpan.textContent = `/${serviceName}`;
            infoDiv.appendChild(serviceSpan);
            serviceDiv.appendChild(infoDiv);

            const versionDiv = document.createElement('div');
            versionDiv.className = 'flex-1';
            const versionText = document.createElement('div');
            if (version) {
                versionText.className = 'text-sm text-olive-700';
                versionText.textContent = version;
            } else {
                versionText.className = 'text-xs text-olive-500 italic';
                versionText.textContent = 'No version detected';
            }
            versionDiv.appendChild(versionText);
            serviceDiv.appendChild(versionDiv);
            servicesContainer.appendChild(serviceDiv);
        });
        return;
    }

    const empty = document.createElement('p');
    empty.className = 'text-sm text-olive-500 italic';
    empty.textContent = 'No open ports detected';
    servicesContainer.appendChild(empty);
}

function renderAssetVulnerabilities(asset) {
    const cveContainer = document.getElementById('asset-detail-cves');
    cveContainer.replaceChildren();

    if (asset.vulnerabilities && asset.vulnerabilities.length > 0) {
        asset.vulnerabilities.forEach(vuln => {
            const cveDiv = document.createElement('div');
            cveDiv.className = 'p-3 bg-white rounded border border-olive-200';

            const header = document.createElement('div');
            header.className = 'flex items-start justify-between mb-2';
            const left = document.createElement('div');
            const title = document.createElement('span');
            title.className = 'font-mono text-sm font-bold text-red-700';
            title.textContent = vuln.id || 'Unknown CVE';
            left.appendChild(title);
            const meta = document.createElement('div');
            meta.className = 'text-xs text-olive-600 mt-1';
            meta.textContent = `Port ${vuln.port || 'N/A'} (${vuln.service || 'unknown'})`;
            left.appendChild(meta);
            header.appendChild(left);

            const score = document.createElement('span');
            score.className = 'inline-block px-2 py-1 rounded bg-red-100 text-red-700 font-medium text-xs';
            score.textContent = vuln.score || 'N/A';
            header.appendChild(score);
            cveDiv.appendChild(header);

            if (vuln.url) {
                const link = document.createElement('a');
                link.className = 'text-sm text-olive-600 hover:text-olive-800 hover:underline';
                link.textContent = 'View Details';
                if (setSafeExternalLink(link, vuln.url)) {
                    cveDiv.appendChild(link);
                }
            }
            cveContainer.appendChild(cveDiv);
        });
        return;
    }

    const empty = document.createElement('p');
    empty.className = 'text-sm text-olive-500 italic';
    empty.textContent = 'No vulnerabilities detected';
    cveContainer.appendChild(empty);
}

function showAssetDetailsModal(asset) {
    const modal = document.getElementById('asset-details-modal');

    document.getElementById('asset-detail-ip').textContent = asset.ip || 'Unknown';
    document.getElementById('asset-detail-hostname').textContent = asset.hostname ? `(${asset.hostname})` : '';
    document.getElementById('asset-detail-mac').textContent = asset.mac || 'N/A';
    document.getElementById('asset-detail-vendor').textContent = asset.vendor || 'Unknown';
    document.getElementById('asset-detail-status').textContent = asset.status || 'up';

    const vendorLink = document.getElementById('asset-vendor-link');
    if (asset.vendor && asset.vendor !== 'Unknown') {
        const vendorSearchUrl = `https://www.google.com/search?q=${encodeURIComponent(asset.vendor + ' company website')}`;
        vendorLink.href = vendorSearchUrl;
        vendorLink.classList.remove('hidden');
    } else {
        vendorLink.classList.add('hidden');
    }

    renderAssetServices(asset);

    const cveSection = document.getElementById('asset-cve-section');
    const cveCount = document.getElementById('asset-cve-count');

    if (asset.vulnerabilities && asset.vulnerabilities.length > 0) {
        cveCount.textContent = asset.vulnerabilities.length;
        cveSection.classList.remove('hidden');
    } else {
        cveSection.classList.add('hidden');
    }
    renderAssetVulnerabilities(asset);

    modal.classList.remove('hidden');
}

function closeAssetDetailsModal() {
    document.getElementById('asset-details-modal').classList.add('hidden');
}

window.renderAssetServices = renderAssetServices;
window.renderAssetVulnerabilities = renderAssetVulnerabilities;
window.showAssetDetailsModal = showAssetDetailsModal;
window.closeAssetDetailsModal = closeAssetDetailsModal;
