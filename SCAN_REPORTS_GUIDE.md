# Scan Report Generation & Historical Viewer Guide

## Overview

This guide covers the new comprehensive scan report generation and historical viewing features added to NmapUI.

## Features Added

### 1. Comprehensive Report Export
- **XML Output**: Complete nmap scan data in XML format
- **HTML Reports**: Professional web-based reports using XSL stylesheet transformation
- **PDF Conversion**: Portable documents generated from HTML reports
- **Organized Storage**: Hierarchical folder structure by customer and date
- **Metadata Tracking**: JSON metadata for each scan including customer info and network fingerprint

### 2. Historical Scan Viewer
- **Browse Scans**: View all saved scans with filtering
- **Customer Filter**: Filter scans by customer name
- **Date Filter**: Filter scans by date
- **View Reports**: Open HTML reports directly in browser
- **Download PDFs**: Download PDF versions of reports
- **Manage Scans**: Delete old scans

### 3. Enhanced Nmap Scanning
- **Vulners Integration**: Automatic CVE detection with vulners NSE script
- **Multiple Output Formats**: XML, nmap text, and gnmap formats
- **Comprehensive Options**: -sS -T4 -A -sC for thorough scanning

## File Structure

Reports are organized in a hierarchical structure:

```
data/scans/
├── CustomerName_1/
│   ├── 2026-01-08/
│   │   ├── scan_143022_192.168.1.0_24/
│   │   │   ├── scan.xml          # Raw nmap XML output
│   │   │   ├── scan.nmap         # Human-readable nmap output
│   │   │   ├── scan.gnmap        # Grepable nmap output
│   │   │   ├── scan.html         # Styled HTML report
│   │   │   ├── scan_report.pdf   # PDF version
│   │   │   └── metadata.json     # Scan metadata
│   │   └── scan_151530_10.0.0.0_16/
│   └── 2026-01-09/
└── CustomerName_2/
    └── 2026-01-08/
```

### Filename Convention
- **Folder**: `scan_HHMMSS_AddressRange`
  - Example: `scan_143022_192.168.1.0_24`
  - Example: `scan_151530_10.0.0.0_16`

## Using the Report Generator

### Step 1: Run a Scan
1. Enter target IP, range, or CIDR in the scan input field
2. Click **Start Scan**
3. Wait for scan to complete (Quick Scan → ARP Scan → Deep Scan)

### Step 2: Generate Report
1. Click the **Generate Report** button (blue button with download icon)
2. Watch the status message for progress
3. Report will be generated with all formats (XML, HTML, PDF)
4. Success message will show the save location

### Report Generation Process
The system will:
1. Create organized folder structure based on customer and date
2. Run comprehensive nmap scan with:
   ```bash
   sudo nmap -sS -T4 -A -sC --script vulners.nse -oA output <target>
   ```
3. Convert XML to HTML using XSL stylesheet
4. Convert HTML to PDF using wkhtmltopdf
5. Save metadata with customer and network information

## Using the Historical Viewer

### Opening the Viewer
Click the **View History** button (purple button with clock icon)

### Filtering Scans
- **Customer Filter**: Select customer from dropdown to show only their scans
- **Date Filter**: Pick a date to show only scans from that day
- **Refresh**: Click to reload the scan list

### Viewing Reports
- **View HTML**: Click to open the HTML report in a new browser tab
- **Download PDF**: Click to download the PDF report
- **Delete**: Remove a scan (requires confirmation)

### Report Actions
Each scan in the history shows:
- Customer name
- Scan timestamp
- Target address/range
- Available report formats (HTML/PDF buttons)

## API Endpoints

For programmatic access:

### Get All Scans
```
GET /api/scans
```
Returns JSON array of all saved scans with metadata

### View HTML Report
```
GET /api/scans/<customer>/<date>/<scan_name>/html
```
Serves the HTML report file

### Download PDF Report
```
GET /api/scans/<customer>/<date>/<scan_name>/pdf
```
Downloads the PDF report file

### Delete Scan
```
DELETE /api/scans/<customer>/<date>/<scan_name>
```
Deletes the entire scan folder

## SocketIO Events

### Emit: generate_report
```javascript
socket.emit('generate_report', {
    target: '192.168.1.0/24',
    customer_name: 'TechCorp',
    scan_results: { /* optional scan data */ }
});
```

### Listen: report_generating
```javascript
socket.on('report_generating', function(data) {
    console.log(data.status); // "Starting report generation..."
});
```

### Listen: report_complete
```javascript
socket.on('report_complete', function(data) {
    console.log(data.path);     // Relative path to scan
    console.log(data.scan_dir); // Absolute path to scan directory
});
```

### Listen: report_error
```javascript
socket.on('report_error', function(data) {
    console.error(data.error);
});
```

## Configuration

### XSL Stylesheet Path
Update in `app.py` if your stylesheet is in a different location:
```python
XSL_STYLESHEET = Path("/path/to/your/nmap-modern.xsl")
```

### Scans Directory
Default location is `data/scans/`. To change:
```python
SCANS_DIR = BASE_DIR / "your" / "custom" / "path"
```

## Troubleshooting

### PDF Generation Fails
**Error**: "wkhtmltopdf not found"
**Solution**: Install wkhtmltopdf:
```bash
# macOS
brew install wkhtmltopdf

# Ubuntu/Debian
sudo apt install wkhtmltopdf

# Or use Python alternative
pip install weasyprint
```

### HTML Conversion Fails
**Error**: "XSL stylesheet not found"
**Solution**:
1. Verify the XSL file exists at the path specified in `app.py`
2. Update `XSL_STYLESHEET` variable if needed
3. Ensure xsltproc is installed: `which xsltproc`

### No Scans Appear in History
**Check**:
1. Verify scans directory exists: `data/scans/`
2. Check folder permissions
3. Look for `metadata.json` files in scan folders
4. Check browser console for JavaScript errors

### Report Generation Times Out
**Solution**:
- Reduce scan range (scan smaller subnets)
- Increase timeout in `run_nmap_with_xml_output()` (default: 600s)
- Split large ranges into multiple scans

## Security Considerations

### Sudo Requirements
Report generation uses `nmap -sS` which requires root privileges:
- The script checks if running as root
- If not root, it prepends `sudo` to the command
- Ensure passwordless sudo is configured or run the app with sudo

### File Permissions
Scan reports may contain sensitive information:
- Restrict access to `data/scans/` directory
- Consider encrypting stored reports
- Implement user authentication for the web interface

### Network Scanning
- Only scan networks you have permission to scan
- Be aware of IDS/IPS systems that may detect scans
- Review your organization's security policies

## Advanced Usage

### Custom Scan Commands
To customize the nmap command used for report generation, edit the `run_nmap_with_xml_output()` function in `app.py`:

```python
cmd = [
    "nmap",
    "-sS",  # Modify scan type
    "-T4",  # Adjust timing
    "-A",   # Enable/disable aggressive scan
    "-sC",  # Enable/disable default scripts
    "--script", str(VULNERS_SCRIPT),  # Add/remove scripts
    "-oA", str(output_base),
    target
]
```

### Integrating with CI/CD
Use the API endpoints to integrate scan reports into your CI/CD pipeline:

```bash
# Generate report
curl -X POST http://localhost:5000/api/generate_report \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "customer_name": "CI Pipeline"}'

# Download latest PDF
curl -o report.pdf http://localhost:5000/api/scans/CI_Pipeline/2026-01-08/scan_143022_192.168.1.0_24/pdf
```

## Tips & Best Practices

1. **Regular Cleanup**: Delete old scans periodically to save disk space
2. **Naming Convention**: Use consistent customer names for better organization
3. **Scan Scheduling**: Generate reports at the end of each business day
4. **Backup Reports**: Archive important scan reports to external storage
5. **Documentation**: Add notes to metadata.json for important findings
6. **Compare Scans**: Keep historical scans to track changes over time
7. **PDF Sharing**: Use PDF format for sharing with non-technical stakeholders

## Support

For issues, feature requests, or questions:
- Check the main README.md
- Review this guide
- Check application logs
- Verify all dependencies are installed

## Version History

### v2.0 (2026-01-08)
- Added comprehensive report generation with XML/HTML/PDF
- Added historical scan viewer with filtering
- Added organized folder structure by customer/date
- Added metadata tracking for scans
- Integrated vulners script into report generation
- Added REST API endpoints for scan management
