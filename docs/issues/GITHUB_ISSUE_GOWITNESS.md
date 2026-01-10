# GitHub Issue: Feature Request - GoWitness Integration for Web Service Screenshots

## Title: Feature: GoWitness Integration for Web Service Screenshots with MD5 Hashing

## Summary:
- Integrate GoWitness tool to automatically capture screenshots of discovered HTTP/HTTPS services
- Generate MD5 hashes for screenshot integrity verification
- Display screenshots in the asset discovery table
- Trigger screenshot capture after Nmap scan completion for web-enabled ports

## Problem Statement:
When scanning networks, Nmap discovers many devices with open HTTP/HTTPS ports (80, 443, 8080, etc.), but users have no visual way to see what these web services actually look like. Without screenshots, it's difficult to:

- Quickly identify what type of web service is running
- Distinguish between different web applications
- Verify service functionality visually
- Document web interfaces for security assessments
- Provide visual evidence of discovered services

GoWitness is the perfect tool for this - it's a web screenshot utility that can capture screenshots of web services discovered during network scans.

## Proposed Solution:

### 1. GoWitness Integration
- Automatically detect HTTP/HTTPS ports from Nmap results
- Generate target list for GoWitness (format: `http://ip:port` or `https://ip:port`)
- Execute GoWitness after Nmap scan completion
- Process and store screenshot results

### 2. Screenshot Management
- Save screenshots with descriptive filenames
- Generate MD5 hashes for integrity verification
- Organize screenshots by IP address and port
- Compress/archive screenshots for storage efficiency

### 3. Frontend Display Integration
- Add screenshot column to asset discovery table
- Display thumbnail images inline with device information
- Provide modal/full-size image viewing
- Show screenshot capture status and timestamps

### 4. Hash Verification & Security
- Generate MD5 hashes for all screenshots
- Store hashes for integrity verification
- Provide hash comparison for duplicate detection
- Secure storage of screenshot files

## Implementation Details:

### Backend Changes (app.py)
1. **GoWitness Integration Service**
   ```python
   class GoWitnessService:
       def __init__(self):
           self.gowitness_path = self.find_gowitness_binary()
           self.screenshot_dir = BASE_DIR / "data" / "screenshots"
           self.screenshot_dir.mkdir(exist_ok=True)

       def find_gowitness_binary(self):
           """Locate GoWitness binary in system PATH"""
           return shutil.which("gowitness") or (BASE_DIR / "gowitness" / "gowitness")

       def generate_targets_from_scan(self, scan_results):
           """Extract HTTP/HTTPS targets from Nmap scan results"""
           targets = []

           for host in scan_results:
               ip = host.get('ip')
               for port_info in host.get('ports', []):
                   port = port_info.get('port')
                   service = port_info.get('service', '').lower()

                   # Check for HTTP-related services
                   if service in ['http', 'https', 'http-alt', 'http-proxy'] or port in ['80', '443', '8080', '8443']:
                       protocol = 'https' if port in ['443', '8443'] or service == 'https' else 'http'
                       targets.append(f"{protocol}://{ip}:{port}")

           return targets

       def capture_screenshots(self, targets):
           """Execute GoWitness to capture screenshots"""
           if not self.gowitness_path:
               logger.warning("GoWitness binary not found, skipping screenshot capture")
               return []

           # Create temporary target file
           target_file = self.screenshot_dir / f"targets_{int(time.time())}.txt"
           with open(target_file, 'w') as f:
               f.write('\n'.join(targets))

           # Execute GoWitness
           cmd = [
               self.gowitness_path,
               "file",
               "-f", str(target_file),
               "-d", str(self.screenshot_dir),
               "--timeout", "30",
               "--delay", "5",
               "--user-agent", "NmapUI-Security-Scanner/1.0"
           ]

           try:
               result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
               if result.returncode == 0:
                   logger.info(f"GoWitness captured {len(targets)} screenshots")
                   return self.process_screenshots(targets)
               else:
                   logger.error(f"GoWitness failed: {result.stderr}")
                   return []
           except subprocess.TimeoutExpired:
               logger.error("GoWitness timed out")
               return []
           finally:
               # Clean up target file
               target_file.unlink(missing_ok=True)

       def process_screenshots(self, targets):
           """Process captured screenshots and generate metadata"""
           screenshots = []

           for target in targets:
               # GoWitness saves files as URL-encoded filenames
               url_encoded = target.replace('://', '_').replace('/', '_').replace(':', '_')
               screenshot_path = self.screenshot_dir / f"{url_encoded}.png"

               if screenshot_path.exists():
                   # Generate MD5 hash
                   md5_hash = self.generate_md5(screenshot_path)

                   # Extract target info
                   ip, port = self.parse_target(target)

                   screenshots.append({
                       'ip': ip,
                       'port': port,
                       'target_url': target,
                       'screenshot_path': str(screenshot_path.relative_to(BASE_DIR)),
                       'md5_hash': md5_hash,
                       'captured_at': datetime.now().isoformat(),
                       'file_size': screenshot_path.stat().st_size
                   })

           return screenshots

       def generate_md5(self, file_path):
           """Generate MD5 hash for file integrity"""
           hash_md5 = hashlib.md5()
           with open(file_path, "rb") as f:
               for chunk in iter(lambda: f.read(4096), b""):
                   hash_md5.update(chunk)
           return hash_md5.hexdigest()

       def parse_target(self, target):
           """Parse target URL to extract IP and port"""
           # Remove protocol
           without_protocol = target.split('://')[1]
           ip_port = without_protocol.split('/')[0]  # Remove path if any
           ip, port = ip_port.rsplit(':', 1)
           return ip, port
   ```

2. **Integration with Scan Workflow**
   ```python
   # After scan completion in start_scan()
   if scan_results:
       # Start GoWitness screenshot capture in background
       socketio.start_background_task(capture_screenshots_async, scan_results)
   ```

3. **New Socket Events**
   - `screenshots_capturing` - Signal screenshot capture start
   - `screenshots_progress` - Show capture progress
   - `screenshots_complete` - Send screenshot results to UI
   - `screenshot_error` - Handle capture failures

### Frontend Changes (templates/index.html)
1. **Enhanced Table with Screenshots**
   ```html
   <thead>
       <tr>
           <th class="px-4 py-3 text-left">Status</th>
           <th class="px-4 py-3 text-left">IP Address</th>
           <th class="px-4 py-3 text-left hidden md:table-cell">MAC Address</th>
           <th class="px-4 py-3 text-left hidden lg:table-cell">Vendor</th>
           <th class="px-4 py-3 text-left max-w-[150px]">Hostname</th>
           <th class="px-4 py-3 text-left">Open Ports</th>
           <th class="px-4 py-3 text-left">Version</th>
           <th class="px-4 py-3 text-left">CVEs</th>
           <th class="px-4 py-3 text-left">Web Preview</th>
           <th class="px-4 py-3 text-left">Actions</th>
       </tr>
   </thead>
   ```

2. **Screenshot Display Logic**
   ```javascript
   function addScreenshotToRow(ip, screenshots) {
       const rows = document.querySelectorAll('#discovery-table tbody tr');
       for (let row of rows) {
           if (row.cells[1].textContent === ip) { // IP column
               const screenshotCell = row.cells[8]; // Web Preview column

               // Find screenshots for this IP
               const ipScreenshots = screenshots.filter(s => s.ip === ip);

               if (ipScreenshots.length > 0) {
                   screenshotCell.innerHTML = ipScreenshots.map(screenshot => `
                       <div class="screenshot-container mb-2">
                           <div class="relative group cursor-pointer" onclick="showScreenshotModal('${screenshot.screenshot_path}', '${screenshot.target_url}', '${screenshot.md5_hash}')">
                               <img src="/api/screenshots/${screenshot.screenshot_path.split('/').pop()}"
                                    alt="Screenshot of ${screenshot.target_url}"
                                    class="w-16 h-12 object-cover rounded border border-olive-200 hover:border-olive-400 transition-colors">
                               <div class="absolute inset-0 bg-black bg-opacity-0 group-hover:bg-opacity-20 transition-all rounded flex items-center justify-center">
                                   <svg class="w-4 h-4 text-white opacity-0 group-hover:opacity-100" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                       <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                                   </svg>
                               </div>
                           </div>
                           <div class="text-xs text-olive-600 mt-1">
                               Port ${screenshot.port}
                           </div>
                       </div>
                   `).join('');
               } else {
                   screenshotCell.innerHTML = '<span class="text-olive-400 text-xs">No web services</span>';
               }
               break;
           }
       }
   }

   function showScreenshotModal(imagePath, url, md5Hash) {
       const modal = document.createElement('div');
       modal.className = 'fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4';
       modal.innerHTML = `
           <div class="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-auto">
               <div class="p-6">
                   <div class="flex justify-between items-center mb-4">
                       <h3 class="text-lg font-semibold text-olive-900">Web Service Screenshot</h3>
                       <button onclick="this.closest('.fixed').remove()" class="text-olive-500 hover:text-olive-700">
                           <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                               <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                           </svg>
                       </button>
                   </div>
                   <div class="mb-4">
                       <div class="text-sm text-olive-600 mb-2">URL: <code class="bg-olive-100 px-2 py-1 rounded">${url}</code></div>
                       <div class="text-sm text-olive-600">MD5: <code class="bg-olive-100 px-2 py-1 rounded font-mono text-xs">${md5Hash}</code></div>
                   </div>
                   <img src="/api/screenshots/${imagePath.split('/').pop()}" alt="Full-size screenshot" class="w-full rounded border border-olive-200">
               </div>
           </div>
       `;
       document.body.appendChild(modal);
   }
   ```

3. **Screenshot API Endpoint**
   ```python
   @app.route("/api/screenshots/<filename>")
   def get_screenshot(filename):
       """Serve screenshot images"""
       screenshot_dir = BASE_DIR / "data" / "screenshots"
       file_path = screenshot_dir / filename

       if file_path.exists() and file_path.suffix.lower() == '.png':
           return send_file(file_path, mimetype='image/png')
       else:
           return "Screenshot not found", 404
   ```

### Data Structure for Screenshots
```json
{
  "screenshots": [
    {
      "ip": "192.168.1.100",
      "port": "80",
      "target_url": "http://192.168.1.100:80",
      "screenshot_path": "data/screenshots/http_192_168_1_100_80.png",
      "md5_hash": "a1b2c3d4e5f678901234567890abcdef",
      "captured_at": "2026-01-09T14:30:45Z",
      "file_size": 245760,
      "gowitness_version": "2.4.1"
    }
  ]
}
```

## User Experience Flow:

### Automatic Screenshot Capture
1. User completes Nmap scan (quick + deep scan)
2. System automatically detects HTTP/HTTPS ports
3. GoWitness launches in background to capture screenshots
4. Progress indicators show screenshot capture status
5. Screenshots appear in table once capture completes

### Visual Asset Discovery
1. User sees thumbnail images in "Web Preview" column
2. Hover shows full URL and port information
3. Click thumbnail opens modal with full-size image
4. MD5 hash displayed for integrity verification
5. Multiple screenshots per IP (different ports) stacked vertically

### Screenshot Management
1. Screenshots stored with descriptive filenames
2. MD5 hashes ensure file integrity
3. Automatic cleanup of old screenshots (configurable)
4. Error handling for failed captures

## Benefits:
1. **Visual Service Identification**: Instantly see what web services look like
2. **Enhanced Security Assessment**: Visual evidence of discovered services
3. **Improved Documentation**: Screenshots for reports and compliance
4. **Faster Reconnaissance**: Quick visual overview of web landscape
5. **Integrity Verification**: MD5 hashes ensure screenshot authenticity

## Acceptance Criteria:
1. ✅ GoWitness automatically detects HTTP/HTTPS ports from scan results
2. ✅ Screenshots captured with configurable timeout and user-agent
3. ✅ MD5 hashes generated and stored for all screenshots
4. ✅ Thumbnail images displayed in asset discovery table
5. ✅ Modal viewer for full-size screenshot examination
6. ✅ Screenshot capture runs after Nmap scan completion
7. ✅ Error handling for failed captures and timeouts
8. ✅ Secure storage and access to screenshot files
9. ✅ Performance optimized (doesn't slow down primary scanning)
10. ✅ Configurable cleanup of old screenshots

## Technical Requirements:
- **GoWitness Installation**: Binary available in system PATH or bundled
- **Dependencies**: PIL/Pillow for image processing (optional)
- **Storage**: Adequate disk space for screenshot storage
- **Network**: Access to discovered web services for screenshot capture
- **Security**: Proper file permissions and access controls

## Security Considerations:
- User-agent string identifies scanner for ethical disclosure
- Respect robots.txt and service terms
- Rate limiting to avoid overwhelming target services
- Secure storage of screenshot files
- MD5 hash verification prevents tampering

## Performance Optimizations:
- Parallel screenshot capture with configurable concurrency
- Timeout limits prevent hanging on slow/unresponsive services
- Compression options for storage efficiency
- Background processing doesn't impact scan performance
- Lazy loading of thumbnail images

---

## Implementation Priority: High
This provides significant value for web service discovery and security assessment.

## Related Tools:
- **GoWitness**: https://github.com/sensepost/gowitness
- **Installation**: `go install github.com/sensepost/gowitness@latest`

## Browser Compatibility:
- Thumbnail display works in all modern browsers
- Modal viewer with responsive design
- Fallback for browsers without JavaScript

This feature transforms network scanning from text-based discovery to visual reconnaissance, providing security professionals with immediate visual context for discovered web services.