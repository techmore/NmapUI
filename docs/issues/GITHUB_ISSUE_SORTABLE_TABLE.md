# GitHub Issue: Feature Request - Sortable Table Headers for Asset Discovery

## Title: Feature: Sortable Table Headers for Asset Discovery Table

## Summary:
- Add clickable sorting functionality to all asset discovery table headers
- Support ascending/descending sort for different data types (IP addresses, strings, numbers)
- Provide visual indicators for current sort column and direction
- Maintain sort state across table updates and page refreshes

## Problem Statement:
The asset discovery table displays network scan results in a tabular format, but users cannot easily organize or find specific devices. With potentially hundreds of discovered assets, the lack of sorting capability makes it difficult to:

- Find devices by IP address range
- Locate hosts by hostname alphabetically
- Identify devices with most open ports
- Sort by vendor or service information
- Organize results by any meaningful criteria

Users must manually scan through potentially large lists to find specific information, reducing efficiency and user experience.

## Proposed Solution:

### 1. Sortable Column Headers
- Make all table headers clickable for sorting
- Support multiple data types with appropriate sorting logic
- Visual indicators for sort direction (up/down arrows)
- Highlight currently sorted column

### 2. Sorting Logic Implementation
- **IP Addresses**: Proper numerical sorting (192.168.1.10 < 192.168.1.100)
- **Hostnames**: Alphabetical sorting (case-insensitive)
- **MAC Addresses**: Hexadecimal sorting
- **Open Ports**: Numerical count sorting
- **Vendors/Services**: Alphabetical sorting
- **CVEs**: Severity/count based sorting

### 3. Sort State Persistence
- Remember sort preferences across page refreshes
- Maintain sort state during live updates
- Store preferences in localStorage for consistency

### 4. User Experience Enhancements
- Clear visual feedback for sortable columns
- Smooth animations during sort operations
- Keyboard accessibility (Enter/Space to sort)
- Multi-column sort support (optional advanced feature)

## Implementation Details:

### Frontend Changes (templates/index.html)
1. **Enhanced Table Headers**
   ```html
   <thead>
       <tr>
           <th class="sortable px-4 py-3 text-left cursor-pointer hover:bg-olive-100 transition-colors group" data-column="status" data-type="text">
               <div class="flex items-center space-x-1">
                   <span>Status</span>
                   <div class="sort-indicators opacity-0 group-hover:opacity-100 transition-opacity">
                       <svg class="w-3 h-3 text-olive-400 sort-asc" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                           <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/>
                       </svg>
                       <svg class="w-3 h-3 text-olive-400 sort-desc" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                           <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                       </svg>
                   </div>
               </div>
           </th>
           <th class="sortable px-4 py-3 text-left cursor-pointer hover:bg-olive-100 transition-colors group" data-column="ip" data-type="ip">
               <div class="flex items-center space-x-1">
                   <span>IP Address</span>
                   <div class="sort-indicators opacity-0 group-hover:opacity-100 transition-opacity">
                       <svg class="w-3 h-3 text-olive-400 sort-asc" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                           <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/>
                       </svg>
                       <svg class="w-3 h-3 text-olive-400 sort-desc" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                           <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                       </svg>
                   </div>
               </div>
           </th>
           <!-- Similar structure for MAC, Vendor, Hostname, Ports, Version, CVEs -->
       </tr>
   </thead>
   ```

2. **Sorting Logic Implementation**
   ```javascript
   class TableSorter {
       constructor(tableId) {
           this.table = document.getElementById(tableId);
           this.currentSort = { column: null, direction: 'asc' };
           this.sortFunctions = {
               'ip': this.sortIPAddresses.bind(this),
               'mac': this.sortMACAddresses.bind(this),
               'text': this.sortText.bind(this),
               'number': this.sortNumbers.bind(this),
               'ports': this.sortPortCount.bind(this)
           };
           this.initializeSorting();
           this.loadSortState();
       }

       initializeSorting() {
           const headers = this.table.querySelectorAll('.sortable');
           headers.forEach(header => {
               header.addEventListener('click', () => this.sortByColumn(header));
               header.addEventListener('keydown', (e) => {
                   if (e.key === 'Enter' || e.key === ' ') {
                       e.preventDefault();
                       this.sortByColumn(header);
                   }
               });
               header.setAttribute('tabindex', '0');
           });
       }

       sortByColumn(header) {
           const column = header.dataset.column;
           const type = header.dataset.type;

           // Toggle sort direction if same column, otherwise default to ascending
           if (this.currentSort.column === column) {
               this.currentSort.direction = this.currentSort.direction === 'asc' ? 'desc' : 'asc';
           } else {
               this.currentSort.column = column;
               this.currentSort.direction = 'asc';
           }

           this.sortTable(column, type, this.currentSort.direction);
           this.updateVisualIndicators(header);
           this.saveSortState();
       }

       sortTable(column, type, direction) {
           const tbody = this.table.querySelector('tbody');
           const rows = Array.from(tbody.querySelectorAll('tr'));

           rows.sort((a, b) => {
               const aValue = this.getCellValue(a, column);
               const bValue = this.getCellValue(b, column);

               const sortFn = this.sortFunctions[type] || this.sortFunctions.text;
               const result = sortFn(aValue, bValue);

               return direction === 'asc' ? result : -result;
           });

           // Reorder DOM elements
           rows.forEach(row => tbody.appendChild(row));
       }

       sortIPAddresses(a, b) {
           // Convert IP addresses to comparable numbers
           const aParts = a.split('.').map(Number);
           const bParts = b.split('.').map(Number);

           for (let i = 0; i < 4; i++) {
               if (aParts[i] !== bParts[i]) {
                   return aParts[i] - bParts[i];
               }
           }
           return 0;
       }

       sortMACAddresses(a, b) {
           // Remove colons and compare as hex
           const aHex = a.replace(/:/g, '');
           const bHex = b.replace(/:/g, '');
           return parseInt(aHex, 16) - parseInt(bHex, 16);
       }

       sortText(a, b) {
           return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
       }

       sortNumbers(a, b) {
           return parseFloat(a) - parseFloat(b);
       }

       sortPortCount(a, b) {
           // Extract port count from "80/tcp, 443/tcp, 22/tcp" format
           const aCount = a.split(',').length;
           const bCount = b.split(',').length;
           return aCount - bCount;
       }

       getCellValue(row, column) {
           const columnIndex = this.getColumnIndex(column);
           const cell = row.cells[columnIndex];
           return cell ? cell.textContent.trim() : '';
       }

       getColumnIndex(column) {
           // Map column names to table indices
           const columnMap = {
               'status': 0,
               'ip': 1,
               'mac': 2,
               'vendor': 3,
               'hostname': 4,
               'open_ports': 5,
               'version': 6,
               'cves': 7
           };
           return columnMap[column] || 0;
       }

       updateVisualIndicators(activeHeader) {
           // Clear all indicators
           this.table.querySelectorAll('.sortable').forEach(header => {
               header.classList.remove('sorted-asc', 'sorted-desc');
           });

           // Set active indicator
           const directionClass = this.currentSort.direction === 'asc' ? 'sorted-asc' : 'sorted-desc';
           activeHeader.classList.add(directionClass);
       }

       saveSortState() {
           const state = {
               column: this.currentSort.column,
               direction: this.currentSort.direction,
               timestamp: Date.now()
           };
           localStorage.setItem('tableSortState', JSON.stringify(state));
       }

       loadSortState() {
           try {
               const state = JSON.parse(localStorage.getItem('tableSortState'));
               if (state && state.column) {
                   this.currentSort = state;
                   // Apply saved sort
                   const header = this.table.querySelector(`[data-column="${state.column}"]`);
                   if (header) {
                       this.sortTable(state.column, header.dataset.type, state.direction);
                       this.updateVisualIndicators(header);
                   }
               }
           } catch (e) {
               console.warn('Failed to load sort state:', e);
           }
       }
   }

   // Initialize table sorter when DOM is ready
   document.addEventListener('DOMContentLoaded', () => {
       new TableSorter('discovery-table');
   });
   ```

### CSS Enhancements
```css
.sortable {
    user-select: none;
}

.sortable:hover .sort-indicators {
    opacity: 1 !important;
}

.sorted-asc .sort-asc {
    color: #065f46; /* olive-800 */
}

.sorted-desc .sort-desc {
    color: #065f46; /* olive-800 */
}

.sort-indicators {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-left: 0.25rem;
}

.sort-asc, .sort-desc {
    transition: color 0.2s ease;
}
```

## User Experience Flow:

### Basic Sorting
1. User clicks on any table header
2. Table sorts by that column in ascending order
3. Visual indicator shows sort direction
4. Clicking same header toggles between ascending/descending

### Advanced Interactions
1. Sort state persists across page refreshes
2. Keyboard navigation support (Tab, Enter, Space)
3. Smooth visual transitions during sorting
4. Sort preferences saved in browser localStorage

### Data Type Handling
- **IP Addresses**: 192.168.1.10 sorts before 192.168.1.100
- **MAC Addresses**: Proper hexadecimal sorting
- **Hostnames**: Case-insensitive alphabetical
- **Port Lists**: Sorted by number of open ports
- **Empty Values**: Handled gracefully (empty strings sort last)

## Benefits:
1. **Improved Navigation**: Quickly find devices in large networks
2. **Better Organization**: Sort by any relevant criteria
3. **Enhanced Productivity**: Faster identification of target devices
4. **Professional UX**: Standard table interaction expectations
5. **Accessibility**: Keyboard navigation and screen reader support

## Acceptance Criteria:
1. ✅ All table headers are clickable and sortable
2. ✅ Visual indicators show current sort column and direction
3. ✅ IP addresses sort numerically (192.168.1.10 < 192.168.1.100)
4. ✅ Different data types sort appropriately (text, numbers, IPs, MACs)
5. ✅ Sort state persists across page refreshes
6. ✅ Keyboard accessibility (Enter/Space to sort)
7. ✅ Smooth animations during sort operations
8. ✅ Works with dynamic table updates (live scan results)
9. ✅ Handles empty/null values gracefully
10. ✅ Performance optimized for large tables (100+ rows)

## Technical Notes:
- Uses efficient Array.sort() with custom comparers
- DOM manipulation is optimized to minimize reflows
- localStorage for persistence with error handling
- Event delegation for dynamic table updates
- Progressive enhancement (works without JavaScript)

## Performance Considerations:
- Sorting large datasets (1000+ rows) should complete in <500ms
- Memory usage remains constant during sort operations
- No impact on scan performance or real-time updates
- Debounced sort operations if needed for very large tables

---

## Implementation Priority: Medium
This provides significant UX improvement for asset management with moderate development effort.

## Related Files:
- `templates/index.html` (table structure and JavaScript)
- CSS styling for sort indicators

## Browser Compatibility:
- Modern browsers with Array.sort() and localStorage support
- Graceful degradation for older browsers
- Touch-friendly for mobile/tablet interfaces

This feature transforms the asset discovery table from a static display into an interactive data exploration tool, significantly improving the user experience for network analysis and device management.