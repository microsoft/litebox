/**
 * Lock Viewer - Interactive timeline visualization for lock traces.
 */

// Global state
let allEvents = [];
let summary = null;
let uniqueLocks = new Set();
let selectedLocks = new Set();
let minTime = 0;
let maxTime = 0;
let minTimeWithDrops = 0;  // Time threshold accounting for dropped events
let commonPathPrefix = '';  // Common prefix to strip from file paths
let lockContention = {};   // Map of lock_addr -> contention duration in ns
let lockSourceFiles = {};  // Map of lock_addr -> first seen source file
let zoomLevel = 1;         // Timeline zoom level (1 = 100%)
let lockTableSortColumn = 'totalWait';  // Current sort column
let lockTableSortAsc = false;  // Sort direction (false = descending)

/**
 * Load events from the API endpoint.
 */
async function loadData() {
    try {
        const response = await fetch('/api/events');
        const data = await response.json();

        summary = data.summary;
        allEvents = data.events || [];

        if (allEvents.length === 0 && !summary) {
            showNoData();
            return;
        }

        // Calculate time range from actual events
        if (allEvents.length > 0) {
            minTime = Math.min(...allEvents.map(e => e.timestamp_ns));
            maxTime = Math.max(...allEvents.map(e => e.timestamp_ns));

            // Calculate minimum time threshold based on dropped events
            // If events were dropped, we can't trust early data
            if (summary && summary.dropped_events > 0) {
                const totalEvents = summary.recorded_events;
                const droppedRatio = summary.dropped_events / totalEvents;
                const timeRange = maxTime - minTime;
                // Set the minimum threshold to skip the early portion where drops occurred
                minTimeWithDrops = minTime + (timeRange * droppedRatio);
            } else {
                minTimeWithDrops = minTime;
            }

            // Find unique locks
            uniqueLocks = new Set(allEvents.map(e => e.lock_addr));
            // Default to NO locks selected (user must toggle them on)
            selectedLocks = new Set();

            // Calculate common path prefix
            commonPathPrefix = calculateCommonPrefix();
            console.log('Common path prefix:', commonPathPrefix);  // Debug

            // Build lock source file map
            lockSourceFiles = {};
            for (const event of allEvents) {
                if (!lockSourceFiles[event.lock_addr]) {
                    lockSourceFiles[event.lock_addr] = { file: event.file, line: event.line };
                }
            }

            // Calculate lock contention statistics
            lockContention = calculateContention();
        }

        updateSummary();
        updateStats();
        updateLockFilter();
        renderTimeline();
    } catch (error) {
        console.error('Error loading data:', error);
        showNoData();
    }
}

/**
 * Calculate the common path prefix for all file paths.
 * Only considers absolute paths (starting with /) for prefix calculation.
 */
function calculateCommonPrefix() {
    // Filter to only absolute paths for prefix calculation
    const files = [...new Set(allEvents.map(e => e.file))]
        .filter(f => f && f.length > 0 && f.startsWith('/'));
    if (files.length === 0) return '';

    // Split all paths into directory components
    const splitPaths = files.map(f => {
        const parts = f.split('/');
        // Return all directory parts (exclude the filename)
        return parts.slice(0, -1);
    });

    if (splitPaths.length === 0 || splitPaths[0].length === 0) return '';

    // Find the common directory prefix
    const firstPath = splitPaths[0];
    let commonDepth = firstPath.length;

    for (let i = 1; i < splitPaths.length; i++) {
        const currentPath = splitPaths[i];
        let matchDepth = 0;
        const maxCheck = Math.min(commonDepth, currentPath.length);

        for (let j = 0; j < maxCheck; j++) {
            if (firstPath[j] === currentPath[j]) {
                matchDepth++;
            } else {
                break;
            }
        }
        commonDepth = matchDepth;
    }

    if (commonDepth === 0) return '';

    // Build the common prefix string
    return firstPath.slice(0, commonDepth).join('/') + '/';
}

/**
 * Strip the common prefix from a file path.
 */
function stripCommonPrefix(filePath) {
    if (commonPathPrefix && filePath.startsWith(commonPathPrefix)) {
        return filePath.substring(commonPathPrefix.length);
    }
    return filePath;
}

/**
 * Calculate contention duration for each lock.
 * Contention is the time between an attempt and its corresponding acquire.
 */
function calculateContention() {
    const contention = {};
    const pendingAttempts = {};  // Map lock_addr -> array of attempt timestamps

    // Sort events by timestamp for accurate calculation
    const sortedEvents = [...allEvents].sort((a, b) => a.timestamp_ns - b.timestamp_ns);

    for (const event of sortedEvents) {
        const lock = event.lock_addr;

        if (!contention[lock]) {
            contention[lock] = { totalWait: 0, attempts: 0, maxWait: 0 };
        }
        if (!pendingAttempts[lock]) {
            pendingAttempts[lock] = [];
        }

        if (event.event_type === 'attempt') {
            pendingAttempts[lock].push(event.timestamp_ns);
        } else if (event.event_type === 'acquired' && pendingAttempts[lock].length > 0) {
            const attemptTime = pendingAttempts[lock].shift();
            const waitTime = event.timestamp_ns - attemptTime;
            contention[lock].totalWait += waitTime;
            contention[lock].attempts++;
            contention[lock].maxWait = Math.max(contention[lock].maxWait, waitTime);
        }
    }

    return contention;
}

/**
 * Format nanoseconds as a human-readable duration.
 */
function formatDuration(ns) {
    if (ns >= 1_000_000) {
        return (ns / 1_000_000).toFixed(2) + 'ms';
    } else if (ns >= 1_000) {
        return (ns / 1_000).toFixed(2) + 'µs';
    } else {
        return ns + 'ns';
    }
}

/**
 * Show the no-data state.
 */
function showNoData() {
    document.getElementById('timeline-content').innerHTML = `
        <div class="no-data">
            <h2>No Lock Data Found</h2>
            <p>Run a program with LiteBox to generate lock trace data at /tmp/locks.jsonl</p>
        </div>
    `;
    document.getElementById('stats').textContent = 'No data loaded';
    document.getElementById('summary-panel').innerHTML = '';
}

/**
 * Update the summary panel with recording statistics.
 */
function updateSummary() {
    const panel = document.getElementById('summary-panel');

    if (!summary) {
        panel.innerHTML = '';
        return;
    }

    const droppedClass = summary.dropped_events > 0 ? 'warning' : 'success';

    panel.innerHTML = `
        <div class="summary-item">
            <span class="label">Total Recorded</span>
            <span class="value">${summary.recorded_events.toLocaleString()}</span>
        </div>
        <div class="summary-item">
            <span class="label">Events Dropped</span>
            <span class="value ${droppedClass}">${summary.dropped_events.toLocaleString()}</span>
        </div>
        <div class="summary-item">
            <span class="label">Buffer Utilization</span>
            <span class="value">${((summary.recorded_events - summary.dropped_events) / summary.recorded_events * 100).toFixed(1)}%</span>
        </div>
        <div class="summary-item">
            <span class="label">Events in View</span>
            <span class="value">${allEvents.length.toLocaleString()}</span>
        </div>
    `;
}

/**
 * Update the stats line in the header.
 */
function updateStats() {
    const stats = document.getElementById('stats');
    if (allEvents.length === 0) {
        stats.textContent = 'No events to display';
        return;
    }
    const duration = (maxTime - minTime) / 1_000_000; // Convert to ms
    stats.textContent = `${allEvents.length} events | ${uniqueLocks.size} unique locks | Duration: ${duration.toFixed(2)}ms`;
}

/**
 * Update the lock filter UI with a sortable table.
 */
function updateLockFilter() {
    const container = document.getElementById('lock-filter');

    // Build lock data array for sorting
    const lockData = Array.from(uniqueLocks).map(lock => {
        const cont = lockContention[lock] || { totalWait: 0, attempts: 0, maxWait: 0 };
        const source = lockSourceFiles[lock] || { file: '', line: 0 };
        return {
            lock,
            totalWait: cont.totalWait,
            attempts: cont.attempts,
            maxWait: cont.maxWait,
            file: source.file,
            line: source.line,
            selected: selectedLocks.has(lock)
        };
    });

    // Sort based on current sort column
    lockData.sort((a, b) => {
        let valA, valB;
        switch (lockTableSortColumn) {
            case 'lock':
                valA = a.lock;
                valB = b.lock;
                break;
            case 'totalWait':
                valA = a.totalWait;
                valB = b.totalWait;
                break;
            case 'attempts':
                valA = a.attempts;
                valB = b.attempts;
                break;
            case 'maxWait':
                valA = a.maxWait;
                valB = b.maxWait;
                break;
            case 'file':
                valA = a.file;
                valB = b.file;
                break;
            default:
                valA = a.totalWait;
                valB = b.totalWait;
        }

        if (typeof valA === 'string') {
            const cmp = valA.localeCompare(valB);
            return lockTableSortAsc ? cmp : -cmp;
        }
        return lockTableSortAsc ? valA - valB : valB - valA;
    });

    // Build table HTML
    const sortIndicator = (col) => {
        if (lockTableSortColumn === col) {
            return lockTableSortAsc ? ' ▲' : ' ▼';
        }
        return '';
    };

    let html = `
        <table class="lock-table">
            <thead>
                <tr>
                    <th class="lock-table-checkbox"></th>
                    <th class="sortable" onclick="sortLockTable('lock')">Lock${sortIndicator('lock')}</th>
                    <th class="sortable" onclick="sortLockTable('totalWait')">Total Wait${sortIndicator('totalWait')}</th>
                    <th class="sortable" onclick="sortLockTable('attempts')">Attempts${sortIndicator('attempts')}</th>
                    <th class="sortable" onclick="sortLockTable('maxWait')">Max Wait${sortIndicator('maxWait')}</th>
                    <th class="sortable" onclick="sortLockTable('file')">Source File${sortIndicator('file')}</th>
                </tr>
            </thead>
            <tbody>
    `;

    for (const data of lockData) {
        const strippedFile = stripCommonPrefix(data.file);
        const selectedClass = data.selected ? 'selected' : '';
        html += `
            <tr class="lock-row ${selectedClass}" onclick="toggleLock('${data.lock}')">
                <td class="lock-table-checkbox">
                    <input type="checkbox" ${data.selected ? 'checked' : ''} onclick="event.stopPropagation(); toggleLock('${data.lock}')">
                </td>
                <td class="lock-addr">${data.lock}</td>
                <td class="lock-stat">${formatDuration(data.totalWait)}</td>
                <td class="lock-stat">${data.attempts}</td>
                <td class="lock-stat">${formatDuration(data.maxWait)}</td>
                <td class="lock-file" title="${data.file}:${data.line}">${strippedFile}:${data.line}</td>
            </tr>
        `;
    }

    html += '</tbody></table>';
    container.innerHTML = html;
}

/**
 * Sort the lock table by a column.
 */
function sortLockTable(column) {
    if (lockTableSortColumn === column) {
        // Toggle sort direction
        lockTableSortAsc = !lockTableSortAsc;
    } else {
        lockTableSortColumn = column;
        // Default to descending for numeric columns, ascending for text
        lockTableSortAsc = (column === 'lock' || column === 'file');
    }
    updateLockFilter();
}

/**
 * Select all locks.
 */
function selectAllLocks() {
    selectedLocks = new Set(uniqueLocks);
    updateLockFilter();
    renderTimeline();
}

/**
 * Deselect all locks.
 */
function selectNoLocks() {
    selectedLocks = new Set();
    updateLockFilter();
    renderTimeline();
}

/**
 * Toggle a lock in/out of the filter.
 */
function toggleLock(lock) {
    if (selectedLocks.has(lock)) {
        selectedLocks.delete(lock);
    } else {
        selectedLocks.add(lock);
    }
    updateLockFilter();
    renderTimeline();
}

/**
 * Get events filtered by current filter settings.
 */
function getFilteredEvents() {
    const eventTypeFilter = document.getElementById('event-type-filter').value;
    const timeStartPercent = parseInt(document.getElementById('time-start').value);
    const timeEndPercent = parseInt(document.getElementById('time-end').value);

    const timeRange = maxTime - minTime;
    const timeStart = minTime + (timeRange * timeStartPercent / 100);
    const timeEnd = minTime + (timeRange * timeEndPercent / 100);

    return allEvents.filter(event => {
        // Lock filter
        if (!selectedLocks.has(event.lock_addr)) return false;

        // Event type filter
        if (eventTypeFilter !== 'all' && event.event_type !== eventTypeFilter) return false;

        // Time range filter
        if (event.timestamp_ns < timeStart || event.timestamp_ns > timeEnd) return false;

        return true;
    });
}

/**
 * Render the timeline visualization.
 */
function renderTimeline() {
    // Check if no locks are selected first
    if (selectedLocks.size === 0) {
        const totalLocks = uniqueLocks.size;
        document.getElementById('timeline-content').innerHTML = `
            <div class="no-data welcome-message">
                <h2>👆 Select Locks to View</h2>
                <p>Click on rows in the lock table above to enable them, or use "Select All" to show everything.</p>
                <p class="muted">${totalLocks} locks available</p>
            </div>
        `;
        return;
    }

    const events = getFilteredEvents();

    if (events.length === 0) {
        document.getElementById('timeline-content').innerHTML = `
            <div class="no-data">
                <h2>No Events Match Filters</h2>
                <p>Try adjusting your filter settings</p>
            </div>
        `;
        return;
    }

    // Group events by lock
    const lockGroups = {};
    events.forEach(event => {
        if (!lockGroups[event.lock_addr]) {
            lockGroups[event.lock_addr] = [];
        }
        lockGroups[event.lock_addr].push(event);
    });

    // Calculate visible time range
    const visibleMinTime = Math.min(...events.map(e => e.timestamp_ns));
    const visibleMaxTime = Math.max(...events.map(e => e.timestamp_ns));
    const timeRange = visibleMaxTime - visibleMinTime || 1;

    // Build timeline HTML
    const zoomPercent = Math.round(zoomLevel * 100);
    let html = `
        <div class="timeline-controls">
            <div class="zoom-controls">
                <button class="btn btn-small btn-secondary" onclick="zoomOut()">−</button>
                <span class="zoom-level">${zoomPercent}%</span>
                <button class="btn btn-small btn-secondary" onclick="zoomIn()">+</button>
                <button class="btn btn-small btn-secondary" onclick="resetZoom()">Reset</button>
            </div>
            <div class="timeline-time-range">
                <span>${formatTime(visibleMinTime)}</span>
                <span>to</span>
                <span>${formatTime(visibleMaxTime)}</span>
            </div>
        </div>
        <div class="timeline-scroll-container">
        <div class="timeline-tracks" style="width: ${100 * zoomLevel}%;">
    `;

    // Sort locks by contention (most contested first)
    const sortedLocks = Object.keys(lockGroups).sort((a, b) => {
        const contentionA = lockContention[a]?.totalWait || 0;
        const contentionB = lockContention[b]?.totalWait || 0;
        return contentionB - contentionA;
    });

    sortedLocks.forEach(lock => {
        const lockEvents = lockGroups[lock];
        // Get first event to show file:line info (with stripped path)
        const firstEvent = lockEvents[0];
        const strippedFile = stripCommonPrefix(firstEvent.file);
        const label = `${lock} (${strippedFile}:${firstEvent.line})`;
        const fullLabel = `${lock} (${firstEvent.file}:${firstEvent.line})`;

        html += `<div class="timeline-track">`;
        html += `<div class="timeline-track-label" title="${fullLabel}">${label}</div>`;

        lockEvents.forEach((event, idx) => {
            // Cap position to leave room for marker width (max ~99.5% to prevent overflow)
            const rawPosition = ((event.timestamp_ns - visibleMinTime) / timeRange) * 100;
            const position = Math.min(rawPosition, 99.5);
            html += `
                <div class="event-marker ${event.event_type}"
                     style="left: ${position}%"
                     data-event-idx="${allEvents.indexOf(event)}"
                     onmouseenter="showTooltip(event, ${allEvents.indexOf(event)})"
                     onmouseleave="hideTooltip()">
                </div>
            `;
        });

        html += `</div>`;
    });

    html += `</div>`;
    html += `</div>`;  // Close timeline-scroll-container
    html += `
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color attempt"></div>
                <span>Attempt</span>
            </div>
            <div class="legend-item">
                <div class="legend-color acquired"></div>
                <span>Acquired</span>
            </div>
            <div class="legend-item">
                <div class="legend-color released"></div>
                <span>Released</span>
            </div>
        </div>
    `;

    document.getElementById('timeline-content').innerHTML = html;
}

/**
 * Zoom in on the timeline.
 */
function zoomIn() {
    zoomLevel = zoomLevel * 2;  // No max limit
    renderTimeline();
}

/**
 * Zoom out on the timeline.
 */
function zoomOut() {
    zoomLevel = Math.max(zoomLevel / 2, 1);  // Min 100%
    renderTimeline();
}

/**
 * Reset zoom to default.
 */
function resetZoom() {
    zoomLevel = 1;
    renderTimeline();
}

/**
 * Format a nanosecond timestamp as milliseconds.
 */
function formatTime(ns) {
    const ms = ns / 1_000_000;
    return ms.toFixed(3) + 'ms';
}

/**
 * Show the tooltip for an event.
 */
function showTooltip(mouseEvent, eventIdx) {
    const event = allEvents[eventIdx];
    const tooltip = document.getElementById('tooltip');
    const strippedFile = stripCommonPrefix(event.file);
    const cont = lockContention[event.lock_addr];

    let contentionInfo = '';
    if (cont && cont.totalWait > 0) {
        contentionInfo = `
            <div class="tooltip-row"><span class="tooltip-label">Total Wait:</span>${formatDuration(cont.totalWait)}</div>
            <div class="tooltip-row"><span class="tooltip-label">Max Wait:</span>${formatDuration(cont.maxWait)}</div>
        `;
    }

    tooltip.innerHTML = `
        <div class="tooltip-row"><span class="tooltip-label">Event:</span>${event.event_type}</div>
        <div class="tooltip-row"><span class="tooltip-label">Time:</span>${formatTime(event.timestamp_ns)}</div>
        <div class="tooltip-row"><span class="tooltip-label">Lock:</span>${event.lock_addr}</div>
        <div class="tooltip-row"><span class="tooltip-label">Type:</span>${event.lock_type}</div>
        <div class="tooltip-row"><span class="tooltip-label">Location:</span>${strippedFile}:${event.line}</div>
        ${contentionInfo}
    `;

    tooltip.style.left = (mouseEvent.clientX + 10) + 'px';
    tooltip.style.top = (mouseEvent.clientY + 10) + 'px';
    tooltip.classList.add('visible');
}

/**
 * Hide the tooltip.
 */
function hideTooltip() {
    document.getElementById('tooltip').classList.remove('visible');
}

/**
 * Reset all filters to their default state.
 */
function resetFilters() {
    // Reset to no locks selected (default for large datasets)
    selectedLocks = new Set();
    document.getElementById('event-type-filter').value = 'all';
    document.getElementById('time-start').value = getMinTimeSliderValue();
    document.getElementById('time-end').value = 100;
    updateTimeRangeDisplay();
    updateLockFilter();
    renderTimeline();
}

/**
 * Get the minimum slider value based on dropped events.
 */
function getMinTimeSliderValue() {
    if (summary && summary.dropped_events > 0) {
        const totalEvents = summary.recorded_events;
        const droppedRatio = summary.dropped_events / totalEvents;
        return Math.round(droppedRatio * 100);
    }
    return 0;
}

/**
 * Update the time range display labels.
 */
function updateTimeRangeDisplay() {
    const startSlider = document.getElementById('time-start');
    const endSlider = document.getElementById('time-end');
    const display = document.getElementById('time-range-display');

    if (display) {
        display.textContent = `${startSlider.value}% - ${endSlider.value}%`;
    }
}

// Initialize event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('event-type-filter').addEventListener('change', renderTimeline);
    document.getElementById('time-start').addEventListener('input', () => {
        updateTimeRangeDisplay();
        renderTimeline();
    });
    document.getElementById('time-end').addEventListener('input', () => {
        updateTimeRangeDisplay();
        renderTimeline();
    });

    // Initial load
    loadData().then(() => {
        // Set initial slider values based on dropped events
        const minSliderValue = getMinTimeSliderValue();
        document.getElementById('time-start').value = minSliderValue;
        document.getElementById('time-start').min = minSliderValue;
        updateTimeRangeDisplay();
        renderTimeline();
    });
});
