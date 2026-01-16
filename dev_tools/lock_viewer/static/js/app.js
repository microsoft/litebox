// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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
let lockMaxWaitLocations = {};  // Map of lock_addr -> location with max wait time
let lockCreationLocations = {};  // Map of lock_addr -> creation location (from 'created' events)
let lockTypes = {};        // Map of lock_addr -> lock type (from 'created' events)
let zoomLevel = 1;         // Timeline zoom level (1 = 100%)
let lockTableSortColumn = 'maxWait';  // Current sort column
let lockTableSortAsc = false;  // Sort direction (false = descending)
let ignoredUnusedLockCount = 0;  // Count of locks that only had create/destroy events

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
            minTime = allEvents.reduce((min, e) => e.timestamp_ns < min ? e.timestamp_ns : min, Infinity);
            maxTime = allEvents.reduce((max, e) => e.timestamp_ns > max ? e.timestamp_ns : max, -Infinity);

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

            // Find unique locks, filtering out those that were only created/destroyed
            const allLocks = new Set(allEvents.map(e => e.lock_addr));
            const usedLocks = new Set();
            for (const event of allEvents) {
                if (event.event_type === 'attempt' || event.event_type === 'acquired' || event.event_type === 'released') {
                    usedLocks.add(event.lock_addr);
                }
            }
            // Count ignored locks and keep only used ones
            ignoredUnusedLockCount = allLocks.size - usedLocks.size;
            uniqueLocks = usedLocks;
            // Default to NO locks selected (user must toggle them on)
            selectedLocks = new Set();

            // Calculate common path prefix
            commonPathPrefix = calculateCommonPrefix();
            console.log('Common path prefix:', commonPathPrefix);  // Debug

            // Build lock creation location map and lock types from 'created' events
            lockCreationLocations = {};
            lockTypes = {};
            for (const event of allEvents) {
                if (event.event_type === 'created') {
                    lockCreationLocations[event.lock_addr] = { file: event.file, line: event.line };
                    lockTypes[event.lock_addr] = event.lock_type || 'unknown';
                }
            }

            // Calculate lock contention statistics (also builds max wait locations)
            lockContention = calculateContention();

            // Build max wait location map from contention data
            lockMaxWaitLocations = {};
            for (const lock of Object.keys(lockContention)) {
                const cont = lockContention[lock];
                if (cont.maxWaitFile) {
                    lockMaxWaitLocations[lock] = { file: cont.maxWaitFile, line: cont.maxWaitLine };
                }
            }
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
    const pendingAttempts = {};  // Map lock_addr -> array of {timestamp, file, line}

    // Sort events by timestamp for accurate calculation
    const sortedEvents = [...allEvents].sort((a, b) => a.timestamp_ns - b.timestamp_ns);

    for (const event of sortedEvents) {
        const lock = event.lock_addr;

        if (!contention[lock]) {
            contention[lock] = { totalWait: 0, attempts: 0, maxWait: 0, maxWaitFile: '', maxWaitLine: 0 };
        }
        if (!pendingAttempts[lock]) {
            pendingAttempts[lock] = [];
        }

        if (event.event_type === 'attempt') {
            pendingAttempts[lock].push({ timestamp: event.timestamp_ns, file: event.file, line: event.line });
        } else if (event.event_type === 'acquired' && pendingAttempts[lock].length > 0) {
            const attempt = pendingAttempts[lock].shift();
            const waitTime = event.timestamp_ns - attempt.timestamp;
            contention[lock].totalWait += waitTime;
            contention[lock].attempts++;
            if (waitTime > contention[lock].maxWait) {
                contention[lock].maxWait = waitTime;
                contention[lock].maxWaitFile = attempt.file;
                contention[lock].maxWaitLine = attempt.line;
            }
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

    const recordedEvents = summary.recorded_events || 0;
    const droppedEvents = summary.dropped_events || 0;
    const droppedClass = droppedEvents > 0 ? 'warning' : 'success';
    const utilization = recordedEvents > 0
        ? ((recordedEvents - droppedEvents) / recordedEvents * 100).toFixed(1)
        : '100.0';

    panel.innerHTML = `
        <div class="summary-item">
            <span class="label">Total Recorded</span>
            <span class="value">${recordedEvents.toLocaleString()}</span>
        </div>
        <div class="summary-item">
            <span class="label">Events Dropped</span>
            <span class="value ${droppedClass}">${droppedEvents.toLocaleString()}</span>
        </div>
        <div class="summary-item">
            <span class="label">Buffer Utilization</span>
            <span class="value">${utilization}%</span>
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
        const creation = lockCreationLocations[lock] || null;
        const maxWaitLoc = lockMaxWaitLocations[lock] || { file: '', line: 0 };
        return {
            lock,
            lockType: lockTypes[lock] || 'unknown',
            totalWait: cont.totalWait,
            attempts: cont.attempts,
            maxWait: cont.maxWait,
            creationFile: creation ? creation.file : '',
            creationLine: creation ? creation.line : 0,
            file: maxWaitLoc.file,
            line: maxWaitLoc.line,
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
            case 'lockType':
                valA = a.lockType;
                valB = b.lockType;
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
            case 'creation':
                valA = a.creationFile;
                valB = b.creationFile;
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
                    <th class="sortable" onclick="sortLockTable('lockType')">Type${sortIndicator('lockType')}</th>
                    <th class="sortable" onclick="sortLockTable('totalWait')">Total Wait${sortIndicator('totalWait')}</th>
                    <th class="sortable" onclick="sortLockTable('attempts')">Attempts${sortIndicator('attempts')}</th>
                    <th class="sortable" onclick="sortLockTable('maxWait')">Max Wait${sortIndicator('maxWait')}</th>
                    <th class="sortable" onclick="sortLockTable('creation')">Created At${sortIndicator('creation')}</th>
                    <th class="sortable" onclick="sortLockTable('file')">Max Wait At${sortIndicator('file')}</th>
                </tr>
            </thead>
            <tbody>
    `;

    for (const data of lockData) {
        const strippedCreationFile = data.creationFile ? stripCommonPrefix(data.creationFile) : '';
        const strippedFile = stripCommonPrefix(data.file);
        const selectedClass = data.selected ? 'selected' : '';
        const creationDisplay = data.creationFile
            ? `${strippedCreationFile}:${data.creationLine}`
            : '<span style="color: #666;">—</span>';
        const creationTitle = data.creationFile
            ? `${data.creationFile}:${data.creationLine}`
            : 'No creation event recorded';
        const creationHover = data.creationFile
            ? `onmouseenter="showFileTooltip(event, '${data.creationFile.replace(/'/g, "\\'")}', ${data.creationLine}, 'Created At')" onmouseleave="hideTooltip()"`
            : '';
        const maxWaitAtHover = data.file
            ? `onmouseenter="showFileTooltip(event, '${data.file.replace(/'/g, "\\'")}', ${data.line}, 'Max Wait At')" onmouseleave="hideTooltip()"`
            : '';
        const maxWaitAtDisplay = data.file
            ? `${strippedFile}:${data.line}`
            : '<span style="color: #666;">—</span>';
        html += `
            <tr class="lock-row ${selectedClass}" onclick="toggleLock('${data.lock}')">
                <td class="lock-table-checkbox">
                    <input type="checkbox" ${data.selected ? 'checked' : ''} onclick="event.stopPropagation(); toggleLock('${data.lock}')">
                </td>
                <td class="lock-addr">${data.lock}</td>
                <td class="lock-type">${data.lockType}</td>
                <td class="lock-stat">${formatDuration(data.totalWait)}</td>
                <td class="lock-stat">${data.attempts}</td>
                <td class="lock-stat">${formatDuration(data.maxWait)}</td>
                <td class="lock-file" ${creationHover}>${creationDisplay}</td>
                <td class="lock-file" ${maxWaitAtHover}>${maxWaitAtDisplay}</td>
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
 * Build spans from events for a specific lock and location.
 * Returns array of { type: 'waiting'|'holding'|'holding-read'|'holding-write', start, end } spans.
 */
function buildSpans(events) {
    const spans = [];
    const sortedEvents = [...events].sort((a, b) => a.timestamp_ns - b.timestamp_ns);

    let pendingAttempt = null;
    let pendingAcquired = null;

    for (const event of sortedEvents) {
        if (event.event_type === 'attempt') {
            pendingAttempt = event;
        } else if (event.event_type === 'acquired') {
            if (pendingAttempt) {
                // Create waiting span (attempt -> acquired)
                spans.push({
                    type: 'waiting',
                    start: pendingAttempt.timestamp_ns,
                    end: event.timestamp_ns,
                    startEvent: pendingAttempt,
                    endEvent: event
                });
                pendingAttempt = null;
            }
            pendingAcquired = event;
        } else if (event.event_type === 'released') {
            if (pendingAcquired) {
                // Determine holding span type based on lock_type field
                // Events have lock_type like "RwLockRead", "RwLockWrite", "Mutex", etc.
                const eventLockType = (pendingAcquired.lock_type || '').toLowerCase();
                let holdType = 'holding';
                if (eventLockType.includes('read')) {
                    holdType = 'holding-read';
                } else if (eventLockType.includes('write')) {
                    holdType = 'holding-write';
                }
                // Create holding span (acquired -> released)
                spans.push({
                    type: holdType,
                    start: pendingAcquired.timestamp_ns,
                    end: event.timestamp_ns,
                    startEvent: pendingAcquired,
                    endEvent: event
                });
                pendingAcquired = null;
            }
        }
    }

    return spans;
}

/**
 * Render the timeline visualization.
 */
function renderTimeline() {
    // Check if no locks are selected first
    if (selectedLocks.size === 0) {
        const shownLocks = uniqueLocks.size;
        let locksMessage = `${shownLocks} locks available`;
        if (ignoredUnusedLockCount > 0) {
            locksMessage += `; ${ignoredUnusedLockCount} never used`;
        }
        document.getElementById('timeline-content').innerHTML = `
            <div class="no-data welcome-message">
                <h2>👆 Select Locks to View</h2>
                <p>Click on rows in the lock table above to enable them, or use "Select All" to show everything.</p>
                <p class="muted">${locksMessage}</p>
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

    // Group events by lock, then by location (file:line)
    const lockGroups = {};
    events.forEach(event => {
        if (!lockGroups[event.lock_addr]) {
            lockGroups[event.lock_addr] = {};
        }
        const locationKey = `${event.file}:${event.line}`;
        if (!lockGroups[event.lock_addr][locationKey]) {
            lockGroups[event.lock_addr][locationKey] = [];
        }
        lockGroups[event.lock_addr][locationKey].push(event);
    });

    // Calculate visible time range
    const visibleMinTime = events.reduce((min, e) => e.timestamp_ns < min ? e.timestamp_ns : min, Infinity);
    const visibleMaxTime = events.reduce((max, e) => e.timestamp_ns > max ? e.timestamp_ns : max, -Infinity);
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
        const locationGroups = lockGroups[lock];
        const lockType = lockTypes[lock] || 'unknown';

        // Use creation location as primary identity if available
        const creation = lockCreationLocations[lock];
        let lockLabel, headerHover;
        if (creation) {
            const strippedCreationFile = stripCommonPrefix(creation.file);
            lockLabel = `${lock} [${lockType} @ ${strippedCreationFile}:${creation.line}]`;
            headerHover = `onmouseenter="showFileTooltip(event, '${creation.file.replace(/'/g, "\\'")}', ${creation.line}, 'Created At')" onmouseleave="hideTooltip()"`;
        } else {
            lockLabel = `${lock} [${lockType}]`;
            headerHover = '';
        }

        // Create a group container for this lock
        html += `<div class="timeline-lock-group">`;
        html += `<div class="timeline-lock-header" ${headerHover}>${lockLabel}</div>`;

        // Sort locations by total span time (most active first)
        const sortedLocations = Object.keys(locationGroups).sort((a, b) => {
            const spansA = buildSpans(locationGroups[a]);
            const spansB = buildSpans(locationGroups[b]);
            const totalA = spansA.reduce((sum, s) => sum + (s.end - s.start), 0);
            const totalB = spansB.reduce((sum, s) => sum + (s.end - s.start), 0);
            return totalB - totalA;
        });

        sortedLocations.forEach(location => {
            const locationEvents = locationGroups[location];
            const spans = buildSpans(locationEvents);
            const locationFile = location.split(':')[0];
            const locationLine = parseInt(location.split(':')[1]) || 0;
            const strippedLocation = stripCommonPrefix(locationFile) + ':' + locationLine;
            const trackHover = `onmouseenter="showFileTooltip(event, '${locationFile.replace(/'/g, "\\'")}', ${locationLine}, 'Location')" onmouseleave="hideTooltip()"`;

            html += `<div class="timeline-track">`;
            html += `<div class="timeline-track-label" ${trackHover}>${strippedLocation}</div>`;

            // Render spans
            spans.forEach(span => {
                const startPos = ((span.start - visibleMinTime) / timeRange) * 100;
                const endPos = ((span.end - visibleMinTime) / timeRange) * 100;
                const width = Math.max(endPos - startPos, 0.1); // Minimum width for visibility
                const duration = span.end - span.start;
                let spanClass;
                switch (span.type) {
                    case 'waiting':
                        spanClass = 'span-waiting';
                        break;
                    case 'holding-read':
                        spanClass = 'span-holding-read';
                        break;
                    case 'holding-write':
                        spanClass = 'span-holding-write';
                        break;
                    default:
                        spanClass = 'span-holding';
                }

                html += `
                    <div class="timeline-span ${spanClass}"
                         style="left: ${startPos}%; width: ${width}%;"
                         onmouseenter="showSpanTooltip(event, '${span.type}', ${duration}, '${lock}', '${location.replace(/'/g, "\\'")}')"
                         onmouseleave="hideTooltip()">
                    </div>
                `;
            });

            html += `</div>`;
        });

        html += `</div>`; // Close timeline-lock-group
    });

    html += `</div>`;
    html += `</div>`;  // Close timeline-scroll-container
    html += `
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color span-waiting"></div>
                <span>Waiting (attempt → acquired)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color span-holding"></div>
                <span>Holding (mutex)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color span-holding-read"></div>
                <span>Holding Read (RwLock)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color span-holding-write"></div>
                <span>Holding Write (RwLock)</span>
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

// Cache for fetched code snippets
let snippetCache = {};

/**
 * Fetch a code snippet from the server.
 * Returns a promise that resolves to the snippet HTML.
 */
async function fetchSnippet(filePath, line) {
    const cacheKey = `${filePath}:${line}`;
    if (snippetCache[cacheKey]) {
        return snippetCache[cacheKey];
    }

    try {
        // Fetch ~10 lines of context around the target line
        const response = await fetch(`/api/snippet?file=${encodeURIComponent(filePath)}&line=${line}&context=10`);
        const data = await response.json();

        if (data.error || !data.lines || data.lines.length === 0) {
            snippetCache[cacheKey] = '';
            return '';
        }

        const linesHtml = data.lines.map(l => {
            const lineClass = l.is_target ? 'snippet-line snippet-target' : 'snippet-line';
            const escapedContent = escapeHtml(l.content);
            return `<div class="${lineClass}"><span class="snippet-line-number">${l.number}</span><span class="snippet-code">${escapedContent}</span></div>`;
        }).join('');

        const snippetHtml = `<div class="snippet-container">${linesHtml}</div>`;
        snippetCache[cacheKey] = snippetHtml;
        return snippetHtml;
    } catch (error) {
        console.error('Error fetching snippet:', error);
        snippetCache[cacheKey] = '';
        return '';
    }
}

/**
 * Escape HTML entities to prevent XSS.
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Scroll the snippet container to show the highlighted line with ~5 lines of context above.
 */
function scrollToHighlightedLine(tooltip) {
    const container = tooltip.querySelector('.snippet-container');
    const targetLine = tooltip.querySelector('.snippet-target');
    if (container && targetLine) {
        // Get the height of a single line
        const lineHeight = targetLine.offsetHeight;
        // Calculate position to show ~5 lines above the target
        const targetOffset = targetLine.offsetTop - container.offsetTop;
        const scrollPosition = Math.max(0, targetOffset - (lineHeight * 5));
        container.scrollTop = scrollPosition;
    }
}

/**
 * Show a tooltip with a code snippet for a file location.
 */
async function showFileTooltip(mouseEvent, filePath, line, label) {
    // Cancel any pending hide
    keepTooltipVisible();

    const tooltip = document.getElementById('tooltip');

    // Show tooltip immediately with loading state
    tooltip.innerHTML = `
        <div class="tooltip-row"><span class="tooltip-label">${label}:</span>${filePath}:${line}</div>
        <div class="snippet-loading">Loading code...</div>
    `;

    tooltip.style.left = (mouseEvent.clientX + 10) + 'px';
    tooltip.style.top = (mouseEvent.clientY + 10) + 'px';
    tooltip.classList.add('visible');

    // Fetch and display snippet
    if (line > 0) {
        const snippet = await fetchSnippet(filePath, line);
        if (tooltip.classList.contains('visible')) {
            tooltip.innerHTML = `
                <div class="tooltip-row"><span class="tooltip-label">${label}:</span>${filePath}:${line}</div>
                ${snippet || '<div class="snippet-loading">Could not load source</div>'}
            `;
            // Auto-scroll to the highlighted line in the snippet
            scrollToHighlightedLine(tooltip);
        }
    }
}

/**
 * Show the tooltip for a span.
 */
function showSpanTooltip(mouseEvent, spanType, duration, lock, location) {
    // Cancel any pending hide
    keepTooltipVisible();

    const tooltip = document.getElementById('tooltip');
    const spanLabel = spanType === 'waiting' ? 'Waiting' : 'Holding';
    const cont = lockContention[lock];
    const lockType = lockTypes[lock] || 'unknown';

    let contentionInfo = '';
    if (cont && cont.totalWait > 0) {
        contentionInfo = `
            <div class="tooltip-row"><span class="tooltip-label">Total Wait (all locations):</span>${formatDuration(cont.totalWait)}</div>
        `;
    }

    tooltip.innerHTML = `
        <div class="tooltip-row"><span class="tooltip-label">Span:</span>${spanLabel}</div>
        <div class="tooltip-row"><span class="tooltip-label">Duration:</span>${formatDuration(duration)}</div>
        <div class="tooltip-row"><span class="tooltip-label">Lock:</span>${lock}</div>
        <div class="tooltip-row"><span class="tooltip-label">Type:</span>${lockType}</div>
        <div class="tooltip-row"><span class="tooltip-label">Location:</span>${location}</div>
        ${contentionInfo}
    `;

    tooltip.style.left = (mouseEvent.clientX + 10) + 'px';
    tooltip.style.top = (mouseEvent.clientY + 10) + 'px';
    tooltip.classList.add('visible');
}

// Timer for delayed tooltip hiding
let tooltipHideTimer = null;

/**
 * Hide the tooltip after a short delay.
 * The delay allows users to move their mouse to the tooltip.
 */
function hideTooltip() {
    tooltipHideTimer = setTimeout(() => {
        document.getElementById('tooltip').classList.remove('visible');
    }, 150);
}

/**
 * Cancel any pending tooltip hide and keep it visible.
 */
function keepTooltipVisible() {
    if (tooltipHideTimer) {
        clearTimeout(tooltipHideTimer);
        tooltipHideTimer = null;
    }
}

/**
 * Hide the tooltip immediately (used when leaving the tooltip itself).
 */
function hideTooltipNow() {
    if (tooltipHideTimer) {
        clearTimeout(tooltipHideTimer);
        tooltipHideTimer = null;
    }
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

    // Tooltip hover handlers - keep tooltip visible when mouse is over it
    const tooltip = document.getElementById('tooltip');
    tooltip.addEventListener('mouseenter', keepTooltipVisible);
    tooltip.addEventListener('mouseleave', hideTooltipNow);

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
