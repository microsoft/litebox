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

            // Find unique locks
            uniqueLocks = new Set(allEvents.map(e => e.lock_addr));
            selectedLocks = new Set(uniqueLocks);
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
 * Update the lock filter UI.
 */
function updateLockFilter() {
    const container = document.getElementById('lock-filter');
    container.innerHTML = '';

    const lockArray = Array.from(uniqueLocks).sort();
    lockArray.forEach(lock => {
        const tag = document.createElement('span');
        tag.className = 'lock-tag' + (selectedLocks.has(lock) ? ' selected' : '');
        tag.textContent = lock;
        tag.onclick = () => toggleLock(lock);
        container.appendChild(tag);
    });
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
    let html = `
        <div class="timeline-header">
            <span>${formatTime(visibleMinTime)}</span>
            <span>${formatTime(visibleMaxTime)}</span>
        </div>
        <div class="timeline-tracks">
    `;

    const sortedLocks = Object.keys(lockGroups).sort();
    sortedLocks.forEach(lock => {
        const lockEvents = lockGroups[lock];
        // Get first event to show file:line info
        const firstEvent = lockEvents[0];
        const label = `${lock} (${firstEvent.file}:${firstEvent.line})`;

        html += `<div class="timeline-track">`;
        html += `<div class="timeline-track-label" title="${label}">${label}</div>`;

        lockEvents.forEach((event, idx) => {
            const position = ((event.timestamp_ns - visibleMinTime) / timeRange) * 100;
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

    tooltip.innerHTML = `
        <div class="tooltip-row"><span class="tooltip-label">Event:</span>${event.event_type}</div>
        <div class="tooltip-row"><span class="tooltip-label">Time:</span>${formatTime(event.timestamp_ns)}</div>
        <div class="tooltip-row"><span class="tooltip-label">Lock:</span>${event.lock_addr}</div>
        <div class="tooltip-row"><span class="tooltip-label">Type:</span>${event.lock_type}</div>
        <div class="tooltip-row"><span class="tooltip-label">Location:</span>${event.file}:${event.line}</div>
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
    selectedLocks = new Set(uniqueLocks);
    document.getElementById('event-type-filter').value = 'all';
    document.getElementById('time-start').value = 0;
    document.getElementById('time-end').value = 100;
    updateLockFilter();
    renderTimeline();
}

// Initialize event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('event-type-filter').addEventListener('change', renderTimeline);
    document.getElementById('time-start').addEventListener('input', renderTimeline);
    document.getElementById('time-end').addEventListener('input', renderTimeline);

    // Initial load
    loadData();
});
