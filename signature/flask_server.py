from flask import Flask, render_template_string, request, jsonify
import os
from datetime import datetime
import re

app = Flask(__name__)

def ensure_log_file():
    """Ensure log file exists"""
    log_path = "intrusion_log.txt"
    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        with open(log_path, "w") as f:
            sample_logs = [
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] Server startup\n",
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Packet: Sample log entry\n",
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] WARNING Unusual login attempt\n",
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} CRITICAL Potential breach detected\n",
                f"ERROR: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Authentication failure\n"
            ]
            f.writelines(sample_logs)

def parse_log_entry(log):
    """Parse log entry with protocol-specific color handling"""
    patterns = [
        r'^(\[.*?\]) (.*?)$',
        
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[?(\w+)\]? (.+)$',
        
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ?(.+)$'
    ]
    
    for pattern in patterns:
        match = re.match(pattern, log.strip())
        if match:
            if len(match.groups()) == 2:
                level_message = match.groups()[0]
                message = match.groups()[1]
                
                level_match = re.match(r'\[(\w+)\]', level_message)
                if level_match:
                    level = level_match.group(1)
                else:
                    level = 'ALERT'
                
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            elif len(match.groups()) == 3:
                timestamp, level, message = match.groups()
            else:
                timestamp, message = match.groups()
                level = 'ALERT'
            
            protocol = 'TCP'  
            if 'UDP' in message:
                protocol = 'UDP'
            
            if 'SYN Flood' in message:
                level = 'CRITICAL'
            elif 'Alert' in str(level):
                level = 'WARNING'
            
            return {
                'timestamp': timestamp,
                'level': level.upper(),
                'protocol': protocol,
                'message': message,
                'color': get_level_color(level.upper(), protocol)
            }
    
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'level': 'ALERT',
        'protocol': 'UNKNOWN',
        'message': log.strip(),
        'color': 'text-danger'
    }

def get_level_color(level, protocol=None):
    """Assign color based on log level and protocol"""
    colors = {
        'INFO': 'text-primary',
        'WARNING': 'text-warning',
        'ERROR': 'text-danger',
        'CRITICAL': 'text-danger fw-bold',
        'ALERT': 'text-danger',
        'DEBUG': 'text-secondary'
    }
    
    if protocol == 'UDP':
        if level == 'CRITICAL':
            return 'text-warning'  
        elif level == 'WARNING':
            return 'text-info'    
    
    return colors.get(level, 'text-muted')
@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Intrusion Detection System</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
        <style>
            body {
                background-color: #121212;
                color: #e0e0e0;
                font-family: 'JetBrains Mono', monospace;
            }
            .log-container {
                background-color: #1e1e1e;
                border-radius: 12px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.5);
                padding: 20px;
                margin-top: 30px;
            }
            .log-entry {
                border-bottom: 1px solid #333;
                padding: 10px;
                transition: background-color 0.3s ease;
            }
            .log-entry:hover {
                background-color: #2c2c2c;
            }
            .log-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }
            .filter-buttons {
                display: flex;
                gap: 10px;
            }
            #liveSearch {
                background-color: #2c2c2c;
                border: 1px solid #444;
                color: #e0e0e0;
            }
            .modal-content {
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="log-container">
                <div class="log-header">
                    <h1 class="mb-0">
                        <i class="bi bi-shield-lock text-danger"></i> 
                        Intrusion Detection Logs
                    </h1>
                    <div class="filter-buttons">
                        <input type="text" id="liveSearch" class="form-control form-control-sm" placeholder="🔍 Search logs...">
                        <div class="btn-group" role="group">
                            <button id="filterAll" class="btn btn-sm btn-outline-light active">All</button>
                            <button id="filterCritical" class="btn btn-sm btn-outline-danger">Critical</button>
                            <button id="filterWarning" class="btn btn-sm btn-outline-warning">Warning</button>
                            <button id="filterInfo" class="btn btn-sm btn-outline-primary">Info</button>
                        </div>
                    </div>
                </div>

                <div id="logEntries" class="log-entries">
                    <!-- Log entries will be dynamically loaded here -->
                </div>

                <div class="d-flex justify-content-center mt-3">
                    <button id="loadMore" class="btn btn-outline-light">Load More</button>
                </div>
            </div>
        </div>

        <!-- Log Details Modal -->
        <div class="modal fade" id="logDetailModal" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Log Details</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body" id="logDetailBody">
                        <!-- Log details will be populated here -->
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            // Fetch initial logs
            let currentPage = 1;
            const logModal = new bootstrap.Modal(document.getElementById('logDetailModal'));

            function fetchLogs(page, filter = null, search = null) {
                fetch(`/api/logs?page=${page}&filter=${filter || ''}&search=${search || ''}`)
                    .then(response => response.json())
                    .then(data => {
                        const logContainer = document.getElementById('logEntries');
                        if (page === 1) logContainer.innerHTML = '';
                        
                        data.logs.forEach(log => {
                            const logElement = document.createElement('div');
                            logElement.className = `log-entry ${log.color} d-flex justify-content-between align-items-center`;
                            logElement.innerHTML = `
                                <div class="d-flex align-items-center">
                                    <span class="me-3 text-muted small">${log.timestamp}</span>
                                    <span class="badge ${log.color.replace('text-', 'bg-')} me-2">${log.level}</span>
                                    <span>${log.message}</span>
                                </div>
                                <button class="btn btn-sm btn-outline-info log-details" data-timestamp="${log.timestamp}" data-level="${log.level}" data-message="${log.message}">
                                    <i class="bi bi-info-circle"></i>
                                </button>
                            `;
                            logContainer.appendChild(logElement);
                        });

                        // Update load more button
                        const loadMoreBtn = document.getElementById('loadMore');
                        loadMoreBtn.style.display = data.has_more ? 'block' : 'none';
                    });
            }

            // Initial log load
            fetchLogs(1);

            // Load More button
            document.getElementById('loadMore').addEventListener('click', () => {
                currentPage++;
                fetchLogs(currentPage);
            });

            // Filter buttons
            document.getElementById('filterAll').addEventListener('click', () => {
                currentPage = 1;
                fetchLogs(1);
                updateFilterButtons('All');
            });

            document.getElementById('filterCritical').addEventListener('click', () => {
                currentPage = 1;
                fetchLogs(1, 'CRITICAL');
                updateFilterButtons('Critical');
            });

            document.getElementById('filterWarning').addEventListener('click', () => {
                currentPage = 1;
                fetchLogs(1, 'WARNING');
                updateFilterButtons('Warning');
            });

            document.getElementById('filterInfo').addEventListener('click', () => {
                currentPage = 1;
                fetchLogs(1, 'INFO');
                updateFilterButtons('Info');
            });

            function updateFilterButtons(activeFilter) {
                ['All', 'Critical', 'Warning', 'Info'].forEach(filter => {
                    const btn = document.getElementById(`filter${filter}`);
                    btn.classList.toggle('active', filter === activeFilter);
                });
            }

            // Live search
            document.getElementById('liveSearch').addEventListener('input', (e) => {
                currentPage = 1;
                fetchLogs(1, null, e.target.value);
            });

            // Log details modal
            document.addEventListener('click', (e) => {
                if (e.target.closest('.log-details')) {
                    const btn = e.target.closest('.log-details');
                    const timestamp = btn.getAttribute('data-timestamp');
                    const level = btn.getAttribute('data-level');
                    const message = btn.getAttribute('data-message');

                    document.getElementById('logDetailBody').innerHTML = `
                        <p><strong>Timestamp:</strong> ${timestamp}</p>
                        <p><strong>Level:</strong> ${level}</p>
                        <p><strong>Message:</strong> ${message}</p>
                    `;
                    logModal.show();
                }
            });
        </script>
    </body>
    </html>
    """)

@app.route('/api/logs')
def get_logs():
    ensure_log_file()

    with open("intrusion_log.txt", "r") as log:
        logs = log.readlines()
    
    logs.reverse()
    
    page = request.args.get('page', 1, type=int)
    filter_level = request.args.get('filter')
    search_term = request.args.get('search')
    
    parsed_logs = [parse_log_entry(log) for log in logs]
    
    if filter_level:
        parsed_logs = [log for log in parsed_logs if log['level'] == filter_level]
    
    if search_term:
        parsed_logs = [log for log in parsed_logs if search_term.lower() in log['message'].lower()]
    
    per_page = 20
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        'logs': parsed_logs[start:end],
        'has_more': end < len(parsed_logs)
    })

if __name__ == '__main__':
    app.run(debug=True)