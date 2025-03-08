let token = localStorage.getItem('token');
let editor;

require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.36.1/min/vs' }});
require(['vs/editor/editor.main'], function() {
    editor = monaco.editor.create(document.getElementById('monaco-editor'), {
        value: '// Enter your code here\n',
        language: 'python',
        theme: 'vs-dark',
        minimap: { enabled: true },
        automaticLayout: true
    });
});

function checkAuth() {
    if (token) {
        fetch('/profile', {
            headers: { 'Authorization': `Bearer ${token}` }
        }).then(res => {
            if (res.ok) showDashboard();
            else logout();
        });
    }
}

function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
    .then(res => res.json())
    .then(data => {
        if (data.access_token) {
            token = data.access_token;
            localStorage.setItem('token', token);
            showDashboard();
        }
    });
}

function showDashboard() {
    document.getElementById('login').style.display = 'none';
    document.getElementById('dashboard').style.display = 'flex';
    
    fetch('/profile', {
        headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(profile => {
        document.getElementById('username-display').textContent = profile.username;
        loadReports();
    });
}

function uploadCode() {
    const code = editor.getValue();
    document.getElementById('status-text').textContent = 'Scanning code...';

    fetch('/upload', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ code })
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById('status-text').textContent = 'Scan completed';
        showPanel('reports');
        loadReports();
    })
    .catch(() => {
        document.getElementById('status-text').textContent = 'Scan failed';
    });
}

function showPanel(panelName) {
    document.querySelectorAll('.sidebar-item').forEach(item => 
        item.classList.remove('active'));
    document.querySelector(`[onclick="showPanel('${panelName}')"]`)
        .classList.add('active');

    document.getElementById('editor-panel').style.display = 'none';
    document.getElementById('reports-panel').style.display = 'none';
    
    if(panelName === 'editor') {
        document.getElementById('editor-panel').style.display = 'block';
    } else if(panelName === 'reports') {
        document.getElementById('reports-panel').style.display = 'block';
        loadReports();
    }
}

function loadReports() {
    fetch('/reports', {
        headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(res => res.json())
    .then(reports => {
        const reportsDiv = document.getElementById('reports-list');
        reportsDiv.innerHTML = reports.map(report => `
            <div class="report">
                > Scan Report #${report.id}
                ${report.vulnerabilities.map(vul => `
                    <div class="vulnerability ${vul.severity.toLowerCase()}">
                        [${vul.severity}] ${vul.name}
                        <div class="recommendation">▶ ${vul.recommendation}</div>
                    </div>
                `).join('')}
            </div>
        `).join('');
    });
}

function logout() {
    localStorage.removeItem('token');
    token = null;
    document.getElementById('login').style.display = 'flex';
    document.getElementById('dashboard').style.display = 'none';
}

checkAuth();