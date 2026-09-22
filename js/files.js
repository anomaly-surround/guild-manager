// File vault tab (R2 uploads)

// --- File Vault ---

async function loadAndRenderFiles() {
    teamTab = 'files';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/files`);
    const el = document.getElementById('filesContent');
    if (el) el.innerHTML = renderFilesContent(data.files || [], data.totalBytes || 0);
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function getFileIcon(contentType, name) {
    if (contentType.startsWith('image/')) return '🖼️';
    if (contentType.startsWith('video/')) return '🎬';
    if (contentType.startsWith('audio/')) return '🎵';
    if (contentType.includes('pdf')) return '📄';
    if (contentType.includes('spreadsheet') || name.match(/\.(xlsx?|csv)$/i)) return '📊';
    if (contentType.includes('document') || name.match(/\.(docx?|txt)$/i)) return '📝';
    if (contentType.includes('zip') || name.match(/\.(zip|rar|7z)$/i)) return '📦';
    return '📎';
}

function renderFilesContent(files, totalBytes) {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    const premium = team.premium_team;
    const storageLimit = premium ? 500 * 1024 * 1024 : 100 * 1024 * 1024;
    const usedPct = Math.round((totalBytes / storageLimit) * 100);
    let html = '';

    // Storage bar
    html += `<div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <h3>Storage</h3>
            <span style="font-size:0.85em;color:var(--text-muted)">${formatFileSize(totalBytes)} / ${premium ? '500 MB' : '100 MB'}</span>
        </div>
        <div style="background:var(--bg-input);border-radius:6px;height:8px;overflow:hidden">
            <div style="background:linear-gradient(90deg,var(--accent),var(--accent2));height:100%;width:${Math.min(usedPct, 100)}%;border-radius:6px;transition:width 0.3s"></div>
        </div>
    </div>`;

    // Upload form
    html += `<div class="card">
        <div class="collapsible-header" onclick="toggleSection('uploadFileForm', this)">
            <h3>+ Upload File</h3>
            <span class="toggle-arrow">&#9660;</span>
        </div>
        <div class="collapsible-body" id="uploadFileForm">
            <div style="margin-top:12px">
                <input type="file" id="fileInput" style="margin-bottom:8px">
                <div style="font-size:0.8em;color:var(--text-dim);margin-bottom:8px">Max 5MB per file. Accepts images, documents, spreadsheets, etc.</div>
                <button class="btn btn-primary" onclick="uploadFile()">Upload</button>
                <div id="uploadProgress" style="display:none;margin-top:8px;font-size:0.85em;color:var(--accent)">Uploading...</div>
            </div>
        </div>
    </div>`;

    // Files list
    html += '<div class="card"><h3>Files (' + files.length + ')</h3>';
    if (files.length === 0) {
        html += '<div class="empty-state">No files uploaded yet</div>';
    }
    for (const f of files) {
        const date = new Date(f.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        const icon = getFileIcon(f.content_type, f.file_name);
        const isImage = f.content_type.startsWith('image/');

        html += `<div class="dkp-row" style="padding:10px 0;align-items:flex-start">
            <div style="display:flex;gap:10px;align-items:center;flex:1;min-width:0">
                <span style="font-size:1.4em">${icon}</span>
                <div style="min-width:0;flex:1">
                    <div style="font-weight:600;font-size:0.9em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(f.file_name)}</div>
                    <div style="font-size:0.75em;color:var(--text-dim)">${formatFileSize(f.file_size)} &middot; ${escapeHtml(f.uploaded_by_name)} &middot; ${date}</div>
                </div>
            </div>
            <div style="display:flex;gap:4px;flex-shrink:0">
                ${isImage ? `<button class="btn btn-secondary btn-sm" onclick="previewFile('${f.id}','${escapeHtml(f.file_name)}','${f.content_type}')" style="font-size:0.75em">Preview</button>` : ''}
                <button class="btn btn-secondary btn-sm" onclick="downloadFile('${f.id}')" style="font-size:0.75em">Download</button>
                ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deleteFile('${f.id}')" style="font-size:0.75em">X</button>` : ''}
            </div>
        </div>`;
    }
    html += '</div>';
    return html;
}

const uploadFile = guard('uploadFile', async function() {
    const input = document.getElementById('fileInput');
    if (!input.files || !input.files[0]) return showToast('Select a file first');
    const file = input.files[0];
    if (file.size > 5 * 1024 * 1024) return showToast('File too large (max 5MB)');

    const progress = document.getElementById('uploadProgress');
    if (progress) progress.style.display = 'block';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch(API + `/api/teams/${currentTeamId}/files`, {
            method: 'POST',
            headers: token ? { 'Authorization': `Bearer ${token}` } : {},
            body: formData,
        });
        const data = await res.json();
        if (data.error) { showToast(data.error); return; }
        showToast('File uploaded!');
        loadAndRenderFiles();
    } catch(e) {
        showToast('Upload failed');
    } finally {
        if (progress) progress.style.display = 'none';
    }
});

function downloadFile(fileId) {
    window.open(API + `/api/teams/${currentTeamId}/files/${fileId}/download?token=${token}`, '_blank');
}

function previewFile(fileId, fileName, contentType) {
    const url = API + `/api/teams/${currentTeamId}/files/${fileId}/download?token=${token}`;
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:700px;max-width:95vw;margin:0;max-height:90vh;overflow:auto">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                    <h3 style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(fileName)}</h3>
                    <button class="btn btn-sm" style="background:var(--bg-input);color:var(--text-muted)" onclick="document.getElementById('deathModal').innerHTML=''">✕</button>
                </div>
                <img src="${url}" style="max-width:100%;border-radius:8px" alt="${escapeHtml(fileName)}">
            </div>
        </div>`;
}

const deleteFile = guard('deleteFile', async function(fileId) {
    await api('DELETE', `/api/teams/${currentTeamId}/files/${fileId}`);
    showToast('File deleted');
    loadAndRenderFiles();
});
