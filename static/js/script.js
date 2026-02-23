// =============================================
// CODE FORMATTER — Brace-aware auto-indentation
// =============================================
function formatCode(raw) {
    const lines = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    const TAB = '    '; // 4-space tab = one indent level
    let depth = 0;
    const out = [];

    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();

        if (line === '') {
            out.push('');
            continue;
        }

        // Closing brace: dedent BEFORE printing this line
        if (line.startsWith('}')) {
            depth = Math.max(0, depth - 1);
        }

        out.push(TAB.repeat(depth) + line);

        // Count net braces to set indent for the NEXT line
        let opens  = (line.match(/\{/g) || []).length;
        let closes = (line.match(/\}/g) || []).length;

        // We already handled the leading } above, so compensate
        if (line.startsWith('}')) closes--;

        depth = Math.max(0, depth + opens - closes);
    }

    return out.join('\n');
}

// =============================================
// PowerPoint Viewer with PDF-like functionality
// =============================================
class PowerPointViewer {
    constructor() {
        this.currentPage = 1;
        this.totalPages = 1;
        this.zoomLevel = 100;
        this.rotation = 0;
        this.isAnnotationMode = false;
        this.history = [];
        this.historyIndex = -1;

        this.init();
    }

    init() {
        this.bindEvents();
        this.updateUI();
    }

    bindEvents() {
        const sidenavToggle = document.getElementById('sidenavToggle');
        if (sidenavToggle) {
            sidenavToggle.addEventListener('click', () => this.toggleSidenav());
        }

        const pageInput = document.querySelector('.page-input');
        if (pageInput) {
            pageInput.addEventListener('change', (e) => this.goToPage(parseInt(e.target.value)));
            pageInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.goToPage(parseInt(e.target.value));
            });
        }

        const zoomOut = document.querySelector('.icon-btn-remove');
        const zoomIn  = document.querySelector('.icon-btn-add');
        const zoomInput = document.querySelector('.zoom-input');

        if (zoomOut)   zoomOut.addEventListener('click', () => this.zoomOut());
        if (zoomIn)    zoomIn.addEventListener('click',  () => this.zoomIn());
        if (zoomInput) {
            zoomInput.addEventListener('change', (e) => {
                const value = parseInt(e.target.value.replace('%', ''));
                this.setZoom(value);
            });
        }

        const fitBtn = document.getElementById('fit');
        if (fitBtn) fitBtn.addEventListener('click', () => this.fitToWidth());

        const rotateBtn = document.getElementById('rotate');
        if (rotateBtn) rotateBtn.addEventListener('click', () => this.rotate());

        const annotateBtn = document.getElementById('annotate');
        if (annotateBtn) annotateBtn.addEventListener('click', () => this.toggleAnnotation());

        const undoBtn = document.getElementById('undo');
        const redoBtn = document.getElementById('redo');
        if (undoBtn) undoBtn.addEventListener('click', () => this.undo());
        if (redoBtn) redoBtn.addEventListener('click', () => this.redo());

        const downloadBtn = document.querySelector('[title="Download"]');
        const printBtn    = document.querySelector('[title="Print"]');
        if (downloadBtn) downloadBtn.addEventListener('click', () => this.download());
        if (printBtn)    printBtn.addEventListener('click',    () => this.print());

        document.addEventListener('keydown', (e) => this.handleKeyboard(e));

        document.addEventListener('wheel', (e) => {
            if (e.ctrlKey) {
                e.preventDefault();
                e.deltaY < 0 ? this.zoomIn() : this.zoomOut();
            }
        }, { passive: false });
    }

    goToPage(pageNumber) {
        if (pageNumber >= 1 && pageNumber <= this.totalPages) {
            this.currentPage = pageNumber;
            this.updateUI();
            this.renderPage();
            this.saveState();
        }
    }

    nextPage()     { if (this.currentPage < this.totalPages) this.goToPage(this.currentPage + 1); }
    previousPage() { if (this.currentPage > 1)               this.goToPage(this.currentPage - 1); }

    zoomIn()  { this.setZoom(Math.min(this.zoomLevel + 25, 500)); }
    zoomOut() { this.setZoom(Math.max(this.zoomLevel - 25, 25));  }

    setZoom(level) {
        this.zoomLevel = Math.max(25, Math.min(500, level));
        this.updateUI();
        this.applyZoom();
        this.saveState();
    }

    fitToWidth() {
        const viewer    = document.getElementById('document-viewer');
        const container = document.getElementById('document-container');
        if (viewer && container) {
            const viewerWidth    = viewer.clientWidth - 40;
            const containerWidth = container.scrollWidth / (this.zoomLevel / 100);
            const fitZoom        = Math.floor((viewerWidth / containerWidth) * 100);
            this.setZoom(Math.max(25, Math.min(500, fitZoom)));
        }
        const fitBtn = document.getElementById('fit');
        if (fitBtn) {
            fitBtn.classList.add('active');
            setTimeout(() => fitBtn.classList.remove('active'), 200);
        }
    }

    applyZoom() {
        const container = document.getElementById('document-container');
        if (container) {
            container.style.transform       = `scale(${this.zoomLevel / 100}) rotate(${this.rotation}deg)`;
            container.style.transformOrigin = 'top center';
        }
    }

    rotate() {
        this.rotation = (this.rotation + 90) % 360;
        this.applyZoom();
        this.saveState();
        const rotateBtn = document.getElementById('rotate');
        if (rotateBtn) rotateBtn.querySelector('i').style.transform = `rotate(${this.rotation}deg)`;
    }

    toggleAnnotation() {
        this.isAnnotationMode = !this.isAnnotationMode;
        const annotateBtn = document.getElementById('annotate');
        if (annotateBtn) annotateBtn.classList.toggle('active', this.isAnnotationMode);
        this.isAnnotationMode ? this.enableDrawing() : this.disableDrawing();
    }

    enableDrawing() {
        const slideContainer = document.getElementById('document-container') || document.body;
        if (!document.getElementById('drawing-canvas')) {
            const canvas = document.createElement('canvas');
            canvas.id = 'drawing-canvas';
            Object.assign(canvas.style, {
                position: 'absolute', top: '0', left: '0',
                pointerEvents: 'auto', cursor: 'crosshair'
            });
            canvas.width  = slideContainer.offsetWidth;
            canvas.height = slideContainer.offsetHeight;
            slideContainer.style.position = 'relative';
            slideContainer.appendChild(canvas);
            this.setupDrawing(canvas);
        } else {
            const c = document.getElementById('drawing-canvas');
            c.style.pointerEvents = 'auto';
            c.style.cursor        = 'crosshair';
        }
    }

    disableDrawing() {
        const canvas = document.getElementById('drawing-canvas');
        if (canvas) { canvas.style.pointerEvents = 'none'; canvas.style.cursor = 'default'; }
    }

    setupDrawing(canvas) {
        const ctx = canvas.getContext('2d');
        ctx.strokeStyle = '#e74c3c';
        ctx.lineWidth   = 2;
        let isDrawing   = false;

        canvas.addEventListener('mousedown', (e) => {
            if (this.isAnnotationMode) { isDrawing = true; ctx.beginPath(); ctx.moveTo(e.offsetX, e.offsetY); }
        });
        canvas.addEventListener('mousemove', (e) => {
            if (isDrawing && this.isAnnotationMode) { ctx.lineTo(e.offsetX, e.offsetY); ctx.stroke(); }
        });
        canvas.addEventListener('mouseup', () => {
            if (isDrawing) { isDrawing = false; this.saveState(); }
        });
    }

    saveState() {
        const state = { page: this.currentPage, zoom: this.zoomLevel, rotation: this.rotation, timestamp: Date.now() };
        this.history = this.history.slice(0, this.historyIndex + 1);
        this.history.push(state);
        this.historyIndex = this.history.length - 1;
        if (this.history.length > 50) { this.history = this.history.slice(-50); this.historyIndex = this.history.length - 1; }
        this.updateUndoRedoButtons();
    }

    undo() { if (this.historyIndex > 0) { this.historyIndex--; this.restoreState(this.history[this.historyIndex]); } }
    redo() { if (this.historyIndex < this.history.length - 1) { this.historyIndex++; this.restoreState(this.history[this.historyIndex]); } }

    restoreState(state) {
        this.currentPage = state.page;
        this.zoomLevel   = state.zoom;
        this.rotation    = state.rotation;
        this.updateUI();
        this.applyZoom();
        this.renderPage();
        this.updateUndoRedoButtons();
    }

    updateUndoRedoButtons() {
        const undoBtn = document.getElementById('undo');
        const redoBtn = document.getElementById('redo');
        if (undoBtn) undoBtn.disabled = this.historyIndex <= 0;
        if (redoBtn) redoBtn.disabled = this.historyIndex >= this.history.length - 1;
    }

    handleKeyboard(e) {
        if (e.ctrlKey) {
            switch (e.key) {
                case '=': case '+': e.preventDefault(); this.zoomIn();        break;
                case '-':           e.preventDefault(); this.zoomOut();       break;
                case '0':           e.preventDefault(); this.setZoom(100);   break;
                case 'z':           e.preventDefault(); e.shiftKey ? this.redo() : this.undo(); break;
                case 'p':           e.preventDefault(); this.print();         break;
            }
        }
        switch (e.key) {
            case 'ArrowRight': case 'PageDown': e.preventDefault(); this.nextPage();              break;
            case 'ArrowLeft':  case 'PageUp':   e.preventDefault(); this.previousPage();           break;
            case 'Home':                        e.preventDefault(); this.goToPage(1);             break;
            case 'End':                         e.preventDefault(); this.goToPage(this.totalPages); break;
            case 'Escape': if (this.isAnnotationMode) this.toggleAnnotation(); break;
        }
    }

    toggleSidenav() {
        let sidenav = document.getElementById('sidenav');
        if (!sidenav) sidenav = this.createSideNav();

        const toggle = document.getElementById('sidenavToggle');
        const isOpen = sidenav.classList.contains('open');

        if (isOpen) {
            sidenav.classList.remove('open');
            sidenav.style.transform = 'translateX(-100%)';
            toggle && toggle.setAttribute('aria-expanded', 'false');
            const overlay = document.getElementById('sidenav-overlay');
            if (overlay) overlay.remove();
        } else {
            sidenav.style.display = 'block';
            sidenav.getBoundingClientRect();
            sidenav.classList.add('open');
            sidenav.style.transform = 'translateX(0)';
            toggle && toggle.setAttribute('aria-expanded', 'true');

            if (!document.getElementById('sidenav-overlay')) {
                const overlay = document.createElement('div');
                overlay.id = 'sidenav-overlay';
                overlay.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.4);z-index:999;';
                overlay.addEventListener('click', () => this.toggleSidenav());
                document.body.appendChild(overlay);
            }
        }
    }

    createSideNav() {
        const sidenav = document.createElement('div');
        sidenav.id = 'sidenav';
        sidenav.style.cssText = `
            position:fixed;top:0;left:0;width:220px;height:100vh;
            background:#2b2b2b;color:white;border-right:1px solid #444;
            transform:translateX(-100%);transition:transform 0.25s ease;
            z-index:1000;padding:70px 16px 20px;box-sizing:border-box;display:none;
        `;
        sidenav.innerHTML = `
            <h3 style="font-size:13px;color:#aaa;text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;">Slides</h3>
            <div id="slide-thumbnails">
                ${Array.from({length: this.totalPages}, (_, i) => `
                    <div onclick="window.pptViewer.goToPage(${i+1});window.pptViewer.toggleSidenav();"
                         style="padding:10px 12px;margin:4px 0;border:1px solid #444;cursor:pointer;
                                border-radius:4px;font-size:13px;background:#3c3c3c;transition:background 0.2s;"
                         onmouseover="this.style.background='#505050'"
                         onmouseout="this.style.background='#3c3c3c'">
                        Slide ${i+1}
                    </div>
                `).join('')}
            </div>
        `;
        document.body.appendChild(sidenav);
        return sidenav;
    }

    download() {
        try {
            const title    = document.getElementById('title').textContent || 'presentation';
            const filename = title.replace(/Microsoft PowerPoint - /, '').replace(/ - Compatibility Mode/, '') || 'presentation.pptx';
            const fileUrl  = window.fileUrl || null;
            if (fileUrl) {
                const link = document.createElement('a');
                link.href = fileUrl; link.download = filename; link.style.display = 'none';
                document.body.appendChild(link); link.click(); document.body.removeChild(link);
                return;
            }
            this.downloadAsHTML(filename);
        } catch (error) {
            console.error('Download failed:', error);
            alert('Download functionality requires server setup.');
        }
    }

    downloadAsHTML(filename) {
        const blob = new Blob([document.documentElement.outerHTML], { type: 'text/html' });
        const url  = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url; link.download = filename.replace('.pptx', '.html'); link.style.display = 'none';
        document.body.appendChild(link); link.click(); document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(url), 100);
    }

    print() {
        const originalTitle = document.title;
        document.title = (document.getElementById('title')?.textContent || 'Presentation')
            .replace(/Microsoft PowerPoint - /, '').replace(/ - Compatibility Mode/, '');
        const toolbar = document.getElementById('toolbar');
        if (toolbar) toolbar.style.display = 'none';
        setTimeout(() => {
            window.print();
            setTimeout(() => {
                if (toolbar) toolbar.style.display = '';
                document.title = originalTitle;
            }, 500);
        }, 100);
    }

    renderPage() {
        const allSlides = document.querySelectorAll('[data-slide], .slide');
        allSlides.forEach(slide => { slide.style.display = 'none'; slide.classList.remove('active', 'current-slide'); });
        const currentSlide = document.querySelector(`[data-slide="${this.currentPage}"]`);
        if (currentSlide) {
            currentSlide.style.display = 'block';
            currentSlide.classList.add('active', 'current-slide');
            this.applyZoom();
        }
    }

    updateUI() {
        const pageInput = document.querySelector('.page-input');
        if (pageInput) pageInput.value = this.currentPage;
        const pageTotal = document.querySelector('.page-total');
        if (pageTotal) pageTotal.textContent = `/ ${this.totalPages}`;
        const zoomInput = document.querySelector('.zoom-input');
        if (zoomInput) zoomInput.value = `${this.zoomLevel}%`;
        this.updateUndoRedoButtons();
    }

    setTotalPages(total) { this.totalPages = total; this.updateUI(); }

    getCurrentState() {
        return { page: this.currentPage, totalPages: this.totalPages, zoom: this.zoomLevel, rotation: this.rotation, isAnnotationMode: this.isAnnotationMode };
    }
}

// =============================================
// ANSWER RENDERER — with brace-aware formatting
// =============================================
function renderAnswer(rawAnswer) {
    // 1. Protect fenced code blocks: extract them, format, then re-inject
    const codeBlocks = [];
    let html = rawAnswer
        // Fenced code with language tag  ```lang\n...\n```
        .replace(/```[a-z]*\n([\s\S]*?)```/gi, (_, code) => {
            const idx = codeBlocks.length;
            codeBlocks.push('<pre><code>' + formatCode(code) + '</code></pre>');
            return `%%CODEBLOCK_${idx}%%`;
        })
        // Fenced code without language tag  ```...```
        .replace(/```([\s\S]*?)```/g, (_, code) => {
            const idx = codeBlocks.length;
            codeBlocks.push('<pre><code>' + formatCode(code) + '</code></pre>');
            return `%%CODEBLOCK_${idx}%%`;
        });

    // 2. Apply remaining markdown transforms (headings, bold, italic, inline code, lists)
    html = html
        .replace(/^### (.+)$/gm, '<h3>$1</h3>')
        .replace(/^## (.+)$/gm,  '<h2>$1</h2>')
        .replace(/^# (.+)$/gm,   '<h1>$1</h1>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*([^*]+)\*/g,   '<em>$1</em>')
        .replace(/`([^`]+)`/g,     '<code>$1</code>')
        .replace(/^(\d+)\.\s+(.+)$/gm, "<li data-number='$1'>$2</li>")
        .replace(/^[-*]\s+(.+)$/gm,    '<li>$1</li>')
        .replace(/\n\n/g, '<br><br>')
        .replace(/\n/g, '<br>');

    // 3. Wrap bare <li> runs in <ul>/<ol>
    html = html.replace(
        /(<li(?:\s+data-number='\d+')?>[^<]*<\/li>(?:<br>)*)+/g,
        (match) => {
            const clean = match.replace(/<br>/g, '');
            return clean.includes("data-number=")
                ? '<ol>' + clean.replace(/\s+data-number='\d+'/g, '') + '</ol>'
                : '<ul>' + clean + '</ul>';
        }
    );

    // 4. Re-inject formatted code blocks
    codeBlocks.forEach((block, idx) => {
        html = html.replace(`%%CODEBLOCK_${idx}%%`, block);
    });

    return html;
}

// =============================================
// Init
// =============================================
document.addEventListener('DOMContentLoaded', () => {
    window.pptViewer = new PowerPointViewer();

    // Patch search form to use renderAnswer()
    const sf = document.getElementById('searchForm');
    if (sf) {
        sf.addEventListener('submit', function(e) { e.preventDefault(); });
    }
});

// Make renderAnswer globally available so index.html inline script can call it
window.renderAnswer = renderAnswer;

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PowerPointViewer, formatCode, renderAnswer };
}