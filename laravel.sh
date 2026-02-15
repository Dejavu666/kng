#!/bin/bash

# ══════════════════════════════════════════════════════════════
# 🔐 HIDDEN VAULT UPLOADER — ONE-COMMAND INSTALLER
# ══════════════════════════════════════════════════════════════
# Usage:
#   chmod +x install-vault.sh
#   ./install-vault.sh /var/www/your-laravel-project
#
# Atau langsung:
#   bash install-vault.sh /var/www/your-laravel-project
# ══════════════════════════════════════════════════════════════

set -e

# ── WARNA ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  🔐 Hidden Vault Uploader — Installer${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
    echo ""
}

log_info()    { echo -e "  ${BLUE}ℹ${NC}  $1"; }
log_success() { echo -e "  ${GREEN}✓${NC}  $1"; }
log_warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
log_error()   { echo -e "  ${RED}✕${NC}  $1"; }
log_step()    { echo -e "\n${BOLD}[$1/8]${NC} $2"; }

# ══════════════════════════════════════════════════════════════
# VALIDASI
# ══════════════════════════════════════════════════════════════
print_banner

LARAVEL_PATH="${1}"

if [ -z "$LARAVEL_PATH" ]; then
    echo -e "${YELLOW}Usage:${NC} bash install-vault.sh /path/to/laravel-project"
    echo ""
    echo "  Contoh:"
    echo "    bash install-vault.sh /var/www/mysite"
    echo "    bash install-vault.sh /home/user/laravel-app"
    echo ""
    exit 1
fi

# Hapus trailing slash
LARAVEL_PATH="${LARAVEL_PATH%/}"

if [ ! -f "$LARAVEL_PATH/artisan" ]; then
    log_error "Bukan project Laravel! File 'artisan' tidak ditemukan di: $LARAVEL_PATH"
    exit 1
fi

if [ ! -f "$LARAVEL_PATH/composer.json" ]; then
    log_error "composer.json tidak ditemukan di: $LARAVEL_PATH"
    exit 1
fi

log_success "Project Laravel ditemukan: $LARAVEL_PATH"

# ── Detect Laravel version ──
LARAVEL_VERSION=$(php "$LARAVEL_PATH/artisan" --version 2>/dev/null | grep -oP '\d+' | head -1 || echo "10")
log_info "Laravel version: $LARAVEL_VERSION"

# ── Generate credentials ──
VAULT_KEY=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
VAULT_PATH="sys-$(openssl rand -hex 4)"

echo ""
echo -e "${BOLD}Konfigurasi Vault:${NC}"
echo -e "  Access Key  : ${GREEN}${VAULT_KEY}${NC}"
echo -e "  URL Path    : ${GREEN}/${VAULT_PATH}${NC}"
echo ""
read -p "  Lanjutkan instalasi? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    log_warn "Instalasi dibatalkan."
    exit 0
fi

# ══════════════════════════════════════════════════════════════
# STEP 1: Buat Controller
# ══════════════════════════════════════════════════════════════
log_step 1 "Membuat VaultController..."

mkdir -p "$LARAVEL_PATH/app/Http/Controllers"

cat > "$LARAVEL_PATH/app/Http/Controllers/VaultController.php" << 'CONTROLLER_EOF'
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class VaultController extends Controller
{
    public function index()
    {
        return view('vault.index');
    }

    public function auth(Request $request)
    {
        $key = $request->input('key');
        $valid = config('vault.access_key');

        if ($key === $valid) {
            $request->session()->put('vault_token', $key);
            Log::channel('vault')->info('Vault login', ['ip' => $request->ip(), 'agent' => $request->userAgent()]);
            return response()->json(['success' => true]);
        }

        Log::channel('vault')->warning('Vault login failed', ['ip' => $request->ip()]);
        return response()->json(['success' => false], 401);
    }

    public function listFiles(Request $request)
    {
        $allFiles = collect(Storage::disk('vault')->allFiles())
            ->reject(fn($path) => str_starts_with($path, '.meta/'))
            ->map(function ($path) {
                $fullPath = Storage::disk('vault')->path($path);
                $meta = $this->getFileMeta($path);
                return [
                    'id'          => md5($path),
                    'name'        => $meta['original_name'] ?? basename($path),
                    'path'        => $path,
                    'size'        => Storage::disk('vault')->size($path),
                    'type'        => $this->getMimeType($fullPath, $path),
                    'category'    => $meta['category'] ?? $this->guessCategoryFromPath($path),
                    'uploaded_at' => $meta['uploaded_at'] ?? date('c', Storage::disk('vault')->lastModified($path)),
                    'url'         => route('vault.download', ['id' => md5($path)]),
                ];
            })
            ->sortByDesc('uploaded_at')
            ->values();

        return response()->json([
            'files'   => $allFiles,
            'storage' => [
                'used'  => $allFiles->sum('size'),
                'total' => config('vault.max_storage', 500 * 1024 * 1024),
            ],
        ]);
    }

    public function upload(Request $request)
    {
        $request->validate([
            'files'   => 'required|array|min:1',
            'files.*' => 'file|max:102400',
        ]);

        $maxStorage = config('vault.max_storage', 500 * 1024 * 1024);
        $currentUsage = $this->getCurrentUsage();
        $uploaded = [];
        $errors = [];

        foreach ($request->file('files') as $file) {
            $originalName = $file->getClientOriginalName();
            $ext = strtolower($file->getClientOriginalExtension());

            $allowed = config('vault.allowed_extensions', []);
            if (!empty($allowed) && !in_array($ext, $allowed)) {
                $errors[] = "{$originalName}: ekstensi .{$ext} tidak diizinkan";
                continue;
            }

            if ($currentUsage + $file->getSize() > $maxStorage) {
                $errors[] = "{$originalName}: storage penuh";
                continue;
            }

            $category = $this->guessCategoryFromExtension($ext, $file->getMimeType());
            $safeName = $this->generateSafeFilename($originalName);
            $storagePath = $category . '/' . $safeName;

            Storage::disk('vault')->put($storagePath, file_get_contents($file->getRealPath()));

            $this->saveFileMeta($storagePath, [
                'original_name' => $originalName,
                'category'      => $category,
                'extension'     => $ext,
                'mime_type'     => $file->getMimeType(),
                'size'          => $file->getSize(),
                'uploaded_at'   => now()->toIso8601String(),
                'ip'            => $request->ip(),
            ]);

            $currentUsage += $file->getSize();

            $uploaded[] = [
                'id'          => md5($storagePath),
                'name'        => $originalName,
                'path'        => $storagePath,
                'size'        => $file->getSize(),
                'type'        => $file->getMimeType(),
                'category'    => $category,
                'uploaded_at' => now()->toIso8601String(),
                'url'         => route('vault.download', ['id' => md5($storagePath)]),
            ];
        }

        Log::channel('vault')->info('Vault upload', ['count' => count($uploaded), 'ip' => $request->ip()]);

        return response()->json([
            'message' => count($uploaded) . ' file berhasil diupload',
            'files'   => $uploaded,
            'errors'  => $errors,
        ]);
    }

    public function download($id)
    {
        $file = $this->findFileById($id);
        if (!$file) return response()->json(['error' => 'File tidak ditemukan'], 404);

        $meta = $this->getFileMeta($file['path']);
        $originalName = $meta['original_name'] ?? basename($file['path']);

        return Storage::disk('vault')->download(
            $file['path'], $originalName, $this->getDownloadHeaders($originalName)
        );
    }

    public function preview($id)
    {
        $file = $this->findFileById($id);
        if (!$file) return response()->json(['error' => 'File tidak ditemukan'], 404);

        $fullPath = Storage::disk('vault')->path($file['path']);
        $mime = $this->getMimeType($fullPath, $file['path']);

        if (!str_starts_with($mime, 'image/')) {
            return response()->json(['error' => 'Preview hanya untuk gambar'], 422);
        }

        return response()->file($fullPath, [
            'Content-Type' => $mime,
            'Cache-Control' => 'private, max-age=3600',
        ]);
    }

    public function viewContent($id)
    {
        $file = $this->findFileById($id);
        if (!$file) return response()->json(['error' => 'File tidak ditemukan'], 404);

        $meta = $this->getFileMeta($file['path']);
        $ext = $meta['extension'] ?? pathinfo($file['path'], PATHINFO_EXTENSION);
        $viewable = ['php','js','ts','css','scss','html','json','xml','yaml','yml',
                      'env','conf','ini','txt','md','sql','sh','py','rb','java','go',
                      'vue','jsx','tsx','svg','htaccess','log','blade.php'];

        if (!in_array($ext, $viewable)) {
            return response()->json(['error' => 'Tipe file tidak bisa ditampilkan'], 422);
        }

        $content = Storage::disk('vault')->get($file['path']);
        $size = Storage::disk('vault')->size($file['path']);

        if ($size > 2 * 1024 * 1024) {
            $content = mb_substr($content, 0, 500000) . "\n\n... [truncated] ...";
        }

        return response()->json([
            'name'      => $meta['original_name'] ?? basename($file['path']),
            'extension' => $ext,
            'content'   => $content,
            'size'      => $size,
        ]);
    }

    public function delete($id, Request $request)
    {
        $file = $this->findFileById($id);
        if (!$file) return response()->json(['error' => 'File tidak ditemukan'], 404);

        Storage::disk('vault')->delete($file['path']);
        $this->deleteFileMeta($file['path']);

        Log::channel('vault')->info('Vault delete', ['file' => $file['name'], 'ip' => $request->ip()]);
        return response()->json(['message' => 'File berhasil dihapus']);
    }

    public function rename($id, Request $request)
    {
        $request->validate(['name' => 'required|string|max:255']);
        $file = $this->findFileById($id);
        if (!$file) return response()->json(['error' => 'File tidak ditemukan'], 404);

        $meta = $this->getFileMeta($file['path']);
        $meta['original_name'] = $request->input('name');
        $this->saveFileMeta($file['path'], $meta);

        return response()->json(['message' => 'File berhasil direname']);
    }

    // ── Helpers ──

    private function findFileById(string $id): ?array
    {
        foreach (Storage::disk('vault')->allFiles() as $path) {
            if (str_starts_with($path, '.meta/')) continue;
            if (md5($path) === $id) {
                return ['id' => $id, 'name' => basename($path), 'path' => $path];
            }
        }
        return null;
    }

    private function generateSafeFilename(string $original): string
    {
        $name = pathinfo($original, PATHINFO_FILENAME);
        $ext  = pathinfo($original, PATHINFO_EXTENSION);
        $slug = Str::slug($name) ?: 'file';
        return $slug . '-' . Str::random(8) . '.' . $ext;
    }

    private function guessCategoryFromExtension(string $ext, string $mime = ''): string
    {
        $map = [
            'images'    => ['jpg','jpeg','png','gif','svg','webp','ico','bmp','tiff'],
            'documents' => ['pdf','doc','docx','xls','xlsx','csv','ppt','pptx','txt','md','rtf'],
            'backups'   => ['zip','rar','tar','gz','7z','sql','bak','dump'],
            'configs'   => ['env','conf','ini','yaml','yml','json','xml','toml','htaccess','lock'],
        ];
        foreach ($map as $cat => $exts) {
            if (in_array($ext, $exts)) return $cat;
        }
        $codeExts = ['php','js','ts','jsx','tsx','vue','css','scss','less','py','rb','java','go','rs','sh','bash','bat'];
        if (in_array($ext, $codeExts)) return 'configs';
        return 'documents';
    }

    private function guessCategoryFromPath(string $path): string
    {
        $dir = explode('/', $path)[0] ?? '';
        return in_array($dir, ['documents','images','backups','configs']) ? $dir : 'documents';
    }

    private function getMimeType(string $fullPath, string $path): string
    {
        $codeExts = ['php','js','ts','jsx','tsx','vue','css','scss','py','rb','sh','bash'];
        $ext = pathinfo($path, PATHINFO_EXTENSION);
        if (in_array($ext, $codeExts)) return 'text/plain';
        if (file_exists($fullPath)) return mime_content_type($fullPath) ?: 'application/octet-stream';
        return 'application/octet-stream';
    }

    private function getDownloadHeaders(string $filename): array
    {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $headers = [
            'Content-Disposition' => 'attachment; filename="' . $filename . '"',
            'X-Content-Type-Options' => 'nosniff',
        ];
        $exec = ['php','phtml','phar','sh','bash','bat','ps1','exe','py','rb'];
        if (in_array($ext, $exec)) $headers['Content-Type'] = 'application/octet-stream';
        return $headers;
    }

    private function getCurrentUsage(): int
    {
        return collect(Storage::disk('vault')->allFiles())
            ->reject(fn($p) => str_starts_with($p, '.meta/'))
            ->sum(fn($p) => Storage::disk('vault')->size($p));
    }

    private function getFileMeta(string $path): array
    {
        $metaPath = '.meta/' . md5($path) . '.json';
        if (Storage::disk('vault')->exists($metaPath)) {
            return json_decode(Storage::disk('vault')->get($metaPath), true) ?? [];
        }
        return [];
    }

    private function saveFileMeta(string $path, array $meta): void
    {
        Storage::disk('vault')->put('.meta/' . md5($path) . '.json', json_encode($meta, JSON_PRETTY_PRINT));
    }

    private function deleteFileMeta(string $path): void
    {
        Storage::disk('vault')->delete('.meta/' . md5($path) . '.json');
    }
}
CONTROLLER_EOF

log_success "VaultController.php dibuat"

# ══════════════════════════════════════════════════════════════
# STEP 2: Buat Middleware
# ══════════════════════════════════════════════════════════════
log_step 2 "Membuat VaultAuth Middleware..."

mkdir -p "$LARAVEL_PATH/app/Http/Middleware"

cat > "$LARAVEL_PATH/app/Http/Middleware/VaultAuth.php" << 'MIDDLEWARE_EOF'
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class VaultAuth
{
    public function handle(Request $request, Closure $next): Response
    {
        $validKey = config('vault.access_key');
        $isApi = str_contains($request->path(), '/api/');

        if (str_ends_with($request->path(), '/api/auth')) {
            return $next($request);
        }

        if (!$isApi) {
            return $next($request);
        }

        $token = $request->session()->get('vault_token')
            ?? $request->header('X-Vault-Key')
            ?? $request->query('_key');

        if ($token !== $validKey) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $allowedIps = config('vault.allowed_ips', []);
        if (!empty($allowedIps) && !in_array($request->ip(), $allowedIps)) {
            return response()->json(['error' => 'IP not allowed'], 403);
        }

        return $next($request);
    }
}
MIDDLEWARE_EOF

log_success "VaultAuth.php dibuat"

# ══════════════════════════════════════════════════════════════
# STEP 3: Buat Config
# ══════════════════════════════════════════════════════════════
log_step 3 "Membuat config/vault.php..."

cat > "$LARAVEL_PATH/config/vault.php" << 'CONFIG_EOF'
<?php

return [
    'access_key'    => env('VAULT_ACCESS_KEY', 'change-me'),
    'secret_path'   => env('VAULT_SECRET_PATH', 'vault-panel'),
    'max_storage'   => env('VAULT_MAX_STORAGE', 500 * 1024 * 1024),
    'max_file_size' => env('VAULT_MAX_FILE_SIZE', 102400),
    'allowed_ips'   => array_filter(explode(',', env('VAULT_ALLOWED_IPS', ''))),
    'allowed_extensions' => [
        'pdf','doc','docx','xls','xlsx','csv','ppt','pptx','txt','md','rtf',
        'jpg','jpeg','png','gif','svg','webp','ico','bmp',
        'zip','rar','tar','gz','7z',
        'php','js','ts','jsx','tsx','vue','css','scss','less',
        'html','htm','json','xml','yaml','yml','toml',
        'env','conf','ini','htaccess','lock',
        'py','rb','java','go','rs','sh','bash',
        'sql','dump','bak',
        'mp4','mp3','avi','mov','webm','ogg',
        'ttf','otf','woff','woff2',
        'log','map',
    ],
];
CONFIG_EOF

log_success "config/vault.php dibuat"

# ══════════════════════════════════════════════════════════════
# STEP 4: Buat Routes
# ══════════════════════════════════════════════════════════════
log_step 4 "Membuat routes/vault.php & register..."

cat > "$LARAVEL_PATH/routes/vault.php" << 'ROUTES_EOF'
<?php

use App\Http\Controllers\VaultController;
use Illuminate\Support\Facades\Route;

$secretPath = config('vault.secret_path', 'vault-panel');

Route::prefix($secretPath)->middleware(['web', 'vault.auth'])->group(function () {
    Route::get('/', [VaultController::class, 'index'])->name('vault.index');

    Route::prefix('api')->group(function () {
        Route::post('/auth', [VaultController::class, 'auth'])->name('vault.auth');
        Route::get('/files', [VaultController::class, 'listFiles'])->name('vault.files');
        Route::post('/upload', [VaultController::class, 'upload'])->name('vault.upload');
        Route::delete('/files/{id}', [VaultController::class, 'delete'])->name('vault.delete');
        Route::get('/files/{id}/download', [VaultController::class, 'download'])->name('vault.download');
        Route::get('/files/{id}/preview', [VaultController::class, 'preview'])->name('vault.preview');
        Route::get('/files/{id}/view', [VaultController::class, 'viewContent'])->name('vault.view');
        Route::patch('/files/{id}/rename', [VaultController::class, 'rename'])->name('vault.rename');
    });
});
ROUTES_EOF

# Register route di web.php jika belum ada
if ! grep -q "vault.php" "$LARAVEL_PATH/routes/web.php" 2>/dev/null; then
    echo "" >> "$LARAVEL_PATH/routes/web.php"
    echo "// Hidden Vault Uploader" >> "$LARAVEL_PATH/routes/web.php"
    echo "require __DIR__ . '/vault.php';" >> "$LARAVEL_PATH/routes/web.php"
    log_success "Route vault.php di-register ke web.php"
else
    log_warn "Route vault.php sudah ada di web.php, skip"
fi

log_success "routes/vault.php dibuat"

# ══════════════════════════════════════════════════════════════
# STEP 5: Register Middleware
# ══════════════════════════════════════════════════════════════
log_step 5 "Register middleware..."

if [ "$LARAVEL_VERSION" -ge 11 ]; then
    # Laravel 11+ — bootstrap/app.php
    BOOTSTRAP="$LARAVEL_PATH/bootstrap/app.php"
    if [ -f "$BOOTSTRAP" ]; then
        if ! grep -q "vault.auth" "$BOOTSTRAP" 2>/dev/null; then
            # Cari baris withMiddleware dan inject alias
            if grep -q "withMiddleware" "$BOOTSTRAP"; then
                sed -i '/->withMiddleware/,/})/ {
                    /->withMiddleware/ {
                        N
                        s/->withMiddleware(function (Middleware \$middleware) {/->withMiddleware(function (Middleware $middleware) {\n        $middleware->alias([\n            '\''vault.auth'\'' => \\App\\Http\\Middleware\\VaultAuth::class,\n        ]);/
                    }
                }' "$BOOTSTRAP"

                if grep -q "vault.auth" "$BOOTSTRAP"; then
                    log_success "Middleware registered di bootstrap/app.php (Laravel 11+)"
                else
                    log_warn "Gagal auto-register middleware. Tambahkan manual di bootstrap/app.php:"
                    echo -e "    ${YELLOW}\$middleware->alias(['vault.auth' => \\App\\Http\\Middleware\\VaultAuth::class]);${NC}"
                fi
            else
                log_warn "withMiddleware tidak ditemukan di bootstrap/app.php"
                log_warn "Tambahkan manual: \$middleware->alias(['vault.auth' => \\App\\Http\\Middleware\\VaultAuth::class]);"
            fi
        else
            log_warn "Middleware vault.auth sudah terdaftar, skip"
        fi
    fi
else
    # Laravel 10 — Kernel.php
    KERNEL="$LARAVEL_PATH/app/Http/Kernel.php"
    if [ -f "$KERNEL" ]; then
        if ! grep -q "vault.auth" "$KERNEL" 2>/dev/null; then
            sed -i "s/'verified' => \\\\Illuminate\\\\Auth\\\\Middleware\\\\EnsureEmailIsVerified::class,/'verified' => \\\\Illuminate\\\\Auth\\\\Middleware\\\\EnsureEmailIsVerified::class,\n        'vault.auth' => \\\\App\\\\Http\\\\Middleware\\\\VaultAuth::class,/" "$KERNEL"

            if grep -q "vault.auth" "$KERNEL"; then
                log_success "Middleware registered di Kernel.php (Laravel 10)"
            else
                log_warn "Gagal auto-register. Tambahkan manual di Kernel.php \$middlewareAliases:"
                echo -e "    ${YELLOW}'vault.auth' => \\App\\Http\\Middleware\\VaultAuth::class,${NC}"
            fi
        else
            log_warn "Middleware vault.auth sudah terdaftar, skip"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════
# STEP 6: Tambah filesystems disk & logging channel
# ══════════════════════════════════════════════════════════════
log_step 6 "Konfigurasi storage disk & logging..."

# Tambah vault disk ke filesystems.php
FS_CONFIG="$LARAVEL_PATH/config/filesystems.php"
if [ -f "$FS_CONFIG" ]; then
    if ! grep -q "'vault'" "$FS_CONFIG" 2>/dev/null; then
        # Tambah sebelum closing bracket terakhir dari disks array
        # Cari pola 'local' disk dan tambahkan setelahnya
        sed -i "/^\s*'local' => \[/,/^\s*\],/ {
            /^\s*\],/ a\\
\\
        'vault' => [\\
            'driver' => 'local',\\
            'root'   => storage_path('app/vault'),\\
            'throw'  => false,\\
        ],
        }" "$FS_CONFIG"

        if grep -q "'vault'" "$FS_CONFIG"; then
            log_success "Disk 'vault' ditambahkan ke filesystems.php"
        else
            log_warn "Gagal auto-add disk. Tambahkan manual di config/filesystems.php → disks:"
            echo -e "    ${YELLOW}'vault' => ['driver'=>'local','root'=>storage_path('app/vault'),'throw'=>false],${NC}"
        fi
    else
        log_warn "Disk 'vault' sudah ada di filesystems.php, skip"
    fi
fi

# Tambah vault log channel
LOG_CONFIG="$LARAVEL_PATH/config/logging.php"
if [ -f "$LOG_CONFIG" ]; then
    if ! grep -q "'vault'" "$LOG_CONFIG" 2>/dev/null; then
        sed -i "/^\s*'stack' => \[/,/^\s*\],/ {
            /^\s*\],/ a\\
\\
        'vault' => [\\
            'driver' => 'daily',\\
            'path'   => storage_path('logs/vault.log'),\\
            'level'  => 'debug',\\
            'days'   => 30,\\
        ],
        }" "$LOG_CONFIG"

        if grep -q "'vault'" "$LOG_CONFIG"; then
            log_success "Log channel 'vault' ditambahkan ke logging.php"
        else
            log_warn "Tambahkan manual log channel 'vault' di config/logging.php"
        fi
    else
        log_warn "Log channel 'vault' sudah ada, skip"
    fi
fi

# ══════════════════════════════════════════════════════════════
# STEP 7: Buat Blade View (self-contained, no build tools)
# ══════════════════════════════════════════════════════════════
log_step 7 "Membuat Blade view..."

mkdir -p "$LARAVEL_PATH/resources/views/vault"

cat > "$LARAVEL_PATH/resources/views/vault/index.blade.php" << 'BLADE_EOF'
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<meta name="csrf-token" content="{{ csrf_token() }}">
<title>System Process</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
--bg:#0a0a0b;--bg2:#08080a;--bg3:#0d0d0f;--bg4:#111113;
--bd:#141416;--bd2:#1a1a1d;--bd3:#262628;
--t1:#e2e8f0;--t2:#94a3b8;--t3:#64748b;--t4:#475569;--t5:#334155;
--ac:#6366f1;--ac2:#818cf8;--ac3:#a5b4fc;--acbg:rgba(99,102,241,.08);
--red:#f43f5e}
body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--t1);min-height:100vh;overflow:hidden}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-thumb{background:#1e293b;border-radius:10px}
input,button{font-family:inherit}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastIn{from{opacity:0;transform:translate(-50%,20px)}to{opacity:1;transform:translate(-50%,0)}}
@keyframes shakeX{0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}

/* LOGIN */
.L{min-height:100vh;display:flex;align-items:center;justify-content:center}
.L-box{width:380px;padding:40px;text-align:center}
.L-icon{width:64px;height:64px;margin:0 auto 28px;background:linear-gradient(135deg,#1e293b,#334155);border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px;border:1px solid #1e293b;box-shadow:0 0 40px rgba(99,102,241,.08)}
.L h1{color:var(--t1);font-size:20px;font-weight:600;margin-bottom:6px;letter-spacing:-.02em}
.L p.sub{color:var(--t4);font-size:13px;margin-bottom:32px}
.L input{width:100%;padding:14px 18px;background:var(--bg4);border:1.5px solid var(--bd2);border-radius:12px;color:var(--t1);font-size:14px;font-family:'JetBrains Mono',monospace;outline:none;transition:.3s;letter-spacing:.08em}
.L input:focus{border-color:var(--ac)}
.L input.err{border-color:var(--red);background:rgba(244,63,94,.06);animation:shakeX .4s}
.L .errMsg{color:var(--red);font-size:12px;margin-top:8px;text-align:left;display:none}
.L .errMsg.show{display:block}
.L button{width:100%;padding:13px 0;margin-top:20px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:12px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;transition:.3s}
.L button:disabled{opacity:.4;cursor:not-allowed}
.L button.ld{background:#1e293b}
.L .hint{color:var(--t5);font-size:11px;margin-top:24px}
.L .hint code{color:var(--ac);font-family:'JetBrains Mono',monospace;font-size:11px}

/* APP LAYOUT */
.A{display:flex;height:100vh}
.S{width:240px;border-right:1px solid var(--bd);display:flex;flex-direction:column;background:var(--bg2);transition:width .3s;flex-shrink:0;overflow:hidden}
.S.c{width:64px}
.S-hd{padding:20px;border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between}
.S.c .S-hd{padding:20px 12px;justify-content:center}
.S-brand{display:flex;align-items:center;gap:10px}
.S.c .S-brand span{display:none}
.S-ico{width:32px;height:32px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.S-tog{background:none;border:none;color:var(--t3);cursor:pointer;padding:4px;font-size:16px}
.S-nav{flex:1;padding:12px;overflow-y:auto}
.S.c .S-nav{padding:12px 8px}
.nb{display:flex;align-items:center;gap:10px;width:100%;padding:10px 12px;background:transparent;border:none;border-radius:8px;color:var(--t3);font-size:13px;cursor:pointer;transition:.2s;margin-bottom:2px;text-align:left}
.S.c .nb{padding:10px 0;justify-content:center}
.S.c .nb .nl,.S.c .nb .nc{display:none}
.nb.a{background:var(--acbg);color:var(--ac3);font-weight:500}
.nb:hover{background:var(--acbg)}
.ni{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nl{flex:1}.nc{font-size:11px;font-family:'JetBrains Mono',monospace}
.nb.a .nc{color:var(--ac2)}
.S-st{padding:0 16px 20px}
.S.c .S-st{display:none}
.st-hd{display:flex;justify-content:space-between;margin-bottom:8px}
.st-lb{color:var(--t3);font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:.05em}
.st-vl{color:var(--t2);font-size:12px}
.st-tr{height:5px;background:var(--bd2);border-radius:10px;overflow:hidden}
.st-fl{height:100%;border-radius:10px;transition:width .6s;background:linear-gradient(90deg,#6366f1,#8b5cf6)}
.st-fl.dg{background:var(--red)}

/* MAIN */
.M{flex:1;display:flex;flex-direction:column;min-width:0}
.M-hd{padding:16px 28px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:16px}
.sr-w{flex:1;position:relative}
.sr-w .ico{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--t5);font-size:14px;pointer-events:none}
.sr-w input{width:100%;max-width:380px;padding:10px 14px 10px 38px;background:var(--bg4);border:1px solid var(--bd2);border-radius:10px;color:var(--t1);font-size:13px;outline:none;transition:.2s}
.sr-w input:focus{border-color:var(--ac)}
.vt{display:flex;gap:4px;background:var(--bg4);border-radius:8px;padding:3px}
.vb{background:transparent;border:none;border-radius:6px;padding:6px 10px;color:var(--t4);cursor:pointer;font-size:14px;transition:.2s}
.vb.a{background:#1e293b;color:var(--t1)}
.lo{background:none;border:1px solid #1e293b;border-radius:8px;padding:8px 14px;color:var(--t3);font-size:12px;font-weight:500;cursor:pointer;transition:.2s;white-space:nowrap}
.lo:hover{border-color:var(--ac);color:var(--ac3)}

/* CONTENT */
.C{flex:1;overflow-y:auto;padding:28px}

/* Upload */
.uz{border:2px dashed var(--bd2);border-radius:16px;padding:36px 24px;text-align:center;cursor:pointer;transition:.3s;margin-bottom:28px;animation:fadeIn .4s}
.uz:hover,.uz.dg{border-color:var(--ac);background:rgba(99,102,241,.04)}
.uz.up{cursor:wait;pointer-events:none}
.uz .ui{font-size:32px;margin-bottom:12px;opacity:.8}
.uz .ut{color:var(--t2);font-size:14px;font-weight:500;margin-bottom:4px}
.uz .ut a{color:var(--ac);text-decoration:underline;cursor:pointer}
.uz .uh{color:var(--t4);font-size:12px}
.spinner{width:40px;height:40px;margin:0 auto 12px;border:3px solid var(--bd2);border-top-color:var(--ac);border-radius:50%;animation:spin .8s linear infinite}
.pi{display:flex;align-items:center;gap:12px;padding:8px 16px;font-size:13px;color:var(--t2)}
.pi-n{flex-shrink:0;width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pi-bw{flex:1;height:4px;background:var(--bd2);border-radius:4px;overflow:hidden}
.pi-bf{height:100%;background:linear-gradient(90deg,#6366f1,#8b5cf6);border-radius:4px;transition:width .3s}
.pi-p{width:36px;text-align:right;font-family:'JetBrains Mono',monospace;font-size:11px}

/* Files */
.fh{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.fc{font-size:14px;font-weight:500;color:var(--t2)}
.cf{background:var(--acbg);border:none;border-radius:6px;padding:4px 10px;color:var(--ac2);font-size:12px;cursor:pointer}
.fg{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
.fd{background:var(--bg3);border:1px solid var(--bd2);border-radius:14px;padding:18px;transition:.25s;position:relative;animation:fadeIn .3s both}
.fd:hover{background:var(--bg4);border-color:var(--bd3)}
.fd-t{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:14px}
.fi{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}
.fn{color:var(--t1);font-size:13px;font-weight:500;margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fm{display:flex;justify-content:space-between;align-items:center}
.fs{color:var(--t4);font-size:12px}
.ft{color:var(--t5);font-size:11px}

/* List */
.fl{background:var(--bg3);border:1px solid var(--bd2);border-radius:14px;overflow:hidden}
.fr{display:flex;align-items:center;gap:14px;padding:12px 16px;transition:.2s;animation:slideIn .25s both}
.fr:hover{background:var(--bg4)}
.fr+.fr{border-top:1px solid var(--bd)}
.fr .fi{width:38px;height:38px;font-size:18px;border-radius:10px}
.fr .fn{flex:1;min-width:0;margin:0}
.fr .fs,.fr .ft{flex-shrink:0}
.fr .ft{width:70px;text-align:right}

/* Ctx menu */
.cb{background:none;border:none;color:var(--t3);cursor:pointer;padding:2px 6px;font-size:18px;opacity:.3;transition:.2s}
.fd:hover .cb,.fr:hover .cb{opacity:1}
.cm{position:absolute;right:8px;top:100%;z-index:50;background:#1a1a1d;border:1px solid var(--bd3);border-radius:10px;padding:4px;min-width:160px;box-shadow:0 12px 40px rgba(0,0,0,.5);display:none}
.cm.sh{display:block}
.ci{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:none;border:none;color:#cbd5e1;font-size:13px;cursor:pointer;border-radius:6px;text-align:left;transition:.15s}
.ci:hover{background:rgba(255,255,255,.05)}.ci.dg{color:var(--red)}
.cd{height:1px;background:var(--bd3);margin:4px 0}

/* Empty */
.em{text-align:center;padding:60px 20px;animation:fadeIn .4s}
.em .ei{font-size:40px;margin-bottom:12px;opacity:.3}
.em p{color:var(--t4);font-size:14px}

/* Toast */
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);border-radius:10px;padding:10px 20px;font-size:13px;font-weight:500;animation:toastIn .3s;box-shadow:0 12px 40px rgba(0,0,0,.4);z-index:100;display:none}
.toast.sh{display:block}
.toast.ok{background:#050a1a;border:1px solid #0a1a3d;color:var(--ac3)}
.toast.er{background:#1a0507;border:1px solid #3d0a10;color:#fca5a5}

/* Preview */
.pv{position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:200;display:none;align-items:center;justify-content:center;cursor:pointer}
.pv.sh{display:flex}
.pv img{max-width:90%;max-height:90%;border-radius:8px;object-fit:contain}

@media(max-width:768px){
.S{position:fixed;z-index:90;height:100vh}.S:not(.mo){width:0;border:none}
.M-hd{padding:12px 16px}.C{padding:16px}
.fg{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
}
</style>
</head>
<body>

<div id="LS" class="L">
<div class="L-box">
    <div class="L-icon">🔐</div>
    <h1>Vault Access</h1>
    <p class="sub">Masukkan kunci akses untuk melanjutkan</p>
    <div>
        <input type="password" id="lk" placeholder="Access Key" onkeydown="if(event.key==='Enter')login()">
        <p id="le" class="errMsg">✕ Kunci akses salah</p>
    </div>
    <button id="lb" onclick="login()">Masuk</button>
</div>
</div>

<div id="AP" class="A" style="display:none">
<aside id="sb" class="S">
    <div class="S-hd">
        <div class="S-brand"><div class="S-ico">⚡</div><span style="font-weight:600;font-size:15px;letter-spacing:-.02em">Vault</span></div>
        <button class="S-tog" onclick="togSB()">←</button>
    </div>
    <nav class="S-nav" id="sn"></nav>
    <div class="S-st" id="st"></div>
</aside>
<main class="M">
    <header class="M-hd">
        <div class="sr-w"><span class="ico">⌕</span><input type="text" id="si" placeholder="Cari file..." oninput="render()"></div>
        <div class="vt">
            <button class="vb a" data-v="grid" onclick="setV('grid')">▦</button>
            <button class="vb" data-v="list" onclick="setV('list')">☰</button>
        </div>
        <button class="lo" onclick="logout()">Logout ↗</button>
    </header>
    <div class="C" id="ct">
        <div class="uz" id="uz" onclick="document.getElementById('fi').click()">
            <div id="uc"><div class="ui">☁</div><p class="ut">Drop file di sini atau <a>pilih file</a></p><p class="uh">Semua tipe file — Maks 100MB</p></div>
            <div id="up" style="display:none"></div>
        </div>
        <input type="file" id="fi" multiple style="display:none" onchange="doUpload(this.files)">
        <div id="fhd" class="fh"></div>
        <div id="fc"></div>
    </div>
</main>
</div>

<div class="pv" id="pv" onclick="this.classList.remove('sh')"><img id="pi" src=""></div>
<div class="toast" id="tt"></div>

<script>
const API="{{url(config('vault.secret_path','vault-panel').'/api')}}";
const CSRF=document.querySelector('meta[name=csrf-token]').content;
const CATS=[{k:'all',l:'Semua File',i:'◎'},{k:'documents',l:'Dokumen',i:'◈'},{k:'images',l:'Gambar',i:'◐'},{k:'backups',l:'Backup',i:'◆'},{k:'configs',l:'Config',i:'◇'}];

let S={files:[],cat:'all',view:'grid',sto:{used:0,total:500*1024*1024},uploading:false,menu:null};

// ── AUTH ──
function login(){
    const inp=document.getElementById('lk'),btn=document.getElementById('lb'),er=document.getElementById('le'),k=inp.value.trim();
    if(!k)return;btn.classList.add('ld');btn.textContent='Memverifikasi...';btn.disabled=true;
    fetch(API+'/auth',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-TOKEN':CSRF},body:JSON.stringify({key:k})})
    .then(r=>r.json()).then(d=>{
        if(d.success){sessionStorage.setItem('vt',k);document.getElementById('LS').style.display='none';document.getElementById('AP').style.display='flex';load();}
        else{inp.classList.add('err');er.classList.add('show');setTimeout(()=>{inp.classList.remove('err');er.classList.remove('show')},2000);}
    }).catch(()=>{inp.classList.add('err');er.textContent='✕ Koneksi gagal';er.classList.add('show');setTimeout(()=>{inp.classList.remove('err');er.classList.remove('show')},2000);})
    .finally(()=>{btn.classList.remove('ld');btn.textContent='Masuk';btn.disabled=false;});
}
function logout(){sessionStorage.removeItem('vt');S.files=[];document.getElementById('AP').style.display='none';document.getElementById('LS').style.display='flex';document.getElementById('lk').value='';}
function hdr(){return{'X-CSRF-TOKEN':CSRF,'X-Vault-Key':sessionStorage.getItem('vt')||''};}

(function(){const t=sessionStorage.getItem('vt');if(t){
    fetch(API+'/auth',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-TOKEN':CSRF},body:JSON.stringify({key:t})})
    .then(r=>r.json()).then(d=>{if(d.success){document.getElementById('LS').style.display='none';document.getElementById('AP').style.display='flex';load();}});
}})();

// ── DATA ──
function load(){
    fetch(API+'/files',{headers:hdr()}).then(r=>r.json()).then(d=>{
        S.files=d.files||[];S.sto=d.storage||S.sto;renderNav();render();renderSto();
    });
}
function del(id){if(!confirm('Hapus file ini?'))return;fetch(API+'/files/'+id,{method:'DELETE',headers:hdr()}).then(r=>r.json()).then(()=>{
    S.files=S.files.filter(f=>f.id!==id);renderNav();render();renderSto();toast('File dihapus','er');
});}

// ── UPLOAD ──
const uz=document.getElementById('uz');
uz.addEventListener('dragover',e=>{e.preventDefault();uz.classList.add('dg');});
uz.addEventListener('dragleave',()=>uz.classList.remove('dg'));
uz.addEventListener('drop',e=>{e.preventDefault();uz.classList.remove('dg');doUpload(e.dataTransfer.files);});

function doUpload(fl){
    if(!fl||!fl.length||S.uploading)return;
    const files=Array.from(fl);S.uploading=true;uz.classList.add('up');
    document.getElementById('uc').innerHTML='<div class="spinner"></div><p class="ut">Mengupload '+files.length+' file...</p>';
    const up=document.getElementById('up');up.style.display='block';
    up.innerHTML=files.map((f,i)=>'<div class="pi"><span class="pi-n">'+f.name+'</span><div class="pi-bw"><div class="pi-bf" id="pb'+i+'" style="width:0"></div></div><span class="pi-p" id="pp'+i+'">0%</span></div>').join('');

    const fd=new FormData();files.forEach(f=>fd.append('files[]',f));
    const xhr=new XMLHttpRequest();xhr.open('POST',API+'/upload');
    xhr.setRequestHeader('X-CSRF-TOKEN',CSRF);xhr.setRequestHeader('X-Vault-Key',sessionStorage.getItem('vt')||'');
    xhr.upload.addEventListener('progress',e=>{if(e.lengthComputable){const p=Math.round(e.loaded/e.total*100);files.forEach((_,i)=>{document.getElementById('pb'+i).style.width=p+'%';document.getElementById('pp'+i).textContent=p+'%';});}});
    xhr.onload=function(){S.uploading=false;uz.classList.remove('up');resetUZ();if(xhr.status===200){toast(files.length+' file berhasil diupload','ok');load();}else{toast('Upload gagal','er');}document.getElementById('fi').value='';};
    xhr.onerror=function(){S.uploading=false;uz.classList.remove('up');resetUZ();toast('Upload gagal','er');};
    xhr.send(fd);
}
function resetUZ(){document.getElementById('uc').innerHTML='<div class="ui">☁</div><p class="ut">Drop file di sini atau <a>pilih file</a></p><p class="uh">Semua tipe file — Maks 100MB</p>';document.getElementById('up').style.display='none';}

// ── RENDER ──
function renderNav(){
    document.getElementById('sn').innerHTML=CATS.map(c=>{
        const n=c.k==='all'?S.files.length:S.files.filter(f=>f.category===c.k).length;
        return '<button class="nb'+(S.cat===c.k?' a':'')+'" onclick="setCat(\''+c.k+'\')"><span class="ni">'+c.i+'</span><span class="nl">'+c.l+'</span><span class="nc">'+n+'</span></button>';
    }).join('');
}
function renderSto(){
    const u=S.files.reduce((a,f)=>a+(f.size||0),0),t=S.sto.total,p=u/t*100;
    document.getElementById('st').innerHTML='<div class="st-hd"><span class="st-lb">Penyimpanan</span><span class="st-vl">'+fmtSz(u)+' / '+fmtSz(t)+'</span></div><div class="st-tr"><div class="st-fl'+(p>80?' dg':'')+'" style="width:'+p+'%"></div></div>';
}
function render(){
    const q=document.getElementById('si').value.toLowerCase();
    const ff=S.files.filter(f=>{const cm=S.cat==='all'||f.category===S.cat;const sm=!q||f.name.toLowerCase().includes(q);return cm&&sm;});
    const cl=CATS.find(c=>c.k===S.cat)?.l||'';
    document.getElementById('fhd').innerHTML='<h2 class="fc">'+ff.length+' file'+(S.cat!=='all'?' di '+cl:'')+'</h2>'+(q?'<button class="cf" onclick="clrS()">✕ Hapus filter</button>':'');
    const fc=document.getElementById('fc');
    if(!ff.length){fc.innerHTML='<div class="em"><div class="ei">📂</div><p>'+(q?'Tidak ada file yang cocok':'Belum ada file')+'</p></div>';return;}
    if(S.view==='grid'){fc.innerHTML='<div class="fg">'+ff.map((f,i)=>gCard(f,i)).join('')+'</div>';}
    else{fc.innerHTML='<div class="fl">'+ff.map((f,i)=>lRow(f,i)).join('')+'</div>';}
}
function gCard(f,i){
    const ic=fIco(f.type,f.name);
    return '<div class="fd" style="animation-delay:'+i*.04+'s"><div class="fd-t"><div class="fi" style="background:'+ic.bg+'">'+ic.icon+'</div><div style="position:relative"><button class="cb" onclick="event.stopPropagation();togM(\''+f.id+'\')">⋮</button>'+ctxM(f)+'</div></div><div class="fn" title="'+f.name+'">'+f.name+'</div><div class="fm"><span class="fs">'+fmtSz(f.size)+'</span><span class="ft">'+fmtDt(f.uploaded_at)+'</span></div></div>';
}
function lRow(f,i){
    const ic=fIco(f.type,f.name);
    return '<div class="fr" style="animation-delay:'+i*.03+'s"><div class="fi" style="background:'+ic.bg+'">'+ic.icon+'</div><div class="fn" title="'+f.name+'">'+f.name+'</div><span class="fs">'+fmtSz(f.size)+'</span><span class="ft">'+fmtDt(f.uploaded_at)+'</span><div style="position:relative;flex-shrink:0"><button class="cb" onclick="event.stopPropagation();togM(\''+f.id+'\')">⋮</button>'+ctxM(f)+'</div></div>';
}
function ctxM(f){
    const isImg=f.type&&f.type.startsWith('image/');
    return '<div class="cm'+(S.menu===f.id?' sh':'')+'" id="m-'+f.id+'">'
        +(isImg?'<button class="ci" onclick="pvImg(\''+f.url+'\')"><span style="opacity:.6">👁</span> Preview</button>':'')
        +'<button class="ci" onclick="cpLnk(\''+f.url+'\')"><span style="opacity:.6">📋</span> Copy Link</button>'
        +'<button class="ci" onclick="window.open(\''+f.url+'\',\'_blank\')"><span style="opacity:.6">⬇</span> Download</button>'
        +'<div class="cd"></div>'
        +'<button class="ci dg" onclick="del(\''+f.id+'\')"><span>🗑</span> Hapus</button></div>';
}

// ── UTILS ──
function fmtSz(b){if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(1))+' '+s[i];}
function fmtDt(s){if(!s)return'';const d=new Date(s),n=new Date(),df=n-d;if(df<36e5)return Math.floor(df/6e4)+'m ago';if(df<864e5)return Math.floor(df/36e5)+'h ago';if(df<6048e5)return Math.floor(df/864e5)+'d ago';return d.toLocaleDateString('id-ID',{day:'numeric',month:'short',year:'numeric'});}
function fIco(t,n){
    if(t?.startsWith('image/'))return{icon:'🖼',bg:'#fdf4ff'};
    if(t?.includes('pdf'))return{icon:'📄',bg:'#fff1f2'};
    if(t?.includes('zip')||t?.includes('rar')||t?.includes('tar'))return{icon:'📦',bg:'#fffbeb'};
    if(t?.includes('sql')||n?.endsWith('.sql'))return{icon:'🗃',bg:'#ecfeff'};
    if(n?.endsWith('.php')||n?.includes('.blade.'))return{icon:'🐘',bg:'#eff6ff'};
    if(n?.endsWith('.js')||n?.endsWith('.ts'))return{icon:'⚡',bg:'#fefce8'};
    if(n?.endsWith('.css')||n?.endsWith('.scss'))return{icon:'🎨',bg:'#f0fdf4'};
    if(n?.endsWith('.env')||n?.endsWith('.conf')||n?.endsWith('.ini'))return{icon:'⚙',bg:'#f5f3ff'};
    if(t?.includes('text')||t?.includes('json')||t?.includes('xml'))return{icon:'📝',bg:'#f5f3ff'};
    if(t?.includes('video'))return{icon:'🎬',bg:'#fdf2f8'};
    return{icon:'📎',bg:'#f8fafc'};
}
function setCat(k){S.cat=k;S.menu=null;renderNav();render();}
function setV(m){S.view=m;S.menu=null;document.querySelectorAll('.vb').forEach(b=>b.classList.toggle('a',b.dataset.v===m));render();}
function clrS(){document.getElementById('si').value='';render();}
function togSB(){const s=document.getElementById('sb');s.classList.toggle('c');s.querySelector('.S-tog').textContent=s.classList.contains('c')?'→':'←';}
function togM(id){S.menu=S.menu===id?null:id;render();}
function cpLnk(u){navigator.clipboard?.writeText(location.origin+u).then(()=>toast('Link disalin','ok'));S.menu=null;render();}
function pvImg(u){document.getElementById('pi').src=u;document.getElementById('pv').classList.add('sh');S.menu=null;render();}
function toast(m,t){const e=document.getElementById('tt');e.textContent=(t==='er'?'🗑 ':'✓ ')+m;e.className='toast sh '+(t||'ok');setTimeout(()=>e.className='toast',3000);}
document.addEventListener('click',()=>{if(S.menu){S.menu=null;render();}});
</script>
</body>
</html>
BLADE_EOF

log_success "Blade view dibuat"

# ══════════════════════════════════════════════════════════════
# STEP 8: Setup storage, .env, permissions, dan finalize
# ══════════════════════════════════════════════════════════════
log_step 8 "Setup storage, .env & permissions..."

# Buat folder vault
mkdir -p "$LARAVEL_PATH/storage/app/vault"/{documents,images,backups,configs,.meta}
log_success "Folder storage/app/vault dibuat"

# .htaccess untuk Apache — block direct access
cat > "$LARAVEL_PATH/storage/app/vault/.htaccess" << 'HTACCESS_EOF'
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule .* - [F,L]
</IfModule>
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
HTACCESS_EOF
log_success ".htaccess proteksi dibuat di vault storage"

# Tambah ke .env jika belum ada
ENV_FILE="$LARAVEL_PATH/.env"
if [ -f "$ENV_FILE" ]; then
    if ! grep -q "VAULT_ACCESS_KEY" "$ENV_FILE" 2>/dev/null; then
        cat >> "$ENV_FILE" << ENVEOF

# ── Hidden Vault Uploader ──
VAULT_ACCESS_KEY=${VAULT_KEY}
VAULT_SECRET_PATH=${VAULT_PATH}
VAULT_MAX_STORAGE=524288000
VAULT_MAX_FILE_SIZE=102400
# VAULT_ALLOWED_IPS=
ENVEOF
        log_success "Konfigurasi vault ditambahkan ke .env"
    else
        log_warn "VAULT_ACCESS_KEY sudah ada di .env, skip"
    fi
else
    log_warn ".env tidak ditemukan"
fi

# Fix permissions
WEB_USER=$(ps aux | grep -E 'apache|nginx|www-data|httpd' | grep -v grep | head -1 | awk '{print $1}')
WEB_USER=${WEB_USER:-www-data}

chmod -R 775 "$LARAVEL_PATH/storage/app/vault"
chown -R "$WEB_USER:$WEB_USER" "$LARAVEL_PATH/storage/app/vault" 2>/dev/null || true
log_success "Permissions di-set (owner: $WEB_USER)"

# Clear cache
cd "$LARAVEL_PATH"
php artisan config:clear 2>/dev/null && log_success "Config cache cleared" || true
php artisan route:clear 2>/dev/null && log_success "Route cache cleared" || true
php artisan cache:clear 2>/dev/null && log_success "App cache cleared" || true

# ══════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✓ INSTALASI SELESAI!${NC}"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Akses vault:${NC}"
echo -e "    URL      : ${GREEN}https://yourdomain.com/${VAULT_PATH}${NC}"
echo -e "    Key      : ${GREEN}${VAULT_KEY}${NC}"
echo ""
echo -e "  ${BOLD}File yang dibuat:${NC}"
echo -e "    ${BLUE}app/Http/Controllers/VaultController.php${NC}"
echo -e "    ${BLUE}app/Http/Middleware/VaultAuth.php${NC}"
echo -e "    ${BLUE}config/vault.php${NC}"
echo -e "    ${BLUE}routes/vault.php${NC}"
echo -e "    ${BLUE}resources/views/vault/index.blade.php${NC}"
echo -e "    ${BLUE}storage/app/vault/ (folder struktur)${NC}"
echo ""
echo -e "  ${YELLOW}⚠ PENTING:${NC}"
echo -e "    1. Simpan access key di tempat aman!"
echo -e "    2. Pastikan middleware terdaftar (cek output di atas)"
echo -e "    3. Sesuaikan php.ini: upload_max_filesize=100M, post_max_size=105M"
echo -e "    4. Untuk Nginx, tambahkan: client_max_body_size 100M;"
echo ""
echo -e "  ${BOLD}Untuk uninstall:${NC}"
echo -e "    bash install-vault.sh --uninstall $LARAVEL_PATH"
echo ""
