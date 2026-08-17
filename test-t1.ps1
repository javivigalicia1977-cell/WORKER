
# ============================================================
# POTISSE T.1 Backend v6.12.8 — Test Suite PowerShell
# Usa Invoke-RestMethod (nativo PS, sin problemas de escaping)
# ============================================================

param(
    [string]$BaseUrl = "https://nfc.potisse.com",
    [string]$PhotoFile = "archivo.jpg"
)

# Pedir admin key oculta
$secureKey = Read-Host -Prompt "Admin Key" -AsSecureString
$AdminKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
)
if (-not $AdminKey) { Write-Error "Admin Key requerida"; exit 1 }

$ErrorActionPreference = "Stop"
$passed = 0
$failed = 0
$testNum = 0

function Invoke-Test {
    param($Name, $ScriptBlock)
    $script:testNum++
    $n = $script:testNum
    Write-Host "`n[$n/15] $Name" -ForegroundColor Cyan
    try {
        $result = & $ScriptBlock
        Write-Host "  PASS" -ForegroundColor Green
        $script:passed++
        return $result
    } catch {
        Write-Host "  FAIL: $_" -ForegroundColor Red
        $script:failed++
        return $null
    }
}

function Invoke-Api {
    param($Method, $Path, $Body = $null, $ContentType = "application/json")
    $uri = "$BaseUrl$Path`?admin=$AdminKey"
    $headers = @{ "Content-Type" = $ContentType }
    try {
        if ($Body) {
            $resp = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body $Body
        } else {
            $resp = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers
        }
        return @{ code = 200; body = ($resp | ConvertTo-Json -Depth 10); raw = $resp }
    } catch {
        $status = 0
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        $errBody = $_.ErrorDetails.Message
        if (-not $errBody) { $errBody = $_.Exception.Message }
        return @{ code = $status; body = $errBody; raw = $null }
    }
}

# ============================================================
# A. ITEM NUEVOS CAMPOS
# ============================================================

Invoke-Test "A1. Crear item con campos nuevos" {
    $body = '{"id":"TEST-001","name":"Test Item","sku":"TEST-001","category":"finished_good","origin_type":"local","description":"Desc test","cost_per_unit":12.5,"barcode":"123456789"}'
    $r = Invoke-Api -Method "POST" -Path "/api/admin/stock/items" -Body $body
    if ($r.code -ne 201 -and $r.code -ne 200 -and $r.code -ne 409) { throw "HTTP $($r.code): $($r.body)" }
    if ($r.code -eq 409) { Write-Host "  (item ya existia, OK)" -ForegroundColor Yellow }
    $r
}

Invoke-Test "A2. Update item location_id + photo_url" {
    $body = '{"location_id":"workshop","photo_url":"https://example.com/photo.jpg"}'
    $r = Invoke-Api -Method "PUT" -Path "/api/admin/stock/items/TEST-001" -Body $body
    if ($r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    if ($r.raw.item.location_id -ne "workshop") { throw "location_id no actualizado" }
    $r
}

# ============================================================
# B. SUPPLIER NUEVOS CAMPOS
# ============================================================

$supplierId = $null
Invoke-Test "B1. Crear supplier con campos nuevos" {
    $body = '{"name":"Test Sup T1","type":"supplier","payment_terms":"Net 30","rating":4,"tax_id":"B12345678","website":"https://test.com"}'
    $r = Invoke-Api -Method "POST" -Path "/api/admin/stock/suppliers" -Body $body
    if ($r.code -ne 201 -and $r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    $script:supplierId = $r.raw.supplier.id
    Write-Host "  Supplier ID: $($script:supplierId)" -ForegroundColor DarkGray
    $r
}

Invoke-Test "B2. Update supplier rating invalido -> 400" {
    if (-not $script:supplierId) { throw "No supplier ID from B1" }
    $body = '{"rating":6}'
    $r = Invoke-Api -Method "PUT" -Path "/api/admin/stock/suppliers/$($script:supplierId)" -Body $body
    if ($r.code -ne 400) { throw "Esperado 400, recibido $($r.code): $($r.body)" }
    $r
}

# ============================================================
# C. LOCATION (5 bootstrap + CRUD)
# ============================================================

Invoke-Test "C1. List locations (auto-bootstrap 5 defaults)" {
    $r = Invoke-Api -Method "GET" -Path "/api/admin/stock/locations"
    if ($r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    $count = ($r.raw.locations | Measure-Object).Count
    if ($count -lt 5) { throw "Esperadas >=5 locations, recibidas $count" }
    Write-Host "  Locations: $count" -ForegroundColor DarkGray
    $r
}

Invoke-Test "C2. Crear location" {
    $body = '{"id":"new-loc-t1","name":"Nueva Ubicacion T1","type":"warehouse"}'
    $r = Invoke-Api -Method "POST" -Path "/api/admin/stock/locations" -Body $body
    if ($r.code -ne 201 -and $r.code -ne 200 -and $r.code -ne 409) { throw "HTTP $($r.code): $($r.body)" }
    $r
}

Invoke-Test "C3. Get location workshop" {
    $r = Invoke-Api -Method "GET" -Path "/api/admin/stock/locations/workshop"
    if ($r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    if ($r.raw.location.id -ne "workshop") { throw "ID mismatch" }
    $r
}

Invoke-Test "C4. Update location" {
    $body = '{"address":"Calle Falsa 123"}'
    $r = Invoke-Api -Method "PUT" -Path "/api/admin/stock/locations/new-loc-t1" -Body $body
    if ($r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    $r
}

Invoke-Test "C5. Delete location" {
    $r = Invoke-Api -Method "DELETE" -Path "/api/admin/stock/locations/new-loc-t1"
    if ($r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    $r
}

# ============================================================
# D. BATCH current_location_id + MOVEMENT
# ============================================================

$batchId = $null
Invoke-Test "D1. Crear batch con current_location_id" {
    $body = '{"item_sku":"TEST-001","quantity":10,"current_location_id":"warehouse_main"}'
    $r = Invoke-Api -Method "POST" -Path "/api/admin/stock/batches" -Body $body
    if ($r.code -ne 201 -and $r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    $script:batchId = $r.raw.batch.id
    Write-Host "  Batch ID: $($script:batchId)" -ForegroundColor DarkGray
    if ($r.raw.batch.current_location_id -ne "warehouse_main") { throw "current_location_id no asignado" }
    $r
}

Invoke-Test "D2. Movement start" {
    if (-not $script:batchId) { throw "No batch ID from D1" }
    $body = '{"to_location_id":"workshop","note":"Para corte"}'
    $r = Invoke-Api -Method "POST" -Path "/api/admin/stock/batches/$($script:batchId)/movement/start" -Body $body
    if ($r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    if (-not $r.raw.batch.movement_in_progress) { throw "movement_in_progress no es true" }
    $r
}

Invoke-Test "D3. Movement complete" {
    if (-not $script:batchId) { throw "No batch ID from D1" }
    $body = '{"note":"Recibido en taller"}'
    $r = Invoke-Api -Method "POST" -Path "/api/admin/stock/batches/$($script:batchId)/movement/complete" -Body $body
    if ($r.code -ne 200) { throw "HTTP $($r.code): $($r.body)" }
    if ($r.raw.batch.movement_in_progress -ne $false) { throw "movement_in_progress no es false" }
    if ($r.raw.batch.current_location_id -ne "workshop") { throw "current_location_id no es workshop" }
    $r
}

Invoke-Test "D4. Movement start sin movement_in_progress -> 409" {
    if (-not $script:batchId) { throw "No batch ID from D1" }
    $body = '{"to_location_id":"workshop"}'
    $r = Invoke-Api -Method "POST" -Path "/api/admin/stock/batches/$($script:batchId)/movement/start" -Body $body
    if ($r.code -ne 409) { throw "Esperado 409, recibido $($r.code): $($r.body)" }
    $r
}

# ============================================================
# E. UPLOAD PHOTO ITEM R2
# ============================================================

Invoke-Test "E1. Upload photo item" {
    if (-not (Test-Path $PhotoFile)) { throw "No existe archivo: $PhotoFile" }
    $url = "$BaseUrl/api/admin/stock/items/TEST-001/photo`?admin=$AdminKey"
    try {
        $resp = Invoke-RestMethod -Uri $url -Method POST -InFile $PhotoFile -ContentType "image/jpeg"
        if (-not $resp.photo_url) { throw "photo_url no devuelto" }
        Write-Host "  Photo URL: $($resp.photo_url)" -ForegroundColor DarkGray
        @{ code = 200; body = ($resp | ConvertTo-Json -Depth 10); raw = $resp }
    } catch {
        $status = 0
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        throw "HTTP ${status}: $($_.ErrorDetails.Message)"
    }
}

# ============================================================
# RESUMEN
# ============================================================
Write-Host "`n========================================" -ForegroundColor White
Write-Host "RESULTADO: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor White
if ($failed -gt 0) { exit 1 }
