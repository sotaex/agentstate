# logo.ps1 -- Antinel console: floating sentry mark (minimum presence state).
#
# ASCII-only on purpose (same discipline as tray.ps1): Windows PowerShell 5.1
# mis-decodes UTF-8 source without a BOM, so every Chinese label arrives as a
# parameter from Python, where the encoding is under our control.
#
# 0.50.0: the console's minimum state ("floating"). The console is a big
# window nobody wants on screen all day; the sentry only has to BE there.
#
# 0.52.0 (founder 2026-10-17, screenshot of the trembling badge): the badge
# NO LONGER draws the spec-v1.2 animated ring (rotating sweep + wave) with
# GDI+. That hand-drawn ring flickered (40ms full repaints, no double
# buffering) and looked nothing like the Antinel mark. The badge now shows
# the SAME state icon family as the tray (assets/icons/{state}{shield}.ico,
# same mapping as inbox_tray.icon_file), statically, double-buffered, and
# only repaints when the state actually changes.
#
# Resident lifecycle (0.52.0): the badge process STAYS ALIVE across the
# collapse/expand cycle -- expand HIDES it (logo.hide), collapse SHOWS it
# (logo.show), both within one 40ms tick. No more PowerShell cold start on
# every collapse. Only logo.quit retires the process for real.
#
# Protocol (pure text files, no threads / no pipes / no Win32):
#   in : -State <tray.json>   <- {state, shield, tip, ts}  (same file the tray reads)
#   in : -Quit  <logo.quit>   <- file EXISTS  => this process exits at next poll
#   in : -Show  <logo.show>   <- file EXISTS  => badge shows itself (consumes it)
#   in : -Hide  <logo.hide>   <- file EXISTS  => badge hides itself (consumes it)
#   out: -Action <tray_action.txt> <- append one line: open
#
# Click vs drag: movement under 5px and under 1s is a click (write "open");
# anything larger is a drag (move the window, do NOT open).
# Click does NOT quit (0.52.0): the consumer opens the console and then
# writes the hide flag; the badge hides itself only then. If nothing
# consumes the action, the badge STAYS -- a vanished badge with no console
# was the founder's 2026-10-17 screenshot bug.

param(
  [Parameter(Mandatory=$true)][string]$State,
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$true)][string]$Quit,
  [Parameter(Mandatory=$true)][string]$Title,
  [string]$Show = "",
  [string]$Hide = "",
  [string]$IconDir = "",
  [switch]$Hidden,
  [int]$Size = 46,
  [int]$X = -1,
  [int]$Y = -1,
  [string]$Tip = "Antinel",
  [string]$TipStale = "state has stopped updating",
  [int]$StaleAfterSec = 30
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:utf8 = New-Object System.Text.UTF8Encoding($false)

# --- state icon family (SAME mapping as inbox_tray.icon_file / SHIELD_SUFFIX) ---
$SHIELD_SUFFIX = @{ "on" = ""; "unposted" = "-unposted"; "unknown" = "-unknown"; "off" = "-off" }

function Resolve-IconPath([string]$st, [string]$sh) {
  # {state}{shield}.ico preferred, fall back to {state}.ico, then "" (draw nothing).
  # Same fallback rule as inbox_tray.icon_file -- no second opinion here.
  if ($IconDir -eq "") { return "" }
  $suf = ""
  if ($SHIELD_SUFFIX.ContainsKey($sh)) { $suf = $SHIELD_SUFFIX[$sh] }
  if ($suf -ne "") {
    $cand = Join-Path $IconDir ($st + $suf + ".ico")
    if (Test-Path -LiteralPath $cand) { return $cand }
  }
  $base = Join-Path $IconDir ($st + ".ico")
  if (Test-Path -LiteralPath $base) { return $base }
  return ""
}

function Write-Action([string]$a) {
  try {
    [System.IO.File]::AppendAllText($Action, $a + "`n", $script:utf8)
    return $true
  } catch {
    $script:actionWriteFailed = $true
    return $false
  }
}

# Keep the source ASCII-only for Windows PowerShell 5.1 (no-BOM UTF-8 is ACP-decoded).
$script:actionWriteFailed = $false
$script:actionWriteFailTip = -join [char[]]@(0x5C55,0x5F00,0x5931,0x8D25,0xFF1A,
  0x52A8,0x4F5C,0x5199,0x5165,0x5931,0x8D25,0xFF0C,0x8BF7,0x518D,0x70B9,0x4E00,0x6B21)

# ---------------------------------------------------------------- window ---
$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object System.Drawing.Size($Size, $Size)
# measured on this machine: a borderless Form still carries the system
# minimum *tracking* width (SM_CXMINTRACK = 136) -- pin both edges so the
# badge is exactly $Size x $Size.
$form.MinimumSize = New-Object System.Drawing.Size($Size, $Size)
$form.MaximumSize = New-Object System.Drawing.Size($Size, $Size)
$form.FormBorderStyle = "None"
$form.StartPosition = "Manual"
$form.ShowInTaskbar = $false
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::Fuchsia
$form.TransparencyKey = [System.Drawing.Color]::Fuchsia
$form.Text = $Title
# 0.52.0: double-buffer + paint in WM_PAINT only -- the 40ms full repaints
# with background erase were the visible trembling.
$form.GetType().GetProperty("DoubleBuffered",
  [System.Reflection.BindingFlags]"NonPublic,Instance").SetValue($form, $true, $null)
$wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
# DEFAULT position: right-bottom, just above the taskbar (like an IME bar).
# NOTE: the geometry is computed on SEPARATE lines on purpose (see 0.50.0
# history: inline arithmetic in New-Object args breaks the param parser).
$markX = $wa.Right - $Size - 8
$markY = $wa.Bottom - $Size - 8
if ($X -ge 0 -and $Y -ge 0) {
  $form.Location = New-Object System.Drawing.Point($X, $Y)
} else {
  $form.Location = New-Object System.Drawing.Point($markX, $markY)
}

$script:mode = "L0"
$script:shield = "on"
$script:lastPoll = [DateTime]::MinValue
$script:trayStale = $true
$script:tip = $Tip
$script:tipShown = ""
# state icon cache: reload only when the resolved path changes
$script:icoPathLoaded = ""
$script:icoBmp = $null
# NOTE: the window title is NOT the tooltip here -- the title carries the
# find mark (" Antinel - sentry mark"), so Python can find and topmost this
# window (inbox_window.find_logo_windows). The state tip rides on a real
# ToolTip instead; overwriting .Text would blind the finder.
$tipCtl = New-Object System.Windows.Forms.ToolTip
$tipCtl.SetToolTip($form, $Tip)

$script:dragging = $false
$script:downAt = $null
$script:downPt = [System.Drawing.Point]::Empty
$script:moved = 0

function Load-Icon([string]$path) {
  if ($script:icoPathLoaded -eq $path) { return }
  if ($script:icoBmp -ne $null) {
    try { $script:icoBmp.Dispose() } catch { }
    $script:icoBmp = $null
  }
  $script:icoPathLoaded = $path
  if ($path -eq "" -or -not (Test-Path -LiteralPath $path)) { return }
  try {
    # load the NATIVE 48px frame (mk_icons SIZES = 16/32/48/64), then snap
    # alpha: <128 fully transparent, >=128 fully opaque. WHY: the badge is a
    # TransparencyKey(fuchsia) window -- any semi-transparent pixel blends
    # with fuchsia and shows as a PINK FRINGE around the icon (measured
    # 2026-10-17 screenshot). Snapped alpha leaves no semi-transparent
    # pixel to blend, so the badge looks exactly like the tray icon.
    $ico = New-Object System.Drawing.Icon($path, 48, 48)
    $bmp = $ico.ToBitmap()
    $ico.Dispose()
    $rect = New-Object System.Drawing.Rectangle(0, 0, $bmp.Width, $bmp.Height)
    $d = $bmp.LockBits($rect,
      [System.Drawing.Imaging.ImageLockMode]::ReadWrite,
      [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $n = $bmp.Width * $bmp.Height
    $px = New-Object byte[] (4 * $n)
    [System.Runtime.InteropServices.Marshal]::Copy($d.Scan0, $px, 0, 4 * $n)
    for ($i = 0; $i -lt $n; $i++) {
      if ($px[$i * 4 + 3] -lt 128) {
        $px[$i * 4] = 0; $px[$i * 4 + 1] = 0
        $px[$i * 4 + 2] = 0; $px[$i * 4 + 3] = 0
      } else {
        $px[$i * 4 + 3] = 255
      }
    }
    [System.Runtime.InteropServices.Marshal]::Copy($px, 0, $d.Scan0, 4 * $n)
    $bmp.UnlockBits($d)
    $script:icoBmp = $bmp
    $form.Invalidate()
  } catch { $script:icoBmp = $null }
}

function Read-State {
  # stale guard (same rule as tray.ps1): never render a long-dead state as now
  if (([DateTime]::UtcNow - $script:lastPoll).TotalMilliseconds -lt 250) { return }
  $script:lastPoll = [DateTime]::UtcNow
  try {
    if (-not (Test-Path -LiteralPath $State)) { $script:trayStale = $true; return }
    $j = Get-Content -LiteralPath $State -Raw -Encoding UTF8 | ConvertFrom-Json
    $st = [string]$j.state
    if ([string]::IsNullOrWhiteSpace($st)) { $st = "L0" }
    $sh = [string]$j.shield
    if ([string]::IsNullOrWhiteSpace($sh)) { $sh = "on" }
    $script:mode = $st
    $script:shield = $sh
    Load-Icon (Resolve-IconPath $st $sh)
    $t = [string]$j.tip
    if ([string]::IsNullOrWhiteSpace($t)) { $t = $Tip }
    $script:tip = $t
    $age = -1
    if ($j.PSObject.Properties.Name -contains "ts") {
      try { $age = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) - [int64]($j.ts) } catch { $age = -1 }
    }
    $script:trayStale = (($age -lt 0) -or ($age -gt $StaleAfterSec))
  } catch { $script:trayStale = $true }
}

$form.add_Paint({
  param($s, $e)
  try {
    if ($script:icoBmp -eq $null) { return }
    $g = $e.Graphics
    # NearestNeighbor: the bitmap alpha is snapped 0/255 -- any smoothing
    # would re-create semi-transparent edge pixels and the pink fringe
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
    $g.DrawImage($script:icoBmp, 0, 0, $Size, $Size)
  } catch { }
})

function Quit-Now {
  try { $form.Close() } catch { }
  [System.Windows.Forms.Application]::Exit()
}

function Show-Now {
  try {
    $form.Show()
    $form.TopMost = $true
    $form.Activate()
    $form.Invalidate()
  } catch { }
}

function Hide-Now {
  try { $form.Hide() } catch { }
}

# consume a one-shot flag file: existence IS the signal, delete = consume
# (single-purpose flag, unlike the multi-line action file which is renamed).
function Consume-Flag([string]$p) {
  if ($p -eq "") { return $false }
  if (-not (Test-Path -LiteralPath $p)) { return $false }
  try { Remove-Item -LiteralPath $p -Force } catch { }
  return $true
}

$form.add_MouseDown({
  param($s, $e)
  if ($e.Button -ne [System.Windows.Forms.MouseButtons]::Left) { return }
  $script:dragging = $true
  $script:downAt = [DateTime]::UtcNow
  $script:downPt = $e.Location
  $script:moved = 0
})
$form.add_MouseMove({
  param($s, $e)
  if (-not $script:dragging) { return }
  $dx = $e.X - $script:downPt.X
  $dy = $e.Y - $script:downPt.Y
  $script:moved = [Math]::Max($script:moved, [Math]::Max([Math]::Abs($dx), [Math]::Abs($dy)))
  $np = $form.PointToScreen([System.Drawing.Point]::new($e.X, $e.Y))
  $nx = $np.X - $script:downPt.X
  $ny = $np.Y - $script:downPt.Y
  if ($nx -lt $wa.Left) { $nx = $wa.Left }
  if ($ny -lt $wa.Top) { $ny = $wa.Top }
  if ($nx + $Size -gt $wa.Right) { $nx = $wa.Right - $Size }
  if ($ny + $Size -gt $wa.Bottom) { $ny = $wa.Bottom - $Size }
  $form.Location = New-Object System.Drawing.Point($nx, $ny)
})
$form.add_MouseUp({
  param($s, $e)
  if (-not $script:dragging) { return }
  $script:dragging = $false
  $dt = (([DateTime]::UtcNow) - $script:downAt).TotalSeconds
  if (($script:moved -le 5) -and ($dt -le 1.0)) {
    Write-Action "open" | Out-Null
    # the click does NOT exit here (0.52.0): the consumer opens the console,
    # then writes the hide flag and the badge hides itself. Nothing consumes
    # the action => the badge STAYS and the user can click again.
  }
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 40
$timer.add_Tick({
  if (Test-Path -LiteralPath $Quit) { Quit-Now }
  if (Consume-Flag $Show) { Show-Now }
  if (Consume-Flag $Hide) { Hide-Now }
  Read-State
  $tp = $script:tip
  if ($script:trayStale) { $tp = $TipStale }
  if ($script:actionWriteFailed) { $tp = $script:actionWriteFailTip }
  if ($tp.Length -gt 63) { $tp = $tp.Substring(0, 63) }
  if ($tp -ne $script:tipShown) {
    try { $tipCtl.SetToolTip($form, $tp) } catch { }
    $script:tipShown = $tp
  }
})
$timer.Start()

try {
  if ($Hidden) {
    # resident prewarm: start hidden, wait for the show flag.
    # Handle creation is LAZY: a never-shown form has NO HWND at all, so
    # EnumWindows finds nothing (measured 2026-10-17: prewarm "succeeded"
    # but the badge was unfindable). Show() forces the HWND, Hide() hides
    # it again -- both synchronously BEFORE the pump starts, so nothing
    # is ever painted on screen. Application.Run(form) would re-show the
    # form, hence the no-arg Run().
    $form.Show()
    $form.Hide()
    [System.Windows.Forms.Application]::Run()
  } else {
    [System.Windows.Forms.Application]::Run($form)
  }
} finally {
  $timer.Stop()
  try { $form.Dispose() } catch { }
}
