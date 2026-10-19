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
# NO LONGER drew the spec-v1.2 animated ring with GDI+. That hand-drawn ring
# trembled (40ms full repaints, no double buffering) and looked nothing like
# the Antinel mark. The badge showed the SAME state icon family as the tray
# (assets/icons/{state}{shield}.ico), statically.
#
# 0.53.1 (founder 2026-10-19, screenshot of the minimized badge): the static
# icon fixed the trembling but created three new symptoms, all fixed here:
#   (1) "what appeared was a bare circle, not the standard LOGO"  -> the badge
#       now draws the standard mark: ring + beam + trail + lamp + ripples,
#       the SAME motion spec the page runs (_LOGO_JS), delivered through
#       tray.json's "logo" block (inbox_server.logo_motion_spec, single
#       source of truth) and computed by tools/logo_frame.ps1 (pure math,
#       also dot-sourced by the guards).
#   (2) "clicking the middle of the circle did nothing"  -> the window is a
#       per-pixel-alpha layered window; the old TransparencyKey form only
#       hit-tested opaque pixels (icon centre = fully transparent). WndProc
#       now answers WM_NCHITTEST itself: HTCLIENT for the whole drawn area
#       (inscribed circle of the mark's box), HTTRANSPARENT in the four
#       corners so clicks pass through to whatever is behind.
#   (3) "it should stay dynamic like the main window LOGO"  -> frames are
#       pushed at 25fps through UpdateLayeredWindow, driven by a THREAD-POOL
#       TIMER marshaled onto the form's own thread (System.Timers.Timer +
#       SynchronizingObject; the two designs measured and rejected before
#       this one are written down at the animation pump block below). A
#       separate 250ms pool timer polls state and watches the frame pump.
# Why per-pixel alpha instead of "snap alpha to 0/255" (the 0.52.0 trick):
# snapping is what made the static icon acceptable, but the mark's thin
# strokes are 0.3-0.9px at 46px -- only true anti-aliasing draws them without
# stipple, and true AA needs per-pixel alpha (AA edges blended onto the
# TransparencyKey colour show as a PINK FRINGE -- measured 2026-10-17).
# Frames are rendered on a 2x offscreen bitmap with AA and downscaled with
# high-quality interpolation, so sub-pixel strokes survive.
#
# Resident lifecycle (0.52.0): the badge process STAYS ALIVE across the
# collapse/expand cycle -- expand HIDES it (logo.hide), collapse SHOWS it
# (logo.show), both within one 250ms poll. No more PowerShell cold start on
# every collapse. Only logo.quit retires the process for real.
#
# Protocol (pure text files, no threads / no pipes / no Win32):
#   in : -State <tray.json>   <- {state, shield, tip, ts, logo} (same file the
#                                tray reads; "logo" is the motion spec, 0.53.1)
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
#
# Reduced motion (0.53.1, mirrors the page's prefers-reduced-motion / Q-20):
# when the system's "show animations" preference is OFF (MinAnimate=0) the
# badge does NOT tick -- one static frame per state change, drawn at the
# TARGET state (not the boot state; that bug is what FLO-10e guards).

param(
  [Parameter(Mandatory=$true)][string]$State,
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$true)][string]$Quit,
  [Parameter(Mandatory=$true)][string]$Title,
  [string]$Show = "",
  [string]$Hide = "",
  [string]$IconDir = "",
  [string]$Frame = "",
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

# ------------------------------------------------------- layered window ----
# Per-pixel alpha: the frame bitmap IS the window content (WS_EX_LAYERED +
# UpdateLayeredWindow). Nothing is ever painted onto the form's own DC, so
# there is no background erase to flicker (the 0.50.0 trembling) and no
# colour-key fringe (the 0.50.0 pink edge). LogoForm also answers
# WM_NCHITTEST itself -- the whole drawn circle is clickable, the four
# corners are not (they belong to whatever is behind the badge).
Add-Type -TypeDefinition @'
using System;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;
public class LogoLayered {
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [StructLayout(LayoutKind.Sequential)] public struct SIZE { public int CX; public int CY; }
  [StructLayout(LayoutKind.Sequential)] public struct BLENDFUNCTION {
    public byte BlendOp; public byte BlendFlags;
    public byte SourceConstantAlpha; public byte AlphaFormat; }
  [DllImport("user32.dll", SetLastError=true)] public static extern bool UpdateLayeredWindow(
    IntPtr hwnd, IntPtr hdcDst, ref POINT pptDst, ref SIZE psize,
    IntPtr hdcSrc, ref POINT pptSrc, int crKey, ref BLENDFUNCTION pblend, int dwFlags);
  [DllImport("gdi32.dll")] public static extern IntPtr CreateCompatibleDC(IntPtr hdc);
  [DllImport("gdi32.dll")] public static extern bool DeleteDC(IntPtr hdc);
  [DllImport("gdi32.dll")] public static extern IntPtr SelectObject(IntPtr hdc, IntPtr h);
  [DllImport("gdi32.dll")] public static extern bool DeleteObject(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr hwnd);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr hwnd, IntPtr hdc);
}
public class LogoForm : System.Windows.Forms.Form {
  public Func<int, int, int> NcHitTest;      // client (x,y) -> HTCLIENT(1)/HTTRANSPARENT(-1)
  public System.Action FramePaint;           // WM_PAINT: push one layered frame
  protected override CreateParams CreateParams {
    get { CreateParams cp = base.CreateParams; cp.ExStyle |= 0x00080000; return cp; } }
  protected override void WndProc(ref System.Windows.Forms.Message m) {
    if (m.Msg == 0x0084 && NcHitTest != null) {           // WM_NCHITTEST
      long lp = m.LParam.ToInt64();
      int sx = unchecked((short)(lp & 0xFFFF));
      int sy = unchecked((short)((lp >> 16) & 0xFFFF));
      System.Drawing.Point pt = PointToClient(new System.Drawing.Point(sx, sy));
      m.Result = new IntPtr(NcHitTest(pt.X, pt.Y));
      return;
    }
    if (m.Msg == 0x000F && FramePaint != null) {          // WM_PAINT
      base.WndProc(ref m);        // validates the update region (BeginPaint)
      FramePaint();               // ...then the real content goes up as layers
      return;
    }
    base.WndProc(ref m);
  }
}
'@ -ReferencedAssemblies System.Windows.Forms, System.Drawing

# ------------------------------------------------------- frame math in ----
# tools/logo_frame.ps1 is PURE (no window, no files, no clock) and is the ONLY
# implementation of the motion spec math. The guards dot-source this same file
# (FLO-10a/b) -- one implementation, two callers.
$script:frameOk = $false
if ($Frame -ne "" -and (Test-Path -LiteralPath $Frame)) {
  try { . $Frame; $script:frameOk = $true } catch { $script:frameOk = $false }
}

# --- state icon family (SAME mapping as inbox_tray.icon_file / SHIELD_SUFFIX) ---
# 0.53.1: this is now the FALLBACK only (used when the motion spec cannot be
# obtained -- old tray.json / spec build failure). The primary path draws the
# animated mark. Degradation is honest: static, never pretending to move.
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
$script:pushFailed = $false
$script:pushFailTip = -join [char[]]@(0x753B,0x9762,0x63A8,0x9001,0x5931,0x8D25,
  0xFF1A,0x770B,0x4E0D,0x5230,0x54E8,0x6807,0x56FE,0x6848,0xFF0C,0x70B9,0x5B83,
  0x4ECD,0x80FD,0x5C55,0x5F00,0x76D1,0x7406)

# ---------------------------------------------------------------- window ---
$form = New-Object LogoForm
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
$form.Text = $Title
# NOTE: NO TransparencyKey here on purpose (0.53.1). The window is a
# per-pixel-alpha layered window; mixing a colour key into it is what produced
# the pink fringe in 0.50.0. The form's own DC is never displayed.
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
# --- motion spec (0.53.1) ---
$script:spec = $null            # hashtable from tray.json's "logo" block
$script:hadSpec = $false
$script:motionKey = "L0"        # spec.modes[state] (Ls -> LD, dev -> L0)
$script:vis = $null             # current eased visual (the JS's V)
$script:snap = $null            # visual at the moment of the mode switch
$script:hitRadius = [int][Math]::Floor($Size / 2.0)   # safe default until spec
$script:reduceMotion = $false
try {
  # Windows' "show animations in windows" preference -- the system-level twin
  # of the page's prefers-reduced-motion (Q-20). 0 = off = respect it.
  $ma = (Get-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop\WindowMetrics" `
         -Name MinAnimate -ErrorAction Stop).MinAnimate
  if ("$ma" -eq "0") { $script:reduceMotion = $true }
} catch { }
$script:modeClock = New-Object System.Diagnostics.Stopwatch
$script:modeClock.Start()
# frame bitmaps: render at 2x with AA, downscale (sub-pixel strokes survive)
$script:bmpLo = New-Object System.Drawing.Bitmap($Size, $Size,
  [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$script:bmpHi = New-Object System.Drawing.Bitmap((2 * $Size), (2 * $Size),
  [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
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
    # alpha: <128 fully transparent, >=128 fully opaque. WHY: the fallback
    # path blits this bitmap straight into the layered frame -- any
    # semi-transparent pixel would keep partial alpha and look muddy next to
    # the AA-drawn mark. Snapped alpha leaves no in-between.
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

function Import-Spec($logo) {
  # tray.json's "logo" block -> spec hashtable. Anything missing or malformed
  # => $null => the badge honestly falls back to the static tray icon.
  if ($null -eq $logo) { return $null }
  if (-not $script:frameOk) { return $null }
  try {
    $h = ConvertTo-Hashtable $logo
    if ($null -eq $h.motion -or $h.motion.Count -lt 1) { return $null }
    foreach ($k in @("cx","cy","r","ringW","amberR","waveGap","beamLen","beamW","half")) {
      if ($null -eq $h.geom[$k]) { return $null }
    }
    foreach ($k in @("trailN","trailStep","trailOpa","trailFrac","trailInset",
                     "wavePeriod","waveW0","waveW1","beamStart","segGap",
                     "breathBase","breathAmp","breathPeriod","xfade",
                     "l0Delay","l0Ramp","r0Slide","r0SlideT")) {
      if ($null -eq $h.anim[$k]) { return $null }
    }
    foreach ($k in @("ringGreen","ringDarkRed","amber","trail")) {
      if ($null -eq $h.colors[$k]) { return $null }
    }
    if ($null -eq $h.modes) { return $null }
    return $h
  } catch { return $null }
}

function Enter-Mode {
  # A mode switch: snapshot the current visual and restart the clock -- the
  # frame math eases from the snapshot over $xfade seconds (mirrors _LOGO_JS
  # setMode()). The very first switch snapshots the boot visual.
  $script:modeClock.Restart()
  if ($script:spec -ne $null) {
    if ($null -eq $script:vis) { $script:vis = New-Visual $script:spec }
    $script:snap = $script:vis
    $script:hitRadius = Get-HitRadius $Size $script:spec
    Start-Pump                     # spec just arrived: the animation starts now
    Invoke-Frame                  # ...and one frame NOW (mt=0 = the snapshot):
                                  # no 40ms wait after a switch, and the ONLY
                                  # path that draws under reduced motion (the
                                  # frame pump idles there). Safe here: this
                                  # runs on the form's thread already
                                  # (Read-State <- pool poll <- marshal).
  }
  if ($form.Visible) { $form.Invalidate() }
}

function Read-State {
  # stale guard (same rule as tray.ps1): never render a long-dead state as now
  if (([DateTime]::UtcNow - $script:lastPoll).TotalMilliseconds -lt 250) { return }
  $script:lastPoll = [DateTime]::UtcNow
  try {
    if (-not (Test-Path -LiteralPath $State)) { $script:trayStale = $true; return }
    # Parse ONLY when the file changed: the JSON parse is the most expensive
    # thing this badge does (~77ms on a loaded machine, measured 2026-10-19)
    # and tray.json changes only on state transitions. A resident badge that
    # re-parses 4x a second forever is a battery complaint waiting to happen.
    $w = (Get-Item -LiteralPath $State).LastWriteTimeUtc
    if ((-not $script:stateParsed) -or ($w -ne $script:stateStamp)) {
      $j = Get-Content -LiteralPath $State -Raw -Encoding UTF8 | ConvertFrom-Json
      $st = [string]$j.state
      if ([string]::IsNullOrWhiteSpace($st)) { $st = "L0" }
      $sh = [string]$j.shield
      if ([string]::IsNullOrWhiteSpace($sh)) { $sh = "on" }
      $first = -not $script:loaded
      $script:loaded = $true
      $changed = $first -or ($st -ne $script:mode) -or ($sh -ne $script:shield)
      $script:mode = $st
      $script:shield = $sh
      $hasSpec = ($null -ne $j.PSObject.Properties["logo"])
      if ($changed -or ($hasSpec -ne $script:hadSpec)) {
        # spec presence flipped or state changed => (re)load spec, re-enter mode
        $script:hadSpec = $hasSpec
        $script:spec = Import-Spec $(if ($hasSpec) { $j.logo } else { $null })
        if ($script:spec -ne $null) {
          $key = [string]$script:spec.modes[$st]
          if ([string]::IsNullOrWhiteSpace($key)) { $key = "L0" }
          $script:motionKey = $key
        } else {
          $script:motionKey = "L0"
          Load-Icon (Resolve-IconPath $st $sh)
        }
        if ($script:spec -ne $null -or $first) { Enter-Mode }
      }
      $t = [string]$j.tip
      if ([string]::IsNullOrWhiteSpace($t)) { $t = $Tip }
      $script:tip = $t
      $script:stateTs = if ($j.PSObject.Properties.Name -contains "ts") { $j.ts } else { $null }
      $script:stateStamp = $w
      $script:stateParsed = $true
    }
    # Staleness is a function of NOW, so it is recomputed EVERY poll even when
    # the file did not change: the cached ts is the file's, the age is not.
    # (This is why the parse guard above may not cache the verdict.)
    $age = -1
    if ($null -ne $script:stateTs) {
      try { $age = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) - [int64]($script:stateTs) } catch { $age = -1 }
    }
    $script:trayStale = (($age -lt 0) -or ($age -gt $StaleAfterSec))
  } catch { $script:trayStale = $true }
}

function Map-X { param([double]$x,[double]$s,[double]$off,$geom)
  return (($x - [double]$geom.cx) * $s + $off) }
function Map-Y { param([double]$y,[double]$s,[double]$off,$geom)
  return (($y - [double]$geom.cy) * $s + $off) }

function Get-Pen($rgb, [double]$alpha, [double]$width) {
  $a = [int](Get-Clamp ($alpha * 255.0) 0 255)
  $c = [System.Drawing.Color]::FromArgb($a, [int]$rgb[0], [int]$rgb[1], [int]$rgb[2])
  return (New-Object System.Drawing.Pen($c, [float]$width))
}

function Draw-Canvas {
  param($g, [double]$s, [double]$off, $f, $spec)
  # Draw one frame (canvas units from Get-Frame) onto $g. $s maps canvas ->
  # pixels, $off is the bitmap centre. Every colour/geometry value comes from
  # the spec -- nothing here is typed in twice.
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
  $geom = $spec.geom
  $tw = [double]$geom.beamW * $s
  foreach ($t in $f.trail) {
    if ($t.opa -le 0) { continue }
    $pen = Get-Pen $f.beamC $t.opa $tw
    try {
      $g.DrawLine($pen, [float](Map-X $t.x1 $s $off $geom), [float](Map-Y $t.y1 $s $off $geom),
                        [float](Map-X $t.x2 $s $off $geom), [float](Map-Y $t.y2 $s $off $geom))
    } finally { $pen.Dispose() }
  }
  $pen = Get-Pen $f.beamC 1.0 $tw
  try {
    $g.DrawLine($pen, [float]$off, [float]$off,
                      [float](Map-X $f.beam.x2 $s $off $geom),
                      [float](Map-Y $f.beam.y2 $s $off $geom))
  } finally { $pen.Dispose() }
  $segs = Get-RingSegments $spec
  $rr = [double]$geom.r * $s
  $ringA = Get-Clamp ($f.ringO * $f.breath) 0 1
  $pen = Get-Pen $f.ringC $ringA ([double]$geom.ringW * $s)
  try {
    foreach ($sg in $segs) {
      $rect = New-Object System.Drawing.RectangleF([float]($off - $rr), [float]($off - $rr),
                                                   [float](2 * $rr), [float](2 * $rr))
      $g.DrawArc($pen, $rect, [float]($sg.a0 - 90), [float]($sg.a1 - $sg.a0))
    }
  } finally { $pen.Dispose() }
  if ($f.amberO -gt 0) {
    $ar = [double]$geom.amberR * $s
    $brush = New-Object System.Drawing.SolidBrush(
      [System.Drawing.Color]::FromArgb([int](Get-Clamp ($f.amberO * 255.0) 0 255),
        [int]$spec.colors.amber[0], [int]$spec.colors.amber[1], [int]$spec.colors.amber[2]))
    try {
      $g.FillEllipse($brush, [float](Map-X $f.amber.cx $s $off $geom - $ar),
                              [float](Map-Y $f.amber.cy $s $off $geom - $ar),
                              [float](2 * $ar), [float](2 * $ar))
    } finally { $brush.Dispose() }
  }
  foreach ($w in $f.waves) {
    if ($w.opa -le 0) { continue }
    $r = [double]$w.r * $s
    if ($r -le 0) { continue }
    $pen = Get-Pen $f.beamC $w.opa ([double]$w.w * $s)
    try {
      $g.DrawEllipse($pen, [float](Map-X $w.cx $s $off $geom - $r),
                            [float](Map-Y $w.cy $s $off $geom - $r),
                            [float](2 * $r), [float](2 * $r))
    } finally { $pen.Dispose() }
  }
}

function Draw-Frame-Bitmaps {
  param($f)
  $half = [double]$script:spec.geom.half
  $sHi = (2 * $Size) / (2.0 * $half)
  $offHi = $Size
  $g = [System.Drawing.Graphics]::FromImage($script:bmpHi)
  try {
    $g.Clear([System.Drawing.Color]::Transparent)
    Draw-Canvas $g $sHi $offHi $f $script:spec
  } finally { $g.Dispose() }
  $g2 = [System.Drawing.Graphics]::FromImage($script:bmpLo)
  try {
    $g2.Clear([System.Drawing.Color]::Transparent)
    $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g2.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
    $g2.DrawImage($script:bmpHi, 0, 0, $Size, $Size)
  } finally { $g2.Dispose() }
}

function Push-Frame {
  param($Bmp)
  # The bitmap becomes the window content (per-pixel alpha). Position comes
  # from the form's CURRENT location, so a drag only needs one repaint.
  $screenDc = [LogoLayered]::GetDC([IntPtr]::Zero)
  try {
    $memDc = [LogoLayered]::CreateCompatibleDC($screenDc)
    try {
      $hBmp = $Bmp.GetHbitmap([System.Drawing.Color]::FromArgb(0))
      $old = [LogoLayered]::SelectObject($memDc, $hBmp)
      try {
        $pt = New-Object LogoLayered+POINT
        $pt.X = $form.Location.X
        $pt.Y = $form.Location.Y
        $sz = New-Object LogoLayered+SIZE
        $sz.CX = $Size
        $sz.CY = $Size
        $src = New-Object LogoLayered+POINT
        $blend = New-Object LogoLayered+BLENDFUNCTION
        $blend.BlendOp = 0
        $blend.BlendFlags = 0
        $blend.SourceConstantAlpha = 255
        $blend.AlphaFormat = 1
        if (-not [LogoLayered]::UpdateLayeredWindow($form.Handle, [IntPtr]::Zero,
                [ref]$pt, [ref]$sz, $memDc, [ref]$src, 0, [ref]$blend, 2)) {
          $script:pushFailed = $true
        }
      } finally {
        [LogoLayered]::SelectObject($memDc, $old) | Out-Null
        [LogoLayered]::DeleteObject($hBmp) | Out-Null
      }
    } finally { [LogoLayered]::DeleteDC($memDc) | Out-Null }
  } finally { [LogoLayered]::ReleaseDC([IntPtr]::Zero, $screenDc) | Out-Null }
}

# --- hit test: the whole drawn area is clickable, the corners are not -------
$form.NcHitTest = {
  param($x, $y)
  if (-not $script:frameOk) { return 1 }
  if (Test-Hit $x $y $Size $script:hitRadius) { return 1 }
  return -1
}

# --- paint: compute the frame, draw it, push it as the window content -------
function Invoke-Frame {
  try {
    if ($script:spec -ne $null -and $script:frameOk) {
      $mt = $script:modeClock.Elapsed.TotalSeconds
      if ($script:reduceMotion) {
        # reduced motion: one static frame at the TARGET state (xfade in, not
        # the boot state -- that green-ring bug is what FLO-10e guards)
        $mt = [double]$script:spec.anim.xfade
      }
      $f = Get-Frame -Spec $script:spec -Mode $script:motionKey -Mt $mt -Snap $script:snap
      if ($null -ne $f) {
        $script:vis = @{ theta = $f.theta; beamC = $f.beamC; ringO = $f.ringO
                         amberO = $f.amberO; ringRed = $f.ringRed; breath = $f.breath }
        Draw-Frame-Bitmaps $f
      }
    } elseif ($script:icoBmp -ne $null) {
      $g = [System.Drawing.Graphics]::FromImage($script:bmpLo)
      try {
        $g.Clear([System.Drawing.Color]::Transparent)
        # NearestNeighbor: the bitmap alpha is snapped 0/255 -- any smoothing
        # would re-create semi-transparent edge pixels and a muddy edge
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
        $g.DrawImage($script:icoBmp, 0, 0, $Size, $Size)
      } finally { $g.Dispose() }
    } else {
      $g = [System.Drawing.Graphics]::FromImage($script:bmpLo)
      try { $g.Clear([System.Drawing.Color]::Transparent) } finally { $g.Dispose() }
    }
    Push-Frame $script:bmpLo
  } catch {
    $script:pushFailed = $true
  }
}
$form.FramePaint = { Invoke-Frame }

# ------------------------------------------------------- animation pump ----
# 0.53.1: frames are pushed by a THREAD-POOL TIMER marshaled onto the form's
# own thread (System.Timers.Timer + SynchronizingObject; the timers are built
# below, next to the state poller). TWO earlier designs were measured and
# rejected on this very machine (2026-10-19):
#   * Invalidate-per-WinForms-tick (0.50.0): WM_TIMER is SYNTHESIZED only
#     when the message queue is empty. With the mouse over the badge the
#     queue never empties, so the animation starved mid-run while clicks
#     still went through (the pump was alive, the timer was not).
#   * Self-perpetuating POSTED INVOKE (0.53.1 first cut): the handler reposts
#     the next frame before it returns, so the queue never empties either --
#     the same starvation, now self-inflicted. 8 live runs: ticks=1 while
#     frames=352; the quit flag was never consumed, 4 runs showed no window.
# A pool timer fires on its own thread and marshals ONE callback per fire
# (ISynchronizeInvoke.BeginInvoke). AutoReset=$false re-arms the timer only
# after the handler RETURNS, so at most one callback is ever pending and the
# queue empties between frames (probe 2026-10-19: WM_PAINT synthesized 33
# times while 25 callbacks ran, every one of them on the form's thread). A
# machine too slow for the budget fires late instead of stacking a queue.
$LOGO_FRAME_MS = 40                       # 25fps budget
$LOGO_POLL_MS = 250                       # state poll (quit/show/hide/stale)
$script:lastFrameUtc = [DateTime]::UtcNow
$script:quitting = $false

function Quit-Now {
  $script:quitting = $true
  Stop-Pump
  Stop-Poll
  try { $form.Close() } catch { }
  [System.Windows.Forms.Application]::Exit()
}

function Show-Now {
  try {
    $form.Show()
    $form.TopMost = $true
    $form.Activate()
    Start-Pump                     # hidden => the pump idled; restart it
    Invoke-Frame                  # repaint NOW at the shown position -- also
                                  # the only path that draws under reduced
                                  # motion (the frame pump idles there)
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
  # the layered content is positioned BY the push -- moving the window must
  # repaint or the mark stays visually behind at the old spot
  if ($form.Visible) { $form.Invalidate() }
})
$form.add_MouseUp({
  param($s, $e)
  if (-not $script:dragging) { return }
  $script:dragging = $false
  if ($null -eq $script:downAt) { return }        # MouseDown was swallowed
  $dt = (([DateTime]::UtcNow) - $script:downAt).TotalSeconds
  if (($script:moved -le 5) -and ($dt -le 1.0)) {
    Write-Action "open" | Out-Null
    # the click does NOT exit here (0.52.0): the consumer opens the console,
    # then writes the hide flag and the badge hides itself. Nothing consumes
    # the action => the badge STAYS and the user can click again.
  }
})

# The tick body is a named scriptblock wrapped in try/catch: an exception
# anywhere in it (Read-State, the flag checks) must never abort the rest --
# a half-run tick is how the pump used to lose its kick.
$script:onTick = {
  if (Test-Path -LiteralPath $Quit) { Quit-Now }
  if (Consume-Flag $Show) { Show-Now }
  if (Consume-Flag $Hide) { Hide-Now }
  try { Read-State } catch { $script:trayStale = $true }
  # 0.53.1: the animation is driven by the POOL frame timer (see the animation
  # pump block), not by Invalidate-per-tick -- WM_PAINT/WM_TIMER starve under
  # input load. This poll is the frame pump's watchdog: no frame for 1.5s
  # while the badge should be animating => kick the pump again.
  if ((-not $script:reduceMotion) -and $form.Visible -and ($script:spec -ne $null)) {
    if (([DateTime]::UtcNow - $script:lastFrameUtc).TotalSeconds -gt 1.5) { Start-Pump }
  }
  $tp = $script:tip
  if ($script:trayStale) { $tp = $TipStale }
  if ($script:actionWriteFailed) { $tp = $script:actionWriteFailTip }
  if ($script:pushFailed) { $tp = $script:pushFailTip }
  if ($tp.Length -gt 63) { $tp = $tp.Substring(0, 63) }
  if ($tp -ne $script:tipShown) {
    try { $tipCtl.SetToolTip($form, $tp) } catch { }
    $script:tipShown = $tp
  }
}
# ---------------------------------------------------------------- timers ---
# Both are pool timers marshaled onto the form's thread -- see the animation
# pump block for why NOT a WinForms timer and NOT a posted invoke.
$script:frameTimer = New-Object System.Timers.Timer($LOGO_FRAME_MS)
$script:frameTimer.SynchronizingObject = $form
$script:frameTimer.AutoReset = $false
$script:frameTimer.Add_Elapsed({
  param($s, $e)
  $t0 = [DateTime]::UtcNow
  try {
    if ((-not $script:reduceMotion) -and $form.Visible -and ($script:spec -ne $null)) {
      Invoke-Frame
      $script:lastFrameUtc = [DateTime]::UtcNow
    }
  } catch {
    $script:pushFailed = $true
  } finally {
    # Restart-in-finally: an exception in the body must NOT kill the pump
    # (a dead pump is a silently frozen badge -- the worst failure there
    # is). The interval ADAPTS to the measured work: budget minus elapsed,
    # floored at 1ms. A fast machine gets the full 25fps budget; a slow one
    # simply fires back-to-back (rate = 1/work) -- never a growing queue.
    try {
      if (-not $script:quitting) {
        $left = $LOGO_FRAME_MS - ([DateTime]::UtcNow - $t0).TotalMilliseconds
        if ($left -lt 1) { $left = 1 }
        $s.Interval = [int]$left
        $s.Start()
      }
    } catch { }
  }
})

$script:pollTimer = New-Object System.Timers.Timer($LOGO_POLL_MS)
$script:pollTimer.SynchronizingObject = $form
$script:pollTimer.AutoReset = $false
$script:pollTimer.Add_Elapsed({
  param($s, $e)
  try { & $script:onTick } catch { }
  finally {
    try { if (-not $script:quitting) { $s.Start() } } catch { }
  }
})

function Start-Pump {
  # Arm the frame pump. Idempotent: Start() on an armed pool timer is a
  # no-op; on a fired-but-not-rearmed one it kicks the next frame.
  try { if ($null -ne $script:frameTimer) { $script:frameTimer.Start() } } catch { }
}
function Stop-Pump {
  try { if ($null -ne $script:frameTimer) { $script:frameTimer.Stop() } } catch { }
}
function Start-Poll {
  try { if ($null -ne $script:pollTimer) { $script:pollTimer.Start() } } catch { }
}
function Stop-Poll {
  try { if ($null -ne $script:pollTimer) { $script:pollTimer.Stop() } } catch { }
}

# The pumps may only run once the form HAS a handle: SynchronizingObject
# marshals through it, and a fire before that is an InvalidOperationException
# on the POOL thread -- a crash, not a warning. Load is the first moment the
# handle exists, and it fires in both paths (Application.Run($form) shows
# the form; the -Hidden prewarm shows-then-hides it).
$form.add_Load({
  Start-Pump
  Start-Poll
})

# Any close path (Quit-Now, WM_CLOSE, Application.Exit) stops the pool
# timers first: a fire after the form is gone marshals onto a dead handle.
$form.add_FormClosing({
  param($s, $e)
  $script:quitting = $true
  Stop-Pump
  Stop-Poll
})

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
  Stop-Pump
  Stop-Poll
  try { $form.Dispose() } catch { }
}
