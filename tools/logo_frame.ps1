# logo_frame.ps1 -- Antinel console: floating sentry mark -- PURE frame math.
#
# 0.53.0 (founder 2026-10-19, screenshot of the minimized badge): three
# symptoms, one root each, all fixed here or in logo.ps1:
#   * the badge showed a bare circle (the tray-family static .ico), not the
#     standard Antinel mark  -> it now draws the SAME motion spec as the page
#   * clicking the MIDDLE of the circle did nothing (TransparencyKey window +
#     fully transparent icon centre => hit test only covered opaque pixels)
#     -> WM_NCHITTEST now covers the whole drawn area (logo.ps1)
#   * the badge was dead (0.50.0 GDI+ motion was pulled in 0.52.0 because
#     40ms full repaints without double buffering trembled) -> per-pixel
#     alpha via UpdateLayeredWindow + frames computed HERE
#
# This file is PURE: no window, no files, no clock, no drawing. Inputs are
#   $Spec  -- the motion spec hashtable (tray.json's "logo" block, built by
#             inbox_server.logo_motion_spec(); parse with ConvertTo-Hashtable)
#   $Mode  -- motion key ("L0"/"L1"/"L2"/"LD"/"R0")
#   $Mt    -- seconds since this mode was entered
#   $Snap  -- the visual state at the moment of the mode switch
# Output is a frame hashtable of plain numbers in CANVAS units -- exactly the
# quantities _LOGO_JS drives in the browser. logo.ps1 only maps canvas->pixels
# and paints; ci/inbox_guards_0514.py (FLO-10a/b) dot-sources THIS SAME FILE
# under powershell.exe and runs these functions -- one implementation, two
# callers. Never re-implement the frame math anywhere else.
#
# ASCII-only on purpose (same discipline as logo.ps1: Windows PowerShell 5.1
# mis-decodes UTF-8 source without a BOM; every label arrives as a parameter
# from Python, where the encoding is under our control).

function Get-Clamp {
  param([double]$x, [double]$a, [double]$b)
  if ([double]::IsNaN($x)) { return $a }
  if ($x -lt $a) { return $a }
  if ($x -gt $b) { return $b }
  return $x
}

function Get-EaseOut {
  param([double]$t)
  return (1 - [Math]::Pow(1 - $t, 3))
}

function Get-EaseInOut {
  param([double]$t)
  if ($t -lt 0.5) { return 4 * $t * $t * $t }
  return (1 - [Math]::Pow(-2 * $t + 2, 3) / 2)
}

function Get-Lerp {
  param([double]$a, [double]$b, [double]$t)
  return ($a + ($b - $a) * $t)
}

function Get-Mix {
  param($a, $b, [double]$t)
  return @((Get-Lerp $a[0] $b[0] $t), (Get-Lerp $a[1] $b[1] $t),
           (Get-Lerp $a[2] $b[2] $t))
}

function Get-Mod {
  param([double]$a)
  $r = $a % 360
  if ($r -lt 0) { $r += 360 }
  return $r
}

function Get-Px {
  param([double]$a, [double]$r, $geom)
  # canvas units: 0 deg = north, clockwise (mirrors _LOGO_JS px())
  $rad = $a * [Math]::PI / 180.0
  return @(([double]$geom.cx + $r * [Math]::Sin($rad)),
           ([double]$geom.cy - $r * [Math]::Cos($rad)))
}

function ConvertTo-Hashtable {
  param($obj)
  # ConvertFrom-Json yields PSCustomObject trees; the frame math speaks
  # hashtable. One converter, used by logo.ps1 AND by the guards' driver --
  # so the parse step under test is the production parse step.
  if ($obj -is [System.Management.Automation.PSCustomObject]) {
    $h = @{}
    foreach ($p in $obj.PSObject.Properties) {
      $h[$p.Name] = ConvertTo-Hashtable $p.Value
    }
    return $h
  }
  if ($obj -is [Array]) {
    return @($obj | ForEach-Object { ConvertTo-Hashtable $_ })
  }
  return $obj
}

function New-Visual {
  param($Spec)
  # The boot visual == the L0 row of the motion table (mirrors _LOGO_JS boot
  # V: beamC = STYLE.L0.c, ringO 1, amberO .35, ringRed 0). The first mode
  # switch eases FROM here, exactly like the page does.
  $l0 = $Spec.motion["L0"]
  if ($null -eq $l0) { return $null }
  return @{
    theta   = [double]$Spec.anim.beamStart
    beamC   = @([double]$l0.c[0], [double]$l0.c[1], [double]$l0.c[2])
    ringO   = [double]$l0.ringO
    amberO  = [double]$l0.amberO
    ringRed = [double]$l0.ringRed
    breath  = [double]$Spec.anim.breathBase
  }
}

function Get-Frame {
  param($Spec, [string]$Mode, [double]$Mt, $Snap)
  # Returns the frame for this mode at this elapsed time, eased from $Snap.
  # Mirrors _LOGO_JS update()+render() line by line -- if the page's motion
  # changes, THIS function changes with it (FLO-10d pins the constants).
  $st = $Spec.motion[$Mode]
  if ($null -eq $st) { $st = $Spec.motion["L0"] }
  if ($null -eq $st) { return $null }
  $a = $Spec.anim
  $g = $Spec.geom
  $k = Get-EaseOut (Get-Clamp ($Mt / [double]$a.xfade) 0 1)
  $beamC = Get-Mix $Snap.beamC $st.c $k
  $ringO = Get-Lerp $Snap.ringO ([double]$st.ringO) $k
  $amberO = Get-Lerp $Snap.amberO ([double]$st.amberO) $k
  $ringRed = Get-Lerp $Snap.ringRed ([double]$st.ringRed) $k
  $breath = [double]$a.breathBase + [double]$a.breathAmp *
            [Math]::Sin($Mt * 2 * [Math]::PI / [double]$a.breathPeriod)
  $lap = [double]$st.lap
  if ($Mode -eq "L0") {
    if ($Mt -gt [double]$a.l0Delay) {
      $w = Get-Clamp (($Mt - [double]$a.l0Delay) / [double]$a.l0Ramp) 0 1
      $theta = Get-Mod ($Snap.theta + ($Mt - [double]$a.l0Delay) * 360.0 / $lap *
                        (Get-Lerp 0.5 1.0 (Get-EaseOut $w)))
    } else {
      $theta = [double]$Snap.theta
    }
  } elseif ($lap -gt 0) {
    $theta = Get-Mod ($Snap.theta + $Mt * 360.0 / $lap)
  } else {
    $theta = Get-Mod ($Snap.theta + [double]$a.r0Slide *
                      (Get-EaseInOut (Get-Clamp ($Mt / [double]$a.r0SlideT) 0 1)))
  }
  $beamEnd = Get-Px $theta ([double]$g.beamLen) $g
  $amberPt = Get-Px $theta ([double]$g.r) $g
  $ringC = Get-Mix $Spec.colors.ringGreen $Spec.colors.ringDarkRed $ringRed
  $trail = @()
  for ($i = 0; $i -lt [int]$a.trailN; $i++) {
    $ang = Get-Mod ($theta - ($i + 1) * [double]$a.trailStep)
    $r0 = [double]$g.beamLen * (1 - [double]$a.trailFrac)
    $r1 = [double]$g.beamLen - [double]$a.trailInset
    $p0 = Get-Px $ang $r0 $g
    $p1 = Get-Px $ang $r1 $g
    $trail += @{
      a = $ang; x1 = $p0[0]; y1 = $p0[1]; x2 = $p1[0]; y2 = $p1[1]
      opa = [double]$a.trailOpa[$i]
    }
  }
  $waves = @()
  $on = ($Mode -eq "L1" -or $Mode -eq "L2" -or $Mode -eq "LD")
  for ($wv = 0; $wv -lt 2; $wv++) {
    if (-not $on) {
      $waves += @{ cx = $amberPt[0]; cy = $amberPt[1]; r = 0.0; w = 0.0; opa = 0.0 }
      continue
    }
    $ph = (($Mt + $wv * [double]$a.wavePeriod / 2) % [double]$a.wavePeriod) /
          [double]$a.wavePeriod
    $waves += @{
      cx = $amberPt[0]; cy = $amberPt[1]
      r = [double]$g.amberR + [double]$g.waveGap + $ph * [double]$st.waveR
      w = [double]$a.waveW0 - [double]$a.waveW1 * $ph
      opa = [double]$st.waveO * (1 - $ph) * (1 - $ph)
    }
  }
  # ** 0.55.0: the brand plate as frame data. The colour is the spec's
  #    colors.plate (single source: logo.svg's rect fill == the page's
  #    .logo background == this spec, FLO-19a pins the four copies); the
  #    geometry is the BOX itself (half), so the plate covers the window
  #    edge to edge -- which is also why the hit test is the whole window
  #    once a plate is drawn (see $form.NcHitTest in logo.ps1).
  #    Missing colour => $null => the renderer draws no plate; Import-Spec
  #    rejects such a spec anyway, so the badge falls back to the brand
  #    icon (which carries the plate) instead of losing it silently.
  $plate = $null
  if ($null -ne $Spec.colors.plate) {
    $plate = @{
      x = [double]$g.cx - [double]$g.half
      y = [double]$g.cy - [double]$g.half
      w = 2.0 * [double]$g.half
      h = 2.0 * [double]$g.half
      rgb = $Spec.colors.plate
    }
  }
  return @{
    mode = $Mode; mt = $Mt; theta = $theta; beamC = $beamC
    ringO = $ringO; amberO = $amberO; ringRed = $ringRed
    breath = $breath; ringC = $ringC
    beam = @{ x1 = [double]$g.cx; y1 = [double]$g.cy
              x2 = $beamEnd[0]; y2 = $beamEnd[1] }
    amber = @{ cx = $amberPt[0]; cy = $amberPt[1]; r = [double]$g.amberR }
    trail = $trail
    waves = $waves
    plate = $plate
  }
}

function Get-ContentExtent {
  param($Spec)
  # How far the mark can ever be drawn from the centre (canvas units): the
  # lamp head + gap + that mode's wave amplitude, max over modes, capped by
  # the box half-width. This -- not a hardcoded pixel count -- defines the
  # clickable area, so the hit region can never drift from what is drawn.
  $g = $Spec.geom
  $ext = 0.0
  foreach ($key in $Spec.motion.Keys) {
    $m = $Spec.motion[$key]
    $e = [double]$g.r + [double]$g.amberR + [double]$g.waveGap +
         [double]$m.waveR
    if ($e -gt $ext) { $ext = $e }
  }
  $half = [double]$g.half
  if ($ext -gt $half) { $ext = $half }
  return $ext
}

function Get-HitRadius {
  param([int]$Size, $Spec)
  # The clickable radius in client pixels = the drawn extent mapped through
  # the canvas->pixel scale (viewBox half -> Size/2). Derived from the spec,
  # never typed in (FLO-10a checks it against the Python-side computation).
  $scale = $Size / (2.0 * [double]$Spec.geom.half)
  return [int][Math]::Round((Get-ContentExtent $Spec) * $scale)
}

function Test-Hit {
  param([int]$X, [int]$Y, [int]$Size, [int]$Radius)
  # True when (X,Y) -- client coordinates -- lies inside the mark's circle.
  # The four corners of the window are outside on purpose: they stay
  # click-through so the badge never steals clicks meant for what is behind.
  $dx = $X - $Size / 2.0
  $dy = $Y - $Size / 2.0
  return (($dx * $dx + $dy * $dy) -le ($Radius * $Radius))
}

function Get-RingSegments {
  param($Spec)
  # The four ring arcs with the gaps between them (same geometry as the
  # SEGS table in _LOGO_JS, derived from the one segGap constant).
  $segs = @()
  $gap = [double]$Spec.anim.segGap
  for ($q = 0; $q -lt 4; $q++) {
    $segs += @{ a0 = $q * 90 + $gap / 2.0; a1 = ($q + 1) * 90 - $gap / 2.0 }
  }
  return $segs
}
