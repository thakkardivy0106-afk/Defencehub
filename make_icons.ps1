Add-Type -AssemblyName System.Drawing

$iconsDir = Join-Path $PSScriptRoot "icons"
if (-not (Test-Path $iconsDir)) {
    New-Item -ItemType Directory -Path $iconsDir | Out-Null
}

$sizes = @(16, 48, 128)

foreach ($size in $sizes) {
    $filePath = Join-Path $iconsDir "icon$size.png"
    $bmp = [System.Drawing.Bitmap]::new($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $w = [float]$size
    $h = [float]$size
    $pad = $w * 0.08

    $p1 = [System.Drawing.PointF]::new($w / 2.0, $pad)
    $p2 = [System.Drawing.PointF]::new($w - $pad, $pad + $h * 0.22)
    $p3 = [System.Drawing.PointF]::new($w - $pad, $h * 0.58)
    $p4 = [System.Drawing.PointF]::new($w / 2.0, $h - $pad)
    $p5 = [System.Drawing.PointF]::new($pad, $h * 0.58)
    $p6 = [System.Drawing.PointF]::new($pad, $pad + $h * 0.22)

    $pathObj = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $points = [System.Drawing.PointF[]]@($p1, $p2, $p3, $p4, $p5, $p6)
    $pathObj.AddPolygon($points)

    $navyBlue = [System.Drawing.Color]::FromArgb(255, 15, 23, 42)
    $accentBlue = [System.Drawing.Color]::FromArgb(255, 37, 99, 235)
    $brush = [System.Drawing.SolidBrush]::new($navyBlue)
    $g.FillPath($brush, $pathObj)

    $penWidth = [Math]::Max(1.5, $w * 0.07)
    $pen = [System.Drawing.Pen]::new($accentBlue, $penWidth)
    $g.DrawPath($pen, $pathObj)

    $checkPenWidth = [Math]::Max(1.5, $w * 0.09)
    $whitePen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, $checkPenWidth)
    $whitePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $whitePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    
    $cp1 = [System.Drawing.PointF]::new($w * 0.30, $h * 0.50)
    $cp2 = [System.Drawing.PointF]::new($w * 0.45, $h * 0.65)
    $cp3 = [System.Drawing.PointF]::new($w * 0.72, $h * 0.36)
    
    $checkPoints = [System.Drawing.PointF[]]@($cp1, $cp2, $cp3)
    $g.DrawLines($whitePen, $checkPoints)

    $g.Dispose()
    $bmp.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output "Saved $filePath"
}
