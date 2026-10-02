Add-Type -AssemblyName System.Windows.Forms

$source = (Resolve-Path -LiteralPath $PSScriptRoot).Path.TrimEnd('\')
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Choose a folder on the other device where HashHarbor should be copied.'
$dialog.ShowNewFolderButton = $true

if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
    exit 0
}

$destinationRoot = [System.IO.Path]::GetFullPath($dialog.SelectedPath).TrimEnd('\')
$sourcePrefix = $source + '\'
if ($destinationRoot.Equals($source, [System.StringComparison]::OrdinalIgnoreCase) -or
    $destinationRoot.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    [System.Windows.Forms.MessageBox]::Show(
        'Choose a folder outside the HashHarbor project.',
        'HashHarbor project copy',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    exit 1
}

$destination = Join-Path $destinationRoot 'HashHarbor'
$excludedFolders = @('.git', '.venv', '__pycache__', '.vscode')
$robocopyArgs = @(
    $source,
    $destination,
    '/E',
    '/R:2',
    '/W:2',
    '/NFL',
    '/NDL',
    '/NJH',
    '/NJS',
    '/NP',
    '/XD'
) + $excludedFolders + @('/XF', '*.pyc')

& robocopy @robocopyArgs | Out-Null
$copyResult = $LASTEXITCODE

if ($copyResult -lt 8) {
    [System.Windows.Forms.MessageBox]::Show(
        "HashHarbor was copied to:`n$destination`n`nOn the other device, install Python 3.10 or newer and run file_sentinel.py.",
        'HashHarbor project copy complete',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    exit 0
}

[System.Windows.Forms.MessageBox]::Show(
    "The copy failed with robocopy exit code $copyResult.`nCheck that the destination device is connected and writable.",
    'HashHarbor project copy failed',
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Error
) | Out-Null
exit $copyResult