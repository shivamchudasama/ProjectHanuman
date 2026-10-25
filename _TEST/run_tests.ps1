<#
.SYNOPSIS
   Build and run every host test (C and Python) and write a merged report.

.DESCRIPTION
   Same tiers as the CI workflow (.github/workflows/ci.yml), minus the
   firmware build and the sanitizers (Linux only):
     1. C unit tests  - CMake + CTest + Unity, _TEST/CMakeLists.txt
     2. Python tests  - pytest, _TEST/python
   Output in build_test/report/: junit/*.xml, summary.md, report.html
   (and coverage/ with -Coverage).

   Tools: a host gcc on PATH (e.g. MinGW or Strawberry), Python 3.8+ on PATH.
   CMake, CTest and Ninja are taken from PATH, or else from the nRF Connect
   SDK toolchain in C:\ncs\toolchains.

.PARAMETER Coverage
   Also build the C tests with gcov and write HTML coverage for C and Python.

.PARAMETER Clean
   Delete build_test/ first.

.PARAMETER Static
   Also run the static analysis gate (tools/run_static.py: cppcheck, ruff,
   bandit), as the CI job static-analysis does.

.PARAMETER Fuzz
   Also build the fuzz targets in _TEST/fuzz with clang (LLVM on PATH or in
   C:\Program Files\LLVM) into build_fuzz/ and run each for -FuzzSeconds
   (default 30), as the CI job fuzz does.

.EXAMPLE
   powershell -ExecutionPolicy Bypass -File _TEST\run_tests.ps1
#>
param(
   [switch]$Coverage,
   [switch]$Clean,
   [switch]$Static,
   [switch]$Fuzz,
   [int]$FuzzSeconds = 30
)

$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Repo 'build_test'
$Report = Join-Path $Build 'report'

function Find-Tool([string]$Name) {
   $cmd = Get-Command $Name -ErrorAction SilentlyContinue
   if ($cmd) { return $cmd.Source }
   $ncs = Get-ChildItem 'C:\ncs\toolchains\*\opt\bin' -Directory -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -First 1
   if ($ncs -and (Test-Path (Join-Path $ncs.FullName "$Name.exe"))) {
      return (Join-Path $ncs.FullName "$Name.exe")
   }
   throw "$Name not found on PATH or in C:\ncs\toolchains"
}

$Cmake = Find-Tool 'cmake'
$Ctest = Find-Tool 'ctest'
$Ninja = Find-Tool 'ninja'
$Gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source
if (-not $Gcc) { throw 'gcc not found on PATH (install MinGW-w64 or Strawberry Perl)' }
$SysPython = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $SysPython) { throw 'python not found on PATH' }

if ($Clean -and (Test-Path $Build)) { Remove-Item -Recurse -Force $Build }

# Python venv with the test dependencies (kept in build_test/, git-ignored).
# pip runs every time, so a dependency added to requirements-test.txt reaches an
# existing venv too (it is quick when everything is already installed).
$Venv = Join-Path $Build 'venv'
$Py = Join-Path $Venv 'Scripts\python.exe'
if (-not (Test-Path $Py)) {
   & $SysPython -m venv $Venv
}
& $Py -m pip install --quiet --disable-pip-version-check -r (Join-Path $PSScriptRoot 'requirements-test.txt')
if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }

# Old reports must not leak into the new summary
if (Test-Path $Report) { Remove-Item -Recurse -Force $Report }

# ---- 1. C unit tests -----------------------------------------------------------
$covFlag = if ($Coverage) { 'ON' } else { 'OFF' }
& $Cmake -G Ninja -S $PSScriptRoot -B $Build "-DCMAKE_MAKE_PROGRAM=$Ninja" "-DCMAKE_C_COMPILER=$Gcc" `
   "-DPython3_EXECUTABLE=$Py" "-DCOVERAGE=$covFlag"
if ($LASTEXITCODE -ne 0) { throw 'CMake configure failed' }
& $Cmake --build $Build
if ($LASTEXITCODE -ne 0) { throw 'C test build failed' }
& $Ctest --test-dir $Build --output-on-failure
$cResult = $LASTEXITCODE

# ---- 2. Python tests -----------------------------------------------------------
$pyArgs = @('-m', 'pytest', (Join-Path $PSScriptRoot 'python'), '-q', '-p', 'no:cacheprovider',
   "--junitxml=$Report\junit\python.xml", '-o', 'junit_suite_name=python_tools')
if ($Coverage) {
   $env:COVERAGE_FILE = Join-Path $Build '.coverage'      # keep the data file out of the repo root
   $pyArgs += @("--cov=$Repo\_TOOLS\BleHostGUI", "--cov=$Repo\_TOOLS\MemReport",
      "--cov-report=html:$Report\coverage\python")
}
& $Py @pyArgs
$pyResult = $LASTEXITCODE

# ---- Coverage and report -------------------------------------------------------
if ($Coverage) {
   New-Item -ItemType Directory -Force "$Report\coverage\c" | Out-Null
   & $Py -m gcovr --root $Repo --object-directory $Build --filter '_LIB/' --filter '_ASW/' `
      --html-details "$Report\coverage\c\index.html" --print-summary
}
& $Py (Join-Path $PSScriptRoot 'tools\report.py') "$Report\junit" --md "$Report\summary.md" `
   --html "$Report\report.html" --title 'Project Hanuman host tests' | Out-Null

# ---- 3. Optional: static analysis and fuzzing ----------------------------------
$staticResult = 0
if ($Static) {
   & $Py -m pip install --quiet --disable-pip-version-check ruff bandit
   & $Py (Join-Path $PSScriptRoot 'tools\run_static.py') $Repo
   $staticResult = $LASTEXITCODE
}
$fuzzResult = 0
if ($Fuzz) {
   $llvm = 'C:\Program Files\LLVM\bin'
   if (-not (Get-Command clang -ErrorAction SilentlyContinue) -and (Test-Path $llvm)) { $env:PATH = "$llvm;$env:PATH" }
   $clang = (Get-Command clang -ErrorAction SilentlyContinue).Source
   if (-not $clang) { throw 'clang not found (install LLVM) for -Fuzz' }
   # On Windows ASan is a DLL next to clang's runtime libraries
   $rt = Get-ChildItem (Join-Path (Split-Path (Split-Path $clang)) 'lib\clang\*\lib\windows') -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
   if ($rt) { $env:PATH = "$($rt.FullName);$env:PATH" }
   $FuzzBuild = Join-Path $Repo 'build_fuzz'
   & $Cmake -G Ninja -S (Join-Path $PSScriptRoot 'fuzz') -B $FuzzBuild "-DCMAKE_MAKE_PROGRAM=$Ninja" "-DCMAKE_C_COMPILER=$clang" "-DPython3_EXECUTABLE=$Py"
   if ($LASTEXITCODE -ne 0) { throw 'fuzz configure failed' }
   & $Cmake --build $FuzzBuild
   if ($LASTEXITCODE -ne 0) { throw 'fuzz build failed' }
   & $Py (Join-Path $PSScriptRoot 'tools\run_fuzz.py') $FuzzBuild $FuzzSeconds
   $fuzzResult = $LASTEXITCODE
}

Write-Host ''
Write-Host "C tests:      $(if ($cResult -eq 0) { 'PASS' } else { 'FAIL' })"
Write-Host "Python tests: $(if ($pyResult -eq 0) { 'PASS' } else { 'FAIL' })"
if ($Static) { Write-Host "Static:       $(if ($staticResult -eq 0) { 'PASS' } else { 'FAIL' })" }
if ($Fuzz) { Write-Host "Fuzz:         $(if ($fuzzResult -eq 0) { 'PASS' } else { 'FAIL' })" }
Write-Host "Report:       $Report\report.html"
if (($cResult -ne 0) -or ($pyResult -ne 0) -or ($staticResult -ne 0) -or ($fuzzResult -ne 0)) { exit 1 }
exit 0
