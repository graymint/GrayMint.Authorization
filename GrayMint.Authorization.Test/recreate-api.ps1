$curDir = $PSScriptRoot;
$solutionDir = (Split-Path $PSScriptRoot -Parent);

# variables
$projectFile="$solutionDir\GrayMint.Common.Test.WebApiSample\GrayMint.Common.Test.WebApiSample.csproj";
$namespace = "GrayMint.Common.Test.Api";
$nswagFile = "$curDir/Api/Api.nswag";

# run
$nswagExe = "${Env:ProgramFiles(x86)}\Rico Suter\NSwagStudio\Net70\dotnet-nswag.exe";
$variables="/variables:namespace=$namespace,apiFile=Api.cs,projectFile=$projectFile";
& "$nswagExe" run $nswagFile $variables /runtime:Net70;