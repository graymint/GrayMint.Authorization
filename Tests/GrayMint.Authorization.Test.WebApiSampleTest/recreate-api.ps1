$curDir = $PSScriptRoot;
$solutionDir = (Split-Path $PSScriptRoot -Parent);

# variables
$projectFile="$solutionDir\GrayMint.Authorization.Test.WebApiSample\GrayMint.Authorization.Test.WebApiSample.csproj";
$namespace = "GrayMint.Common.Test.Api";
$nswagFile = "$curDir/Api/Api.nswag";

# run
$nswagExe = "${Env:ProgramFiles(x86)}\Rico Suter\NSwagStudio\Net80\dotnet-nswag.exe";
$variables="/variables:namespace=$namespace,apiFile=Api.cs,projectFile=$projectFile";
& "$nswagExe" run $nswagFile $variables;
