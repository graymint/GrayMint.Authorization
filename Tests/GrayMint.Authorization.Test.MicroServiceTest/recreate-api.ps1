$curDir = $PSScriptRoot;
$solutionDir = (Split-Path $PSScriptRoot -Parent);

# variables
$projectFile="$solutionDir\GrayMint.Authorization.Test.MicroserviceSample\GrayMint.Authorization.Test.MicroserviceSample.csproj";
$namespace = "GrayMint.Common.Test.Api";
$nswagFile = "$curDir/Api/Api.nswag";

# run
$nswagExe = "${Env:ProgramFiles(x86)}\Rico Suter\NSwagStudio\Net80\dotnet-nswag.exe";
$variables="/variables:namespace=$namespace,apiFile=Api.cs,projectFile=$projectFile";
& "$nswagExe" run $nswagFile $variables;

# todo: remove after nswag get fixed
# fix beta generated code
# load the api.cs file 
$filePath = "$curDir/Api/Api.cs";
$fileContent = Get-Content -Path $filePath -Raw;
$fileContent = $fileContent -replace '"email:{email}"', '$"email:{email}"';
$fileContent | Set-Content -Path $filePath -Force;
