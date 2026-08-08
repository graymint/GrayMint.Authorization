$curDir = $PSScriptRoot;
$solutionDir = (Split-Path $PSScriptRoot -Parent);

# variables
$projectFile="$solutionDir\GrayMint.Authorization.Test.MicroserviceSample\GrayMint.Authorization.Test.MicroserviceSample.csproj";
$namespace = "GrayMint.Common.Test.Api";
$nswagFile = "$curDir/Api/Api.nswag";

# run; nswag is a local dotnet tool, restored from the manifest at the repo root (./.config).
# Its version must match the NSwag.AspNetCore the sample project pulls in through
# GrayMint.Common.Swagger, because nswag generates the document inside that app.
$variables="/variables:namespace=$namespace,apiFile=Api.cs,projectFile=$projectFile";
Push-Location $curDir;
try {
	dotnet tool restore;
	if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed."; }
	dotnet tool run nswag run $nswagFile $variables;
	if ($LASTEXITCODE -ne 0) { throw "nswag generation failed."; }
}
finally {
	Pop-Location;
}
