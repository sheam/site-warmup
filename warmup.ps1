param([string]$ConfigFile, [string]$Env, [string]$Password)
$Script:config = $null
$scriptStartTime = Get-Date

function Log([string]$msg)
{
    Write-Host $msg
}

function LoadConfig()
{
    if( -not $ConfigFile )
    {
        $ConfigFile = 'config.json'
    }

    if( -not $Env )
    {
        Log('Env argument must be specified')
        exit 1
    }

    $configData = Get-Content $ConfigFile | Out-String | ConvertFrom-Json
    $Script:config = $configData.$Env

    $hasConfigPassword = [bool]($Script:config.PSobject.Properties.name -match 'site_pass')
    if( -not $hasConfigPassword )
    {
        $Script:config | Add-Member -NotePropertyName site_pass -NotePropertyValue $null
    }

    if( $Password )
    {
        $Script:config.site_pass = $Password
    }

    if( -not $Script:config.site_pass )
    {
        Log('No site password supplied, exiting.')
        exit 1
    }
}

function BnUrl([string]$path)
{
    return $Script:config.domain.TrimEnd('/') + '/' + $path.TrimStart('/');
}

function GetHeaders()
{
    if( -not $Script:config.basic_auth_user ) 
    {
        return @{}
    }

    $creds = "$($Script:config.basic_auth_user):$($Script:config.basic_auth_pass)"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($creds))
    $basicAuthValue = "Basic $encodedCreds"

    return @{
        Authorization = $basicAuthValue
    }
}

$Script:actionCount = 0
$Script:actionCountSuccess = 0
$Script:startTime = $null
function LogAction([string] $action)
{
    $Script:startTime = Get-Date
    $Script:actionCount = $Script:actionCount + 1
    $n = $Script:actionCount.ToString().PadLeft(3)
    $a = "$action ".PadRight(70, '.') 
    Write-Host "$n. $a " -NoNewline
}

function LogOk()
{
    $Script:actionCountSuccess = $Script:actionCountSuccess + 1
    $stop = Get-Date
    $duration = New-TimeSpan -Start $Script:startTime -End $stop
    $seconds = [math]::Round($duration.TotalSeconds, 2)
    Write-Host "[OK] ($($seconds)s)"
}

function LogError([string] $errorDetails)
{
    Write-Host '[ERROR]'
    if($errorDetails)
    {
        Write-Host "    ->$errorDetails"
    }
}

function SaveContent([string]$urlPath, [string]$content)
{
    $dir = $Script:config.results_dir
    if( $dir )
    {
        $urlPath = $urlPath.Replace('/', '_').Replace('?', '__').Replace('&','+')
        $path = Join-Path -Path $dir -ChildPath "$urlPath.html"
        $content | Set-Content -Path $path
    }
}

$Script:session = $null
function LoginAuth0
{
    LogAction 'Logging into Auth0'

    $timeout = 4 * 60; #things can be pretty slow the first time we hit the site
    $url = BnUrl('/auth/login?fromSignIn=True')
    $login = Invoke-WebRequest $url -UseBasicParsing -SessionVariable Script:session -Method 'GET' -TimeoutSec $timeout
    $match = [regex]::Match($login.Content, "var config = JSON\.parse\(decodeURIComponent\(escape\(window.atob\('([a-zA-Z0-9=]+)'\)\)\)\);")
    if($match.Success)
    {
        $configDataBase64 = $match.captures.groups[1].value
    }

    if( -not $configDataBase64 )
    {
        LogError('Could not get config data');
        Exit 1
    }

    $configDataUriEncoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($configDataBase64))
    $configDecoded = [System.Web.HttpUtility]::UrlDecode($configDataUriEncoded)
    $lockConfig = ($configDecoded | ConvertFrom-Json)

    $fields = @{
        'redirect_uri' = BnUrl('/signin-auth0')
        'tenant' = $Script:config.auth0_tenant
        'response_type' = 'code id_token'
        'connection' = 'Username-Password-Authentication'
        'sso' = 'true'
        'response_mode' = 'form_post'
        '_intstate' = 'deprecated'
        'allow_signup' = 'false'
        'x-client-_sku' = 'ID_NET461'
        'allow_login' = 'true'
        'scope' = 'openid profile'
        'x-client-ver' = '5.3.0.0'
        'protocol' = 'oauth2'

        'client_id' = $lockConfig.clientID
        'username' = $Script:config.site_user
        'password' = $Script:config.site_pass

        '_csrf' = $lockConfig.internalOptions._csrf
        'nonce' = $lockConfig.internalOptions.nonce
        'state' = $lockConfig.internalOptions.state
    }

    $post_url = "https://$($Script:config.auth0_tenant).auth0.com/usernamepassword/login"
    $post_json = Invoke-WebRequest $post_url -UseBasicParsing -WebSession $Script:session -Method 'POST' -ContentType 'application/json' -TimeoutSec $timeout -Body ($fields|ConvertTo-Json)

    $match = [regex]::Match($post_json.Content, '<input\s+type="\w+"\s+name="wresult"\s+value="([^>]+)">')
    if( -not $match.Success )
    {
        LogError('Could not find wresult')
        Exit 1
    }
    $wresult = $match.captures.groups[1].value

    $match = [regex]::Match($post_json.Content, '<input\s+type="\w+"\s+name="wctx"\s+value="([^>]+)">')
    if( -not $match.Success )
    {
        LogError('Could not find wctx')
        Exit 1
    }
    $wctx = $match.captures.groups[1].value -replace '&#34;','"' | ConvertFrom-Json

    $formFields = @{
        wa = 'wsignin1.0'
        wresult = $wresult
        wctx = $wctx | ConvertTo-Json -Compress
    }
    $url = "https://$($Script:config.auth0_tenant).auth0.com/login/callback"
    $post_form = Invoke-WebRequest $url -UseBasicParsing -WebSession $Script:session -Method 'POST' -ContentType 'application/x-www-form-urlencoded' -TimeoutSec $timeout -Body $formFields
    $match = [regex]::Match($post_form.Content, '<input\s+type="\w+"\s+name="code"\s+value="([^>]+)"\s*/>')
    if( -not $match.Success )
    {
        LogError('Could not find code')
        Exit 1
    }
    $code = $match.captures.groups[1].value

    $match = [regex]::Match($post_form.Content, '<input\s+type="\w+"\s+name="id_token"\s+value="([^>]+)"\s*/>')
    if( -not $match.Success )
    {
        LogError('Could not find code')
        Exit 1
    }
    $token = $match.captures.groups[1].value

    $match = [regex]::Match($post_form.Content, '<input\s+type="\w+"\s+name="state"\s+value="([^>]+)"\s*/>')
    if( -not $match.Success )
    {
        LogError('Could not find code')
        Exit 1
    }
    $state = $match.captures.groups[1].value

    $formFields = @{
        code = $code
        id_token = $token
        state = $state
    }
    $url = BnUrl('/signin-auth0')
    $result = Invoke-WebRequest $url -UseBasicParsing -WebSession $Script:session -Method 'POST' -ContentType 'application/x-www-form-urlencoded' -TimeoutSec $timeout -Body $formFields
    if($result.StatusCode -eq 200)
    {
        LogOk
    }
    else 
    {
        LogError('failed to login')
        Exit 1
    }

    LogAction("Selecting tenant $($Script:config.tenant)")
    $url = BnUrl("/auth/select/$($Script:config.tenant)")
    $result = Invoke-WebRequest $url -UseBasicParsing -WebSession $Script:session -Method 'GET' -TimeoutSec $timeout
    if($result.StatusCode -eq 200)
    {
        LogOk
    }
    else 
    {
        LogError($result.Content)
        Exit 1
    }
}

function RequestPage([string]$path, [string]$test, [bool]$nosession)
{
    $headers = GetHeaders
    $url = BnUrl($path)
    LogAction($url)
    try 
    {
        if($nosession)
        {
            $req = Invoke-WebRequest -Uri $url -UseBasicParsing
        }
        else 
        {
            $req = Invoke-WebRequest -Uri $url -WebSession $Script:session -UseBasicParsing -Headers $headers            
        }
        SaveContent -urlPath $path -content $req.Content


        if( $req.StatusCode -ne 200 )
        {
            LogError("Non-200 status returned: $($req.StatusCode)")
        }
        elseif( $test )
        {
            if( -not $req.Content.ToLower().Contains($test.ToLower()) )
            {
                LogError("Could not find test pattern '$test'")
            }
            else 
            {
                LogOk
            }
        }
        else 
        {
            LogOk
        }
    }
    catch
    {
        LogError("Exception making request: $($_.Exception.Message)")
    }
}

function InitResultsDir
{
    $dir = $Script:config.results_dir
    if( $dir )
    {
        Log("Logging request results to $($Script:config.results_dir)")
    }
    else 
    {
        Log('Not logging results')
        return
    }

    if( -not (Test-Path $dir) )
    {
        mkdir  $dir
    }

    $dir = Join-Path -Path $dir -ChildPath $Env
    if( -not (Test-Path $dir) )
    {
        mkdir  $dir
    }

    Get-ChildItem -Path $dir -Recurse | Remove-Item

    $Script:config.results_dir = $dir
}

function LoadUrlFile
{
    $file = $Script:config.input

    if( -not $file )
    {
        Log('INPUT is not set, no URLs to warm up')
        exit 1
    }

    if( -not (Test-Path $file) )
    {
        Log('Could not find file')
        exit 1
    }

    $result = @()
    foreach($line in Get-Content $file)
    {
        $line = $line.Trim()
        if( $line.StartsWith("#") )
        {
            continue
        }

        $url,$test,$nosession = $line.Split('|')
        $url = $url.Trim()

        if($test)
        {
            $test = $test.Trim()
        }

        if( -not $url )
        {
            continue
        }

        if( $url -eq "end" )
        {
            break
        }

        if($nosession)
        {
            if($nosession -eq "no-session")
            {
                $nosessionBool = $true
            }
            else 
            {
                LogError("Malformed line: '$line' :should be URL|test|no-session")
                exit 1
            }
        }
        else 
        {
            $nosessionBool = $false
        }

        $result += @{ Url = $url; Test = $test; NoSession = $nosessionBool }
    }

    Log("Loaded $($result.Count) URL's from $file")

    return $result
}

function ProcessUrls($urlList)
{
    foreach($item in $urlList)
    {
        RequestPage -path $item.Url -test $item.Test -nosession $item.NoSession
    }
}

function PrintSummaryAndExit()
{
    $stop = Get-Date
    $duration = New-TimeSpan -Start $scriptStartTime -End $stop
    $seconds = [math]::Round($duration.TotalSeconds, 2)
    Log("$($Script:actionCountSuccess) of $($Script:actionCount) pages loaded successfully in $seconds seconds.")
    if( $Script:actionCountSuccess -eq $Script:actionCount )
    {
        Log('All tests completed successfully.')
        exit 0
    }
    Log('Not all tests completed successfully, returning error code.')
    exit 1
}

LoadConfig
InitResultsDir
$url_list = LoadUrlFile
LoginAuth0
ProcessUrls($url_list)
PrintSummaryAndExit
